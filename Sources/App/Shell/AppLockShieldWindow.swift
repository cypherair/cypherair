import SwiftUI
#if os(iOS) || os(visionOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

// MARK: - Unified app shield window (issues #697, #723)
//
// One platform window carries BOTH protective surfaces:
//
// - the **lock surface** while the app is locked (issue #697), and
// - the **cosmetic privacy cover** while the app is not foreground-active
//   (issue #723 — previously an in-scene `.overlay`, which SwiftUI sheets and
//   fullScreenCovers rendered above, leaking presentation content into the
//   app-switcher snapshot).
//
// The window presents while `isCosmeticallyCovered || isLocked` and renders
// `isLocked ? lock : privacy` (`AppLockShieldPolicy`). The cover trigger stays
// dumb: presentation never depends on lock-machine state alone —
// `isCosmeticallyCovered` is synchronous on the away signal, so the shield is
// up before the system snapshots the scene, while the lock itself lands on an
// async `Task`. `AppLockController.isLocked` is already true for
// `.authenticating`/`.authenticationFailed`, so the lock face wins during
// auth prompts with no extra precedence state.
//
// Per-mode input discipline (`AppLockShieldPolicy.Mode`): lock mode takes key
// status and ends the active text-editing session beneath (exactly the #697
// shield behavior); privacy mode does neither — it is purely visual (touch
// routing follows window hit-testing, not key status, so covered content is
// still not tappable). When the asynchronous lock lands while the window is
// already visible in privacy mode, the lock-mode side effects are applied at
// the mode flip.
//
// Platform mechanics:
//
// - iOS / iPadOS / visionOS: an additional `UIWindow` in the same
//   `UIWindowScene` at a `windowLevel` above `.alert`. Level stacking takes
//   precedence over window ordering within a level, and SwiftUI presentations
//   render inside the app's normal-level window, so the shield covers them by
//   construction.
// - macOS: a borderless child window attached to the app window with
//   `addChildWindow(_:ordered: .above)`. Empirically (probed for #697),
//   within-level ordering NEVER beats an attached sheet — so the shield runs
//   at an elevated `NSWindow.Level` while the app is active.
//   `addChildWindow` itself resets the child's level to the parent's (probed
//   for #720), so the elevated level is applied only AFTER attachment.
//   Because AppKit window levels are global across apps, the shield drops
//   back to `.normal` on a REAL app switch so it can never float above other
//   apps' windows. An app-resign caused by a SYSTEM-SHEET evaluation the
//   lock flow itself is driving (the Standard-mode "Use Password…" leg of
//   the #724 in-window unlock) is NOT a real app switch: the shield holds
//   its elevated level while `AppLockController.isAuthenticating` spans the
//   attempt, and drops to `.normal` only if the attempt ends unresolved with
//   the app still inactive. The EMBEDDED in-window evaluation (#724) resigns
//   nothing — a resign during it is a genuine away, which cancels the
//   attempt and ends `.authenticating`, so the elevated exception cannot pin
//   the level while another app is frontmost beyond the cancellation
//   settling. At `.normal` an attached sheet still beats the shield, so while
//   the shield is presented every window in the host's attached-sheet chain
//   additionally carries an opaque cover CHILD OF THE SHEET at the sheet's
//   own level, which does order above it (probed for #723) — that is what
//   covers window-modal sheets while the app is unfocused. The shield frame
//   is the union of the app-window frame and any attached-sheet chain.
//
// The shield observes only `AppLockController` state that already existed:
// `isCosmeticallyCovered`, `isLocked`, plus, on macOS, `isAuthenticating` for
// the activation-level policy above. It contains no lock logic of its own and
// never touches presentation state. Covering hides nothing and dismisses
// nothing — after unlock (or a within-grace return) the user is exactly where
// they left off.

/// Accessibility identifier carried by the shield WINDOW itself (the hosted
/// surface carries `appLock.surface`). Inert AX metadata: UI tests resolve
/// the shield window directly by this identifier — a `.containing(...)`
/// window subquery proved fragile against the AX snapshot of a
/// never-activated app (PR #720), while direct identifier matching does not
/// depend on resolving child elements.
private let shieldWindowAccessibilityIdentifier = "appLock.shieldWindow"

// MARK: - Pure presentation policy

/// The unified shield's pure decision rules (issue #723), kept free of
/// platform types so they are unit-testable on any platform.
enum AppLockShieldPolicy {
    /// What the presented shield window renders and how it treats input.
    enum Mode: Equatable {
        /// Cosmetic cover only: the app is away (or a foreground return is
        /// still resolving its lock decision) but not locked.
        case privacy
        /// The authentication gate: the app is locked (including the
        /// `.authenticating` / `.authenticationFailed` states).
        case lock

        /// Lock mode owns keyboard routing: the shield window becomes key so
        /// keystrokes cannot reach covered content. Privacy mode never takes
        /// key — it must not disturb the focus/keyboard state it covers,
        /// which a within-grace return resumes untouched.
        var takesKeyStatus: Bool { self == .lock }

        /// Lock mode ends the active text-editing session beneath the shield
        /// (UIKit family: the system keyboard lives in its own high-level
        /// window and would otherwise stay up over the lock surface).
        /// Privacy mode leaves the editing session exactly as it is.
        var endsActiveTextEditingSession: Bool { self == .lock }
    }

    /// The presentation condition. The cover half must stay the dumb
    /// synchronous away-signal boolean: only `isCosmeticallyCovered` is
    /// guaranteed to be true before the system snapshots a backgrounding
    /// scene (the lock lands on an async `Task`), so presentation must never
    /// depend on lock-machine state alone.
    static func isPresented(isCosmeticallyCovered: Bool, isLocked: Bool) -> Bool {
        isCosmeticallyCovered || isLocked
    }

    /// The rendering mode of a presented shield. Lock always wins: `isLocked`
    /// is true for `.authenticating`/`.authenticationFailed` too, so the lock
    /// face covers content during auth prompts with no extra state.
    static func mode(isLocked: Bool) -> Mode {
        isLocked ? .lock : .privacy
    }

    /// Whether a mode transition applies the lock-mode input side effects
    /// (take key + end text editing). True exactly on ENTERING lock mode —
    /// from not-presented (`nil`) or from privacy (the asynchronous lock
    /// landing while the window is already visible). Leaving lock mode
    /// applies nothing: key restoration happens when the shield hides.
    static func appliesLockModeInputDiscipline(transitioningFrom previous: Mode?, to next: Mode) -> Bool {
        next == .lock && previous != .lock
    }
}

/// The shield window's root content: the lock surface while locked, the
/// privacy face otherwise. `AppLockController` is `@Observable`, so reading
/// `isLocked` here re-renders the hosted content on every lock transition
/// without recreating the window. The window-level input side effects of a
/// mode flip are applied by the coordinator, not here.
private struct AppShieldContentView: View {
    let appLockController: AppLockController
    #if os(macOS)
    /// The macOS in-window unlock owner the lock surface renders the
    /// embedded authentication for (issue #724).
    let unlockPresenter: AppSessionUnlockPresenter?
    #endif

    var body: some View {
        switch AppLockShieldPolicy.mode(isLocked: appLockController.isLocked) {
        case .lock:
            #if os(macOS)
            AppLockSurfaceView(
                appLockController: appLockController,
                unlockPresenter: unlockPresenter
            )
            #else
            AppLockSurfaceView(appLockController: appLockController)
            #endif
        case .privacy:
            AppPrivacySurfaceView()
        }
    }
}

extension View {
    /// Install the unified app shield: a window-level bridge that presents
    /// the lock surface or the cosmetic privacy cover above ALL app content
    /// while `appLockController.isCosmeticallyCovered || isLocked`. Replaces
    /// both the previous in-scene lock overlay (#697) and the previous
    /// in-scene cosmetic cover overlay (#723). On macOS the lock mode also
    /// hosts the in-window app-session authentication, so the shield carries
    /// the unlock presenter to the surface (issue #724); the UIKit-family
    /// platforms keep the system-sheet presentation and ignore it.
    @MainActor
    func appLockShieldWindow(
        appLockController: AppLockController,
        unlockPresenter: AppSessionUnlockPresenter? = nil
    ) -> some View {
        #if os(macOS)
        return background(
            AppLockShieldWindowHost(
                appLockController: appLockController,
                unlockPresenter: unlockPresenter,
                isCosmeticallyCovered: appLockController.isCosmeticallyCovered,
                isLocked: appLockController.isLocked,
                isAuthenticating: appLockController.isAuthenticating
            )
        )
        #else
        return background(
            AppLockShieldWindowHost(
                appLockController: appLockController,
                isCosmeticallyCovered: appLockController.isCosmeticallyCovered,
                isLocked: appLockController.isLocked,
                isAuthenticating: appLockController.isAuthenticating
            )
        )
        #endif
    }
}

#if os(iOS) || os(visionOS)

private struct AppLockShieldWindowHost: UIViewRepresentable {
    let appLockController: AppLockController
    /// The synchronous away-signal cover trigger. Stored so the representable
    /// value changes — and `updateUIView` fires — in the same render pass the
    /// signal flips in, before the system snapshots a backgrounding scene.
    let isCosmeticallyCovered: Bool
    let isLocked: Bool
    /// Unused on the UIKit family: `UIWindow.Level` is scene-local — it can
    /// never place the shield above another app's windows — so there is no
    /// inactive level drop and therefore no auth-prompt exception to it.
    /// Carried so the shared `appLockShieldWindow(appLockController:)` entry
    /// point has one shape across platforms.
    let isAuthenticating: Bool

    func makeCoordinator() -> AppLockShieldWindowCoordinator {
        AppLockShieldWindowCoordinator(appLockController: appLockController)
    }

    func makeUIView(context: Context) -> AppLockShieldAnchorView {
        let view = AppLockShieldAnchorView()
        view.coordinator = context.coordinator
        view.isUserInteractionEnabled = false
        view.backgroundColor = .clear
        return view
    }

    func updateUIView(_ uiView: AppLockShieldAnchorView, context: Context) {
        context.coordinator.setState(
            cosmeticallyCovered: isCosmeticallyCovered,
            locked: isLocked
        )
    }

    static func dismantleUIView(_ uiView: AppLockShieldAnchorView, coordinator: AppLockShieldWindowCoordinator) {
        coordinator.tearDown()
    }
}

/// Invisible anchor installed in the scene content solely to resolve the
/// hosting `UIWindowScene` from the SwiftUI lifecycle.
final class AppLockShieldAnchorView: UIView {
    weak var coordinator: AppLockShieldWindowCoordinator?

    override func didMoveToWindow() {
        super.didMoveToWindow()
        coordinator?.anchorDidMove(to: window?.windowScene)
    }
}

@MainActor
final class AppLockShieldWindowCoordinator {
    /// Above `.alert` so the shield covers everything the app can present in
    /// its normal-level window — sheets, fullScreenCovers, and alerts.
    static let shieldWindowLevel = UIWindow.Level(UIWindow.Level.alert.rawValue + 1)

    private let appLockController: AppLockController
    private weak var windowScene: UIWindowScene?
    private var shieldWindow: UIWindow?
    private weak var restoreKeyWindow: UIWindow?
    /// The mode whose window-level side effects have been applied to the
    /// presented shield; `nil` while no shield window exists.
    private var presentedMode: AppLockShieldPolicy.Mode?
    /// Whether the presented shield took key status (lock mode ever engaged).
    /// A privacy-only presentation never disturbs key status, so its removal
    /// must not "restore" anything.
    private var shieldTookKeyStatus = false
    private var isCosmeticallyCovered = false
    private var isLocked = false

    init(appLockController: AppLockController) {
        self.appLockController = appLockController
    }

    func anchorDidMove(to scene: UIWindowScene?) {
        guard scene !== windowScene else { return }
        // The anchor re-hosted into a different scene (or resolved for the
        // first time): tear down any existing shield unconditionally — the
        // previous scene may already have died (weak reference cleared),
        // leaving a defunct shield window that must not block
        // re-presentation — and rebuild against the current scene.
        removeShield(restoringKey: false)
        windowScene = scene
        apply()
    }

    func setState(cosmeticallyCovered: Bool, locked: Bool) {
        guard cosmeticallyCovered != isCosmeticallyCovered || locked != isLocked else { return }
        isCosmeticallyCovered = cosmeticallyCovered
        isLocked = locked
        apply()
    }

    func tearDown() {
        removeShield(restoringKey: false)
        windowScene = nil
    }

    private func apply() {
        guard AppLockShieldPolicy.isPresented(
            isCosmeticallyCovered: isCosmeticallyCovered,
            isLocked: isLocked
        ) else {
            removeShield(restoringKey: true)
            return
        }
        presentShieldIfPossible()
        applyMode(AppLockShieldPolicy.mode(isLocked: isLocked))
    }

    private func presentShieldIfPossible() {
        guard shieldWindow == nil, let windowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        window.windowLevel = Self.shieldWindowLevel
        window.accessibilityIdentifier = shieldWindowAccessibilityIdentifier
        // Render-failure floor: the shield WINDOW is opaque independent of
        // the hosted SwiftUI content, so a hosting failure can never show
        // covered content through the shield.
        window.isOpaque = true
        window.backgroundColor = .systemBackground
        window.rootViewController = UIHostingController(
            rootView: AppShieldContentView(appLockController: appLockController)
        )
        window.isHidden = false
        shieldWindow = window
    }

    private func applyMode(_ mode: AppLockShieldPolicy.Mode) {
        guard shieldWindow != nil, mode != presentedMode else { return }
        let previousMode = presentedMode
        presentedMode = mode
        guard AppLockShieldPolicy.appliesLockModeInputDiscipline(
            transitioningFrom: previousMode,
            to: mode
        ) else { return }
        applyLockModeInputDiscipline(mode)
    }

    private func applyLockModeInputDiscipline(_ mode: AppLockShieldPolicy.Mode) {
        guard let shieldWindow else { return }
        let coveredKeyWindow = windowScene?.keyWindow
        if mode.endsActiveTextEditingSession, coveredKeyWindow !== shieldWindow {
            // End any active text-input session beneath the shield so the
            // system keyboard (hosted in its own high-level window) cannot
            // remain up over the lock surface or keep routing keystrokes into
            // covered content. Field contents are untouched; after unlock,
            // refocusing is a tap.
            coveredKeyWindow?.endEditing(true)
        }
        if mode.takesKeyStatus {
            shieldTookKeyStatus = true
            if coveredKeyWindow !== shieldWindow {
                restoreKeyWindow = coveredKeyWindow
            }
            shieldWindow.makeKey()
        }
    }

    private func removeShield(restoringKey: Bool) {
        let tookKeyStatus = shieldTookKeyStatus
        shieldTookKeyStatus = false
        presentedMode = nil
        defer { restoreKeyWindow = nil }
        guard let shieldWindow else { return }
        shieldWindow.isHidden = true
        self.shieldWindow = nil
        // Restore key status only if lock mode took it; a privacy-only
        // presentation left the key window untouched, and forcing one here
        // would move focus on every cover round-trip.
        guard restoringKey, tookKeyStatus else { return }
        if let restoreKeyWindow, !restoreKeyWindow.isHidden {
            restoreKeyWindow.makeKey()
        } else if let fallback = windowScene?.windows.first(where: { !$0.isHidden }) {
            fallback.makeKey()
        }
    }
}

#elseif os(macOS)

/// Accessibility identifier carried by every macOS sheet-cover child window
/// (#723). Inert AX metadata for UI tests, same rationale as
/// `shieldWindowAccessibilityIdentifier`.
private let sheetCoverAccessibilityIdentifier = "appLock.sheetCover"

private struct AppLockShieldWindowHost: NSViewRepresentable {
    let appLockController: AppLockController
    /// The macOS in-window unlock owner, carried to the hosted lock surface
    /// (issue #724).
    let unlockPresenter: AppSessionUnlockPresenter?
    /// The synchronous away-signal cover trigger (see the UIKit twin).
    let isCosmeticallyCovered: Bool
    let isLocked: Bool
    /// `AppLockController.isAuthenticating`, wired through the SwiftUI update
    /// path (a stored property, so the representable value changes and
    /// `updateNSView` fires on every `.authenticating` transition — including
    /// the attempt that ends unresolved while the app is still inactive,
    /// which produces no NSApplication activation notification to re-derive
    /// the level from).
    let isAuthenticating: Bool

    func makeCoordinator() -> AppLockShieldWindowCoordinator {
        AppLockShieldWindowCoordinator(
            appLockController: appLockController,
            unlockPresenter: unlockPresenter
        )
    }

    func makeNSView(context: Context) -> AppLockShieldAnchorView {
        let view = AppLockShieldAnchorView()
        view.coordinator = context.coordinator
        return view
    }

    func updateNSView(_ nsView: AppLockShieldAnchorView, context: Context) {
        context.coordinator.setState(
            cosmeticallyCovered: isCosmeticallyCovered,
            locked: isLocked,
            authenticating: isAuthenticating
        )
    }

    static func dismantleNSView(_ nsView: AppLockShieldAnchorView, coordinator: AppLockShieldWindowCoordinator) {
        coordinator.tearDown()
    }
}

/// Invisible anchor installed in the scene content solely to resolve the
/// hosting `NSWindow` from the SwiftUI lifecycle.
final class AppLockShieldAnchorView: NSView {
    weak var coordinator: AppLockShieldWindowCoordinator?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        coordinator?.anchorDidMove(to: window)
    }
}

/// Borderless windows refuse key status by default; the shield must be able
/// to become key while in LOCK mode so keyboard events cannot reach covered
/// windows. `canBecomeKey` is gated on the presented mode rather than
/// unconditionally true: AppKit's click-to-front makes a clicked window key
/// with no code call involved, so an unconditional override would let a
/// click on the PRIVACY cover (returning within grace from another app) hand
/// the panel key status behind the coordinator's back — `shieldTookKeyStatus`
/// would stay false and `removeShield` would skip restoring the pre-away
/// sheet/field focus, leaving AppKit to reassign key arbitrarily. The gate
/// controls acquisition only: a lock→privacy flip does not strip key status
/// already held (key restoration happens when the shield hides, by design).
private final class AppLockShieldPanel: NSWindow {
    /// Set by the coordinator to the presented mode's `takesKeyStatus`;
    /// false until a mode is applied.
    var allowsKeyStatus = false

    override var canBecomeKey: Bool { allowsKeyStatus }
    override var canBecomeMain: Bool { false }
}

@MainActor
final class AppLockShieldWindowCoordinator {
    /// Above `.modalPanel` so window-modal sheets and modal panels are
    /// covered while the app is active; below the menu-bar/status levels so
    /// system chrome stays on top. Applied per
    /// `shieldLevel(appIsActive:isUnlockAuthenticationInFlight:)` — AppKit
    /// levels order globally across apps, and the shield must never float
    /// above another app's windows on a real app switch.
    static let activeShieldLevel = NSWindow.Level(rawValue: NSWindow.Level.modalPanel.rawValue + 1)

    /// The activation-level policy, kept pure so it is unit-testable.
    /// Elevated while the app is active — the case the #697 invariant is
    /// about — and while an app-session unlock attempt is in flight. The
    /// in-flight exception exists for the SYSTEM-SHEET evaluation (the
    /// Standard-mode "Use Password…" leg of the #724 in-window unlock):
    /// that detached prompt resigns the app (the exact resign
    /// `AppLockController.handleAwayEvent`'s `.authenticating` rule treats as
    /// the auth sheet's own), and a `.normal`-level child window falls behind
    /// an attached sheet (probed for #697) — dropping on that resign would
    /// expose the covered sheet for the whole prompt. The EMBEDDED in-window
    /// evaluation (#724) resigns nothing; a resign during it is a genuine
    /// away that cancels the attempt and ends `.authenticating`, so this
    /// exception holds only for the cancellation-settling moment there. Only
    /// a real app switch — inactive with no unlock in flight — drops to
    /// `.normal`, preserving the recorded deviation that the shield never
    /// floats above other apps' windows. (At `.normal` the attached-sheet
    /// chain is covered by the per-sheet cover children instead.)
    static func shieldLevel(appIsActive: Bool, isUnlockAuthenticationInFlight: Bool) -> NSWindow.Level {
        appIsActive || isUnlockAuthenticationInFlight ? activeShieldLevel : .normal
    }

    /// One opaque cover per window in the host's attached-sheet chain, kept
    /// while the shield is presented. Within a level an attached sheet always
    /// beats an ordinary child window of the SHEET'S PARENT (probed for
    /// #697), so the `.normal`-level inactive shield cannot cover
    /// window-modal sheets — but a borderless child attached to the SHEET
    /// ITSELF does order above it at the same level (probed for #723).
    /// `addChildWindow` resets the child's level to the parent's (probed for
    /// #720), which here is exactly the same-level requirement — no explicit
    /// level write.
    private struct SheetCover {
        weak var sheet: NSWindow?
        let cover: NSWindow
    }

    private let appLockController: AppLockController
    /// Carried to the hosted lock surface, which renders the embedded
    /// in-window authentication for it (issue #724). The coordinator itself
    /// never reads it — the level policy keys on
    /// `appLockController.isAuthenticating` exactly as before.
    private let unlockPresenter: AppSessionUnlockPresenter?
    private weak var hostWindow: NSWindow?
    private var shieldWindow: AppLockShieldPanel?
    private weak var restoreKeyWindow: NSWindow?
    private var sheetCovers: [SheetCover] = []
    /// The mode whose window-level side effects have been applied to the
    /// presented shield; `nil` while no shield window exists.
    private var presentedMode: AppLockShieldPolicy.Mode?
    /// Whether the presented shield took key status (lock mode ever engaged);
    /// a privacy-only presentation restores nothing on removal.
    private var shieldTookKeyStatus = false
    private var isCosmeticallyCovered = false
    private var isLocked = false
    /// SwiftUI-mirrored `AppLockController.isAuthenticating`, used only as a
    /// change signal in `setState`. Level decisions read the controller live:
    /// it sets `.authenticating` synchronously before the LA prompt exists,
    /// so a live read can never be stale when the prompt's resign
    /// notification arrives — this mirror could be, if that resign outruns
    /// the next SwiftUI render.
    private var isAuthenticating = false
    private var observers: [any NSObjectProtocol] = []

    // Observer lifetime: `endObservations()` runs on every shield removal,
    // including the representable's dismantle path (`tearDown()`), so no
    // observer outlives the shield. A nonisolated deinit cannot touch the
    // main-actor observer array under Swift 6; the block observers capture
    // `self` weakly, so they could never fire meaningfully after teardown
    // anyway.

    init(
        appLockController: AppLockController,
        unlockPresenter: AppSessionUnlockPresenter?
    ) {
        self.appLockController = appLockController
        self.unlockPresenter = unlockPresenter
    }

    func anchorDidMove(to window: NSWindow?) {
        guard window !== hostWindow else { return }
        // Tear down unconditionally: the previous host window may already
        // have died (weak reference cleared), and a defunct shield must not
        // block re-presentation against the new host.
        removeShield(restoringKey: false)
        hostWindow = window
        apply()
    }

    func setState(cosmeticallyCovered: Bool, locked: Bool, authenticating: Bool) {
        let authenticatingChanged = authenticating != isAuthenticating
        isAuthenticating = authenticating
        if cosmeticallyCovered != isCosmeticallyCovered || locked != isLocked {
            isCosmeticallyCovered = cosmeticallyCovered
            isLocked = locked
            apply()
        } else if authenticatingChanged {
            // `.authenticating` begins and ends without the presentation
            // signals changing. Re-derive the level on each flip: the begin
            // re-elevates a shield whose level a racing prompt-resign
            // notification may already have processed, and the end drops an
            // elevated shield back to `.normal` when the attempt resolves
            // while the app is still inactive (the system cancels the prompt
            // on a real app switch; no NSApplication activation notification
            // follows).
            applyActivationState()
        }
    }

    func tearDown() {
        removeShield(restoringKey: false)
        hostWindow = nil
    }

    private func apply() {
        guard AppLockShieldPolicy.isPresented(
            isCosmeticallyCovered: isCosmeticallyCovered,
            isLocked: isLocked
        ) else {
            removeShield(restoringKey: true)
            return
        }
        presentShieldIfPossible()
        applyMode(AppLockShieldPolicy.mode(isLocked: isLocked))
    }

    private func presentShieldIfPossible() {
        guard shieldWindow == nil, let hostWindow else { return }
        let shield = AppLockShieldPanel(
            contentRect: Self.shieldFrame(for: hostWindow),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        shield.isReleasedWhenClosed = false
        shield.isExcludedFromWindowsMenu = true
        shield.setAccessibilityIdentifier(shieldWindowAccessibilityIdentifier)
        shield.hasShadow = false
        // Render-failure floor: the shield WINDOW is opaque independent of
        // the hosted SwiftUI content.
        shield.isOpaque = true
        shield.backgroundColor = .windowBackgroundColor
        shield.isMovable = false
        shield.animationBehavior = .none
        // Join a full-screen host's space instead of being stranded outside it.
        shield.collectionBehavior.insert(.fullScreenAuxiliary)
        shield.contentView = NSHostingView(
            rootView: AppShieldContentView(
                appLockController: appLockController,
                unlockPresenter: unlockPresenter
            )
        )
        hostWindow.addChildWindow(shield, ordered: .above)
        shieldWindow = shield
        beginObservations()
        // The level is applied strictly AFTER `addChildWindow`:
        // `addChildWindow` resets the child's level to the parent's (probed
        // for #720 — a pre-attach `modalPanel + 1` reads `.normal` post-
        // attach, leaving an attached sheet in front of the shield), so a
        // level set before attachment is silently lost. A post-attach level
        // sticks and covers the sheet. `applyActivationState()` is the single
        // level writer (level policy + key upkeep + frame + sheet covers),
        // and every other call to it happens after attachment by
        // construction.
        applyActivationState()
    }

    private func applyMode(_ mode: AppLockShieldPolicy.Mode) {
        guard let shieldWindow, mode != presentedMode else { return }
        let previousMode = presentedMode
        presentedMode = mode
        // Structural key gate, applied BEFORE any `makeKey()` below: privacy
        // mode cannot become key even via AppKit's click-to-front (which
        // involves no coordinator code); lock mode can.
        shieldWindow.allowsKeyStatus = mode.takesKeyStatus
        guard AppLockShieldPolicy.appliesLockModeInputDiscipline(
            transitioningFrom: previousMode,
            to: mode
        ) else { return }
        applyLockModeInputDiscipline(mode)
    }

    private func applyLockModeInputDiscipline(_ mode: AppLockShieldPolicy.Mode) {
        guard let shieldWindow else { return }
        // On macOS, taking key status IS the text-editing interruption:
        // AppKit routes key events to the key window, so the covered window's
        // editing session stops receiving keystrokes the moment the shield is
        // key (no UIKit-style `endEditing` call exists or is needed —
        // `Mode.endsActiveTextEditingSession` is consumed by the UIKit twin).
        guard mode.takesKeyStatus else { return }
        shieldTookKeyStatus = true
        let coveredKeyWindow = NSApp.keyWindow
        restoreKeyWindow = (coveredKeyWindow === shieldWindow ? nil : coveredKeyWindow) ?? hostWindow
        // Key status is taken only on a genuinely active app — never
        // `makeKey()` while inactive (the LA sheet owns focus during the
        // prompt). An inactive lock engagement takes key on the next genuine
        // activation via `applyActivationState()`.
        if NSApp.isActive {
            shieldWindow.makeKey()
        }
    }

    private func removeShield(restoringKey: Bool) {
        endObservations()
        removeAllSheetCovers()
        let tookKeyStatus = shieldTookKeyStatus
        shieldTookKeyStatus = false
        presentedMode = nil
        defer { restoreKeyWindow = nil }
        guard let shieldWindow else { return }
        shieldWindow.parent?.removeChildWindow(shieldWindow)
        shieldWindow.orderOut(nil)
        self.shieldWindow = nil
        // Restore key status only if lock mode took it; a privacy-only
        // presentation left the key window (often an open sheet) untouched,
        // and forcing one here would move focus on every cover round-trip.
        guard restoringKey, tookKeyStatus else { return }
        if let target = restoreKeyWindow ?? hostWindow, target.isVisible {
            target.makeKey()
        }
    }

    // MARK: - Geometry, level & sheet-cover upkeep

    /// The host window's attached-sheet chain, outermost first. Sheets are
    /// separate windows that may extend outside the parent frame and may
    /// themselves have attached sheets.
    private static func attachedSheetChain(of hostWindow: NSWindow) -> [NSWindow] {
        var chain: [NSWindow] = []
        var sheet = hostWindow.attachedSheet
        while let current = sheet {
            chain.append(current)
            sheet = current.attachedSheet
        }
        return chain
    }

    /// The shield must cover the app window AND its attached-sheet chain:
    /// sheets are separate windows that may extend outside the parent frame
    /// (verified empirically for #697).
    private static func shieldFrame(for hostWindow: NSWindow) -> NSRect {
        attachedSheetChain(of: hostWindow).reduce(hostWindow.frame) { $0.union($1.frame) }
    }

    private func beginObservations() {
        let center = NotificationCenter.default
        // Geometry and sheet notifications are observed with `object: nil`
        // and filtered to the host window and its attached-sheet chain: a
        // sheet's own resize and a sheet-of-sheet's begin/end fire on the
        // SHEET window, which a host-only observer never sees — leaving the
        // union frame and the sheet covers stale.
        let geometryNames: [Notification.Name] = [
            NSWindow.didResizeNotification,
            NSWindow.didMoveNotification,
            NSWindow.willBeginSheetNotification,
            NSWindow.didEndSheetNotification
        ]
        for name in geometryNames {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] notification in
                let window = notification.object as? NSWindow
                MainActor.assumeIsolated {
                    self?.handleGeometryNotification(from: window)
                }
            })
        }
        let activationNames: [Notification.Name] = [
            NSApplication.didBecomeActiveNotification,
            NSApplication.didResignActiveNotification
        ]
        for name in activationNames {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.applyActivationState()
                }
            })
        }
    }

    private func endObservations() {
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
        }
        observers.removeAll()
    }

    private func handleGeometryNotification(from window: NSWindow?) {
        guard let hostWindow, let window else { return }
        guard window === hostWindow
            || Self.attachedSheetChain(of: hostWindow).contains(where: { $0 === window }) else { return }
        refreshShieldGeometry()
    }

    private func refreshShieldGeometry() {
        applyShieldFrame()
        // A sheet announced by `willBeginSheet` is not attached (and has no
        // final frame) yet; recompute once more after presentation settles.
        DispatchQueue.main.async { [weak self] in
            self?.applyShieldFrame()
        }
    }

    private func applyShieldFrame() {
        guard let shieldWindow, let hostWindow else { return }
        shieldWindow.setFrame(Self.shieldFrame(for: hostWindow), display: true)
        syncSheetCovers()
    }

    private func applyActivationState() {
        guard let shieldWindow else { return }
        shieldWindow.level = Self.shieldLevel(
            appIsActive: NSApp.isActive,
            isUnlockAuthenticationInFlight: appLockController.isAuthenticating
        )
        // Key status is (re)taken only on genuine activation and only in lock
        // mode — never `makeKey()` while the app is inactive (including the
        // elevated auth-prompt posture: the LA sheet owns focus during the
        // prompt), and never in privacy mode (purely visual by policy).
        if NSApp.isActive, presentedMode?.takesKeyStatus == true {
            shieldWindow.makeKey()
        }
        applyShieldFrame()
    }

    // MARK: - Sheet covers (#723)

    /// While the shield is presented, every window in the host's
    /// attached-sheet chain carries a frame-matched opaque cover child (see
    /// `SheetCover`). Driven by the same geometry refresh as the shield frame
    /// — sheet begin/end and resizes re-sync the set.
    private func syncSheetCovers() {
        guard shieldWindow != nil, let hostWindow else {
            removeAllSheetCovers()
            return
        }
        let chain = Self.attachedSheetChain(of: hostWindow)
        var kept: [SheetCover] = []
        for entry in sheetCovers {
            if let sheet = entry.sheet, chain.contains(where: { $0 === sheet }) {
                kept.append(entry)
            } else {
                Self.detachSheetCover(entry)
            }
        }
        sheetCovers = kept
        for sheet in chain where !sheetCovers.contains(where: { $0.sheet === sheet }) {
            sheetCovers.append(Self.makeSheetCover(for: sheet))
        }
        for entry in sheetCovers {
            guard let sheet = entry.sheet else { continue }
            entry.cover.setFrame(sheet.frame, display: true)
        }
    }

    private func removeAllSheetCovers() {
        for entry in sheetCovers {
            Self.detachSheetCover(entry)
        }
        sheetCovers.removeAll()
    }

    private static func detachSheetCover(_ entry: SheetCover) {
        entry.cover.parent?.removeChildWindow(entry.cover)
        entry.cover.orderOut(nil)
    }

    private static func makeSheetCover(for sheet: NSWindow) -> SheetCover {
        // A plain borderless NSWindow: `canBecomeKey` is false for borderless
        // windows by default, so the cover can never take key status — it is
        // an opaque visual cover only, matching the privacy-mode input
        // discipline. It hosts no views: a blank opaque window is the whole
        // job (render floor independent of any content).
        let cover = NSWindow(
            contentRect: sheet.frame,
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        cover.isReleasedWhenClosed = false
        cover.isExcludedFromWindowsMenu = true
        cover.setAccessibilityIdentifier(sheetCoverAccessibilityIdentifier)
        cover.hasShadow = false
        cover.isOpaque = true
        cover.backgroundColor = .windowBackgroundColor
        cover.isMovable = false
        cover.animationBehavior = .none
        cover.collectionBehavior.insert(.fullScreenAuxiliary)
        sheet.addChildWindow(cover, ordered: .above)
        return SheetCover(sheet: sheet, cover: cover)
    }
}

#endif
