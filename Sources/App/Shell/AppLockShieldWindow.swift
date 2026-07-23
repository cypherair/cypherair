import SwiftUI
#if os(iOS) || os(visionOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

// MARK: - App-lock shield window (issue #697)
//
// While the app is locked, the lock surface must cover ALL app content — the
// base scene, SwiftUI sheets and fullScreenCovers, and macOS window-modal
// sheets — with input beneath blocked, without dismissing any presentation.
// An in-scene `.overlay` cannot do that: SwiftUI presentations render above
// the scene content that hosts the overlay. The shield therefore hosts the
// existing `AppLockSurfaceView` in a separate platform window layered above
// the app's presentation stack:
//
// - iOS / iPadOS / visionOS: an additional `UIWindow` in the same
//   `UIWindowScene` at a `windowLevel` above `.alert`. Level stacking takes
//   precedence over window ordering within a level, and SwiftUI presentations
//   render inside the app's normal-level window, so the shield covers them by
//   construction. The shield is key while visible (keyboard/focus beneath is
//   blocked) and hands key back on unlock.
// - macOS: a borderless child window attached to the app window with
//   `addChildWindow(_:ordered: .above)`. Empirically (probed for #697),
//   within-level ordering NEVER beats an attached sheet — the sheet stays in
//   front of a same-level child regardless of explicit reordering — so the
//   shield runs at an elevated `NSWindow.Level` while the app is active.
//   `addChildWindow` itself resets the child's level to the parent's (probed
//   for #720), so the elevated level is applied only AFTER attachment.
//   Because AppKit window levels are global across apps, the shield drops
//   back to `.normal` on a REAL app switch so it can never float above other
//   apps' windows; that inactive posture degrades exactly to the pre-shield
//   in-scene behavior, never below it. An app-resign caused by the lock
//   surface's own unlock prompt is NOT a real app switch: LocalAuthentication
//   resigns the app for the evaluation (the same resign the controller's
//   `.authenticating` rule recognizes as the auth sheet's own), and a
//   `.normal`-level child would fall back behind an attached sheet for the
//   whole prompt — so the shield holds its elevated level while
//   `AppLockController.isAuthenticating` spans the attempt, and drops to
//   `.normal` only if the attempt ends unresolved with the app still
//   inactive. The shield frame is the union of the app-window frame and any
//   attached-sheet chain, because sheets may extend outside the parent frame.
//
// The shield observes only `AppLockController` state that already existed:
// `isLocked` (exactly the state that previously drove the in-scene overlay)
// plus, on macOS, `isAuthenticating` for the activation-level policy above.
// It contains no lock logic of its own and never touches presentation state.
// Locking hides nothing and dismisses nothing — after unlock the user is
// exactly where they left off.

extension View {
    /// Install the app-lock shield: a window-level bridge that presents
    /// `AppLockSurfaceView` above all app content while
    /// `appLockController.isLocked` is true. Replaces the previous in-scene
    /// `.overlay` presentation of the lock surface.
    @MainActor
    func appLockShieldWindow(appLockController: AppLockController) -> some View {
        background(
            AppLockShieldWindowHost(
                appLockController: appLockController,
                isLocked: appLockController.isLocked,
                isAuthenticating: appLockController.isAuthenticating
            )
        )
    }
}

#if os(iOS) || os(visionOS)

private struct AppLockShieldWindowHost: UIViewRepresentable {
    let appLockController: AppLockController
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
        context.coordinator.setLocked(isLocked)
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

    func setLocked(_ locked: Bool) {
        guard locked != isLocked else { return }
        isLocked = locked
        apply()
    }

    func tearDown() {
        removeShield(restoringKey: false)
        windowScene = nil
    }

    private func apply() {
        if isLocked {
            presentShieldIfPossible()
        } else {
            removeShield(restoringKey: true)
        }
    }

    private func presentShieldIfPossible() {
        guard shieldWindow == nil, let windowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        window.windowLevel = Self.shieldWindowLevel
        window.rootViewController = UIHostingController(
            rootView: AppLockSurfaceView(appLockController: appLockController)
        )
        restoreKeyWindow = windowScene.keyWindow
        // End any active text-input session beneath the shield so the system
        // keyboard (hosted in its own high-level window) cannot remain up over
        // the lock surface or keep routing keystrokes into covered content.
        // Field contents are untouched; after unlock, refocusing is a tap.
        restoreKeyWindow?.endEditing(true)
        window.isHidden = false
        window.makeKey()
        shieldWindow = window
    }

    private func removeShield(restoringKey: Bool) {
        defer { restoreKeyWindow = nil }
        guard let shieldWindow else { return }
        shieldWindow.isHidden = true
        self.shieldWindow = nil
        guard restoringKey else { return }
        if let restoreKeyWindow, !restoreKeyWindow.isHidden {
            restoreKeyWindow.makeKey()
        } else if let fallback = windowScene?.windows.first(where: { !$0.isHidden }) {
            fallback.makeKey()
        }
    }
}

#elseif os(macOS)

private struct AppLockShieldWindowHost: NSViewRepresentable {
    let appLockController: AppLockController
    let isLocked: Bool
    /// `AppLockController.isAuthenticating`, wired through the SwiftUI update
    /// path (a stored property, so the representable value changes and
    /// `updateNSView` fires on every `.authenticating` transition — including
    /// the attempt that ends unresolved while the app is still inactive,
    /// which produces no NSApplication activation notification to re-derive
    /// the level from).
    let isAuthenticating: Bool

    func makeCoordinator() -> AppLockShieldWindowCoordinator {
        AppLockShieldWindowCoordinator(appLockController: appLockController)
    }

    func makeNSView(context: Context) -> AppLockShieldAnchorView {
        let view = AppLockShieldAnchorView()
        view.coordinator = context.coordinator
        return view
    }

    func updateNSView(_ nsView: AppLockShieldAnchorView, context: Context) {
        context.coordinator.setState(locked: isLocked, authenticating: isAuthenticating)
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

/// Borderless windows refuse key status by default; the shield must be key
/// while locked so keyboard events cannot reach covered windows.
private final class AppLockShieldPanel: NSWindow {
    override var canBecomeKey: Bool { true }
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
    /// about — and while an app-session unlock attempt is in flight:
    /// LocalAuthentication's prompt resigns the app (the exact resign
    /// `AppLockController.handleAwayEvent`'s `.authenticating` rule treats as
    /// the auth sheet's own), and a `.normal`-level child window falls behind
    /// an attached sheet (probed for #697) — dropping on that resign would
    /// expose the covered sheet for the whole prompt. Only a real app switch
    /// — inactive with no unlock in flight — drops to `.normal`, preserving
    /// the recorded deviation that the shield never floats above other apps'
    /// windows.
    static func shieldLevel(appIsActive: Bool, isUnlockAuthenticationInFlight: Bool) -> NSWindow.Level {
        appIsActive || isUnlockAuthenticationInFlight ? activeShieldLevel : .normal
    }

    private let appLockController: AppLockController
    private weak var hostWindow: NSWindow?
    private var shieldWindow: NSWindow?
    private weak var restoreKeyWindow: NSWindow?
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

    init(appLockController: AppLockController) {
        self.appLockController = appLockController
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

    func setState(locked: Bool, authenticating: Bool) {
        let authenticatingChanged = authenticating != isAuthenticating
        isAuthenticating = authenticating
        if locked != isLocked {
            isLocked = locked
            apply()
        } else if authenticatingChanged {
            // `.authenticating` begins and ends without `isLocked` changing.
            // Re-derive the level on each flip: the begin re-elevates a
            // shield whose level a racing prompt-resign notification may
            // already have processed, and the end drops an elevated shield
            // back to `.normal` when the attempt resolves while the app is
            // still inactive (the system cancels the prompt on a real app
            // switch; no NSApplication activation notification follows).
            applyActivationState()
        }
    }

    func tearDown() {
        removeShield(restoringKey: false)
        hostWindow = nil
    }

    private func apply() {
        if isLocked {
            presentShieldIfPossible()
        } else {
            removeShield(restoringKey: true)
        }
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
        shield.hasShadow = false
        shield.isOpaque = true
        shield.backgroundColor = .windowBackgroundColor
        shield.isMovable = false
        shield.animationBehavior = .none
        // Join a full-screen host's space instead of being stranded outside it.
        shield.collectionBehavior.insert(.fullScreenAuxiliary)
        shield.contentView = NSHostingView(
            rootView: AppLockSurfaceView(appLockController: appLockController)
        )
        restoreKeyWindow = NSApp.keyWindow ?? hostWindow
        hostWindow.addChildWindow(shield, ordered: .above)
        shieldWindow = shield
        beginObservations(hostWindow: hostWindow)
        // The level is applied strictly AFTER `addChildWindow`:
        // `addChildWindow` resets the child's level to the parent's (probed
        // for #720 — a pre-attach `modalPanel + 1` reads `.normal` post-
        // attach, leaving an attached sheet in front of the shield), so a
        // level set before attachment is silently lost. A post-attach level
        // sticks and covers the sheet. `applyActivationState()` is the single
        // level writer (level policy + key restore + frame), and every other
        // call to it happens after attachment by construction.
        applyActivationState()
    }

    private func removeShield(restoringKey: Bool) {
        endObservations()
        defer { restoreKeyWindow = nil }
        guard let shieldWindow else { return }
        shieldWindow.parent?.removeChildWindow(shieldWindow)
        shieldWindow.orderOut(nil)
        self.shieldWindow = nil
        guard restoringKey else { return }
        if let target = restoreKeyWindow ?? hostWindow, target.isVisible {
            target.makeKey()
        }
    }

    // MARK: - Geometry & level upkeep

    /// The shield must cover the app window AND its attached-sheet chain:
    /// sheets are separate windows that may extend outside the parent frame
    /// (verified empirically for #697).
    private static func shieldFrame(for hostWindow: NSWindow) -> NSRect {
        var frame = hostWindow.frame
        var sheet = hostWindow.attachedSheet
        while let current = sheet {
            frame = frame.union(current.frame)
            sheet = current.attachedSheet
        }
        return frame
    }

    private func beginObservations(hostWindow: NSWindow) {
        let center = NotificationCenter.default
        let geometryNames: [Notification.Name] = [
            NSWindow.didResizeNotification,
            NSWindow.didMoveNotification,
            NSWindow.willBeginSheetNotification,
            NSWindow.didEndSheetNotification
        ]
        for name in geometryNames {
            observers.append(center.addObserver(forName: name, object: hostWindow, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.refreshShieldGeometry()
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
    }

    private func applyActivationState() {
        guard let shieldWindow else { return }
        shieldWindow.level = Self.shieldLevel(
            appIsActive: NSApp.isActive,
            isUnlockAuthenticationInFlight: appLockController.isAuthenticating
        )
        // Key status is restored only on genuine activation — never
        // `makeKey()` while the app is inactive, including the elevated
        // auth-prompt posture (the LA sheet owns focus during the prompt).
        if NSApp.isActive {
            shieldWindow.makeKey()
        }
        applyShieldFrame()
    }
}

#endif
