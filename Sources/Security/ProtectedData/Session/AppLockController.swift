import Foundation
import LocalAuthentication

/// The single source of truth for the app lock state (shipped model in
/// docs/SECURITY.md §4–§5).
///
/// Lock is an **explicit** state: views read it directly and nothing infers lock
/// from a blur flag. The system biometric sheet's transient `.inactive` is never
/// treated as an away event, so there is nothing to disambiguate (the grace=0
/// "no double-auth" behavior holds structurally; see `handleAwayEvent`).
///
/// The grace window is decided in exactly two places, on one predicate
/// (`graceDeadline`): the foreground return, and — on macOS, where the process
/// keeps running while the app is away — the deadline armed at the away event
/// (`armAwayRelock`), so the interval bounds how long an unlocked session can
/// survive rather than only when the next prompt appears.
///
/// Subsystem boundary:
/// - This controller owns the lock state, the auto-lock grace decision, the
///   per-platform away/foreground bookkeeping, the fail-closed Protected App-Data
///   relock on entering `locked`, and the **sequencing** of the authenticated-
///   `LAContext` handoff on unlock.
/// - `AppSessionOrchestrator` owns the app-session-auth concerns: it is the
///   custodian of the handoff context (`recordAuthentication`,
///   `pendingAuthenticatedContext`, `consumeAuthenticatedContextForProtectedData`).
///   On a successful unlock this controller calls back into the orchestrator (via
///   the injected `recordSuccessfulAuthentication`) to store the context and record
///   the authentication; on every away/relock/failure it calls `discardHandoffContext`.
///
/// Dependencies are injected as closures so the controller is a pure, isolated
/// state machine in unit tests (no real Keychain / LocalAuthentication / Protected
/// App-Data graph required).
@Observable
@MainActor
final class AppLockController {
    /// Explicit lock state. Views read this (and the small computed projections
    /// below); nothing infers lock from a blur flag.
    enum LockState: Equatable {
        /// Boots here. Fail-closed: Protected App-Data is relocked before this is
        /// entered (except the very first boot, where nothing is authorized yet).
        case locked
        /// An unlock attempt is in flight (the controller is driving an app-session
        /// authentication it is awaiting).
        case authenticating
        case unlocked
        /// The last unlock attempt failed; the lock surface shows retry / locked-out
        /// messaging based on the reason.
        case authenticationFailed(AppSessionAuthenticationFailureReason)
    }

    private let gracePeriodProvider: () -> Int?
    private let lastAuthenticationDateProvider: () -> Date?
    private let evaluateAppSessionAuthentication: (String) async throws -> AppSessionAuthenticationResult
    /// Store the authenticated context + record the authentication on the
    /// orchestrator (the handoff-context custodian).
    private let recordSuccessfulAuthentication: (LAContext?) -> Void
    /// Discard the orchestrator's pending handoff context (fail-closed) on
    /// away/relock/failure.
    private let discardHandoffContext: () -> Void
    /// Fail-closed Protected App-Data relock (fans out to all relock participants
    /// and zeroizes the wrapping root key). The trigger owner moves here; the
    /// fan-out itself stays in `ProtectedDataSessionCoordinator`.
    private let relockProtectedData: () async -> Void
    /// Post-unlock domain-open fan-out. Receives the authenticated context.
    private let postAuthenticationHandler: (LAContext?) async -> Void
    /// Ordinary-settings relock side effect.
    private let contentClearHandler: () -> Void
    /// Live coordinator query used on macOS to close begin/end hook races. When
    /// absent, tests that exercise the controller directly fall back to the
    /// main-actor mirror.
    private let operationPromptInProgressProvider: (() -> Bool)?
    /// Suspends for the given number of seconds — the wake-up the macOS away
    /// relock deadline is built on. Production sleeps on the continuous clock,
    /// which keeps counting while the Mac is asleep, so a machine that wakes past
    /// the deadline relocks at once instead of restarting the wait. Tests inject
    /// their own so the deadline is driven rather than waited out.
    private let waitForAwayRelockDeadline: (TimeInterval) async throws -> Void

    private(set) var lockState: LockState = .locked

    #if os(macOS)
    /// A macOS app-resign arrived while a private-key operation prompt was in
    /// flight (the `.authenticating` rule). The away decision is
    /// deferred to the prompts' end: `handleOperationPromptsEnded()` processes it
    /// if the app is still not foreground-active, and discards it if the user
    /// returned.
    private var hasPendingOperationPromptAway = false

    /// Main-actor mirror of "an operation-prompt session is open", maintained by
    /// `handleOperationPromptSessionBegan()` / `handleOperationPromptsEnded()`
    /// (wired from `AuthenticationPromptCoordinator`'s lifecycle hooks). The away
    /// rule combines this mirror with the coordinator's live depth when one is
    /// injected: live depth catches a resign that beats the began-hop, while a
    /// false live depth prevents a stale ended-hop mirror from swallowing a real
    /// away after the prompt has ended.
    /// A counter, not a Bool: if a new session's began-hop lands before the
    /// previous session's ended-hop, the count stays positive — correct under any
    /// hop interleaving. (A resign racing ahead of the very first began-hop is
    /// processed as a genuine away — fail-closed, the right direction.)
    private var openOperationPromptSessions = 0

    /// The pending away relock wake-up (`armAwayRelock`). It exists only while
    /// the app is unlocked and away: every transition out of that pair disarms
    /// it, and the wake-up re-checks both before acting.
    private var awayRelockTask: Task<Void, Never>?
    #endif

    /// Monotonic token bumped on every genuine away event. The unlock flow captures
    /// it before the auth `await` and bails if it changed — i.e. the app genuinely
    /// left the foreground mid-authentication, so the just-produced context must be
    /// discarded and not handed off ("real background wins").
    private var awayGeneration = 0

    /// The away epoch (`awayGeneration`) the controller has already responded to with a
    /// foreground decision (authenticated, stayed unlocked within grace, or is awaiting
    /// an explicit retry after a failure). A foreground whose `awayGeneration` still
    /// matches this is a spurious `.active` — the biometric sheet's own dismissal,
    /// Control Center, an app-switcher peek, a banner — and must NOT re-trigger auth.
    /// This closes both the grace=0 unlock loop and the cancelled/failed-state re-prompt
    /// loop. `nil` = no epoch handled yet (cold launch). The explicit retry button uses
    /// `retryUnlock`, which bypasses this gate.
    private var handledAwayGeneration: Int?

    /// Whether the app is genuinely foreground-active. Owned here as the single
    /// source of truth and updated by the lifecycle observer via
    /// `noteForegroundActive(_:)`. The cosmetic cover reads this through
    /// `isCosmeticallyCovered`.
    ///
    /// It also gates `handleForegroundActive`: the lock surface auto-invokes
    /// authentication when it appears, but at grace=0 the surface is inserted
    /// *during* the background lock transition. Without this guard that auto-invoke
    /// would start an unlock while the app is hidden and consume the away epoch
    /// (`handledAwayGeneration`), suppressing the genuine foreground return.
    /// Defaults to `true` because a cold launch is foreground.
    private(set) var isForegroundActive = true

    /// Holds the cosmetic cover up across the *asynchronous* gap between a
    /// genuine foreground return and the lock decision that follows it. The
    /// observer sets `isForegroundActive = true` synchronously (which alone would
    /// drop the cover) and only then schedules `handleForegroundActive` on a
    /// `Task`. If grace has expired, the lock surface is not raised until that
    /// task runs, so for one or more frames the underlying content would be
    /// visible — a resume-time flash of protected content. Set `true`
    /// synchronously in `noteForegroundActive` on the false→true transition and
    /// cleared by `handleForegroundActive`'s top-level `defer` on every exit path,
    /// so the cover persists until the lock decision has resolved (surface raised,
    /// stayed unlocked within grace, or spurious foreground).
    private(set) var isResolvingForegroundLock = false

    /// Generation of lock-state transitions, used by views/tests as an
    /// `@Observable` change signal independent of equal states.
    private(set) var transitionGeneration = 0

    init(
        gracePeriodProvider: @escaping () -> Int?,
        lastAuthenticationDateProvider: @escaping () -> Date?,
        evaluateAppSessionAuthentication: @escaping (String) async throws -> AppSessionAuthenticationResult,
        recordSuccessfulAuthentication: @escaping (LAContext?) -> Void,
        discardHandoffContext: @escaping () -> Void,
        relockProtectedData: @escaping () async -> Void,
        postAuthenticationHandler: @escaping (LAContext?) async -> Void = { _ in },
        contentClearHandler: @escaping () -> Void = {},
        operationPromptInProgressProvider: (() -> Bool)? = nil,
        waitForAwayRelockDeadline: @escaping (TimeInterval) async throws -> Void = { seconds in
            try await Task.sleep(for: .seconds(seconds), tolerance: .seconds(1), clock: .continuous)
        }
    ) {
        self.gracePeriodProvider = gracePeriodProvider
        self.lastAuthenticationDateProvider = lastAuthenticationDateProvider
        self.evaluateAppSessionAuthentication = evaluateAppSessionAuthentication
        self.recordSuccessfulAuthentication = recordSuccessfulAuthentication
        self.discardHandoffContext = discardHandoffContext
        self.relockProtectedData = relockProtectedData
        self.postAuthenticationHandler = postAuthenticationHandler
        self.contentClearHandler = contentClearHandler
        self.operationPromptInProgressProvider = operationPromptInProgressProvider
        self.waitForAwayRelockDeadline = waitForAwayRelockDeadline
    }

    // MARK: - Computed projections (read by views)

    var isLocked: Bool {
        if case .unlocked = lockState {
            return false
        }
        return true
    }

    var isAuthenticating: Bool {
        if case .authenticating = lockState {
            return true
        }
        return false
    }

    var authenticationFailure: AppSessionAuthenticationFailureReason? {
        if case .authenticationFailed(let reason) = lockState {
            return reason
        }
        return nil
    }

    /// The cosmetic-cover trigger: the shield window (`AppLockShieldWindow`)
    /// presents on this predicate OR `isLocked`, and renders its privacy face
    /// when covered but not locked (issue #723). True while the app is not
    /// foreground-active, and additionally while a foreground return is still
    /// resolving its lock decision (`isResolvingForegroundLock`) so content
    /// cannot flash between the synchronous foreground signal and the
    /// asynchronous lock surface. Distinct from `isLocked`: the cover is
    /// cosmetic (app-switcher snapshot / shoulder-surfing), the lock surface
    /// is the authentication gate.
    var isCosmeticallyCovered: Bool {
        !isForegroundActive || isResolvingForegroundLock
    }

    // MARK: - Lifecycle entry points (called by the lifecycle observer)

    /// Update the foreground-active signal from the lifecycle observer (the single
    /// owner of the platform signal). Pure bookkeeping — it performs no lock logic.
    /// The observer must set this `true` *before* calling `handleForegroundActive`
    /// on a genuine foreground, and `false` on `.inactive` / `.background` / resign /
    /// screen-lock, so the lock surface's auto-invoke during a background lock
    /// transition is a no-op and the genuine foreground return drives auth.
    func noteForegroundActive(_ active: Bool) {
        guard isForegroundActive != active else {
            return
        }
        isForegroundActive = active
        if active {
            // The away window is over — `handleForegroundActive`, which the
            // observer always schedules right after this call, owns the lock
            // decision from here.
            disarmAwayRelock()
            // Keep the cosmetic cover up across the async gap until
            // `handleForegroundActive` resolves the lock decision. Set
            // unconditionally on the transition (not gated on grace/lock
            // predicates — that would duplicate the decision and race it); the
            // matching `handleForegroundActive` — always scheduled by the observer
            // right after this call — clears it on every exit path.
            isResolvingForegroundLock = true
        }
    }

    /// A genuine away event for this platform: iOS/iPadOS/visionOS
    /// `ScenePhase.background`; macOS app-resign ∪ screen-lock ∪ "Lock Now".
    /// (A biometric prompt's `.inactive` is NOT routed here — see the observer.)
    func handleAwayEvent() {
        #if os(macOS)
        // The `.authenticating` rule: an app-resign during an
        // app-driven authentication is explicit state, never an away event.
        //
        // (a) An app-session unlock is in flight (`.authenticating` spans the
        //     evaluation AND the post-auth fan-out): the system auth sheet's own
        //     resign must not invalidate the unlock it belongs to. Every exit from
        //     the unlock flow settles an explicit lock state, and the genuine lock
        //     signals — screen-lock and "Lock Now" — flow through `lockNow`, which
        //     is not routed here and therefore still wins (it bumps
        //     `awayGeneration`, so the in-flight result is discarded).
        if isAuthenticating {
            return
        }
        // (b) A private-key operation prompt is in flight: the resign is ambiguous
        //     (the prompt's own resign vs. a genuine app switch), so the away
        //     decision is DEFERRED to the prompts' end rather than suppressed
        //     outright. `handleOperationPromptsEnded()` processes the away if the
        //     app is still not foreground-active then, and discards it if the user
        //     returned.
        if isOperationPromptInProgressForAwayRule {
            // Later resigns during the same prompt session carry no additional
            // information: the decision at the prompts' end depends only on
            // `isForegroundActive`.
            hasPendingOperationPromptAway = true
            return
        }
        #endif

        // Any genuine away invalidates an in-flight unlock attempt.
        awayGeneration &+= 1
        discardHandoffContext()

        // "Immediately" (interval 0) locks on the away event, literally. A
        // non-zero interval leaves the session open for the rest of the grace
        // window, which two places then decide on the same predicate: the
        // foreground return, and — on macOS, where the process keeps running
        // while away — the armed deadline below if the user has not come back
        // by then.
        guard effectiveGracePeriod() == 0 else {
            armAwayRelock()
            return
        }
        Task { await enterLocked() }
    }

    /// Arm the wake-up that relocks the app once the grace window expires while
    /// it is away.
    ///
    /// macOS only, and the reason is the platform's rather than a policy: the
    /// process keeps running while the app is not frontmost, so with no wake-up
    /// nothing relocks until the user returns — the unwrapped wrapping root key
    /// and decrypted content stay resident for however long that is, and the
    /// grace interval bounds only the next prompt, not the exposure. iOS,
    /// iPadOS, and visionOS suspend the process while away instead, so
    /// evaluating on the foreground return is exact there; a wake-up armed on
    /// those platforms could only fire inside whatever sliver of background
    /// execution the system happened to grant, which would make the relock
    /// moment a system-timing artifact rather than the stated interval.
    private func armAwayRelock() {
        #if os(macOS)
        disarmAwayRelock()
        // Nothing to relock unless a session is actually open: `.locked` and
        // `.authenticationFailed` have already relocked, and `.authenticating`
        // settles an explicit state of its own.
        guard case .unlocked = lockState else {
            return
        }
        let secondsRemaining = max(graceDeadline.timeIntervalSinceNow, 0)
        awayRelockTask = Task { [weak self] in
            guard let wait = self?.waitForAwayRelockDeadline else {
                return
            }
            do {
                try await wait(secondsRemaining)
            } catch {
                // Cancelled: a foreground return or an explicit lock took over.
                return
            }
            guard !Task.isCancelled else {
                return
            }
            self?.handleAwayRelockDeadline()
        }
        #endif
    }

    /// Cancel the pending away relock wake-up. A no-op where none is armed,
    /// which is every platform but macOS.
    private func disarmAwayRelock() {
        #if os(macOS)
        awayRelockTask?.cancel()
        awayRelockTask = nil
        #endif
    }

    /// The away relock deadline arrived. It applies the same predicate the
    /// foreground return applies — the deadline is a second place to evaluate
    /// the grace window, never a second rule for it.
    private func handleAwayRelockDeadline() {
        #if os(macOS)
        // This wake-up is spent; clearing the handle first keeps the re-arm
        // below from cancelling the task it is running in.
        awayRelockTask = nil

        // The user came back, or the session is no longer open: whoever holds
        // that transition owns the decision.
        guard !isForegroundActive, case .unlocked = lockState else {
            return
        }
        guard isGracePeriodExpired else {
            // The wall clock the window is expressed in moved relative to the
            // real time waited out (an adjustment or a slew), so the window has
            // not actually passed. Wait out the remainder rather than relocking
            // early.
            armAwayRelock()
            return
        }
        Task { await enterLocked() }
        #endif
    }

    /// An operation-prompt session began (the coordinator's stack went 0 → 1;
    /// wired from `AuthenticationPromptCoordinator` on macOS). Opens the
    /// main-actor mirror the away rule consults.
    func handleOperationPromptSessionBegan() {
        #if os(macOS)
        openOperationPromptSessions += 1
        #endif
    }

    /// The last in-flight private-key operation prompt ended (wired from
    /// `AuthenticationPromptCoordinator` on macOS). Closes the main-actor mirror
    /// and decides a deferred away (the `.authenticating` rule): if a
    /// resign arrived during the prompts and the app is still not
    /// foreground-active, the away is processed now (normal grace semantics); if
    /// the user returned — or an explicit lock already superseded it — it is
    /// discarded.
    func handleOperationPromptsEnded() {
        #if os(macOS)
        if openOperationPromptSessions > 0 {
            openOperationPromptSessions -= 1
        }
        guard hasPendingOperationPromptAway else {
            return
        }
        hasPendingOperationPromptAway = false
        guard !isLockedState else {
            // An explicit lock (lockNow / screen-lock) or a processed away
            // already locked the app; the deferred decision is moot.
            return
        }
        guard !isForegroundActive else {
            return
        }
        handleAwayEvent()
        #endif
    }

    #if os(macOS)
    private var isOperationPromptInProgressForAwayRule: Bool {
        if let operationPromptInProgressProvider {
            return operationPromptInProgressProvider()
        }
        return openOperationPromptSessions > 0
    }
    #endif

    /// The app returned to the foreground. Idempotent: safe to call from both the
    /// lifecycle observer (`.active` / `didBecomeActive`) and the lock surface's
    /// auto-invoke.
    func handleForegroundActive() async {
        // Release the resume-time cover hold once the lock decision has resolved,
        // on EVERY exit path (not-foreground-active, in-flight, spurious,
        // within-grace, or the full unlock flow). On the unlock path this fires in
        // the same main-actor slice as the terminal `setLockState`, so when the
        // surface is not raised (unlocked/within-grace) the cover and any surface
        // drop together with no post-decision flash; when the surface IS raised it
        // already draws above the cover, so clearing here is safe. Structurally
        // prevents a cover stuck up forever.
        defer { isResolvingForegroundLock = false }

        // Only a genuine foreground-active state drives an unlock. The lock surface
        // auto-invokes this on appear, and at grace=0 the surface is inserted during
        // the background lock transition — that call must be a pure no-op (no
        // `handledAwayGeneration` marking, no `runUnlockFlow`) so the away epoch is
        // not consumed and the genuine `.active` return drives auth.
        guard isForegroundActive else {
            return
        }

        // An unlock is already in flight; do not start a second one (the
        // check-then-set is atomic under @MainActor up to the first `await` in
        // `runUnlockFlow`).
        guard !isAuthenticating else {
            return
        }

        // Spurious-foreground gate: a foreground whose away epoch we have already
        // responded to (authenticated, stayed unlocked within grace, or are awaiting an
        // explicit retry after a failure) is a non-away `.active` — the biometric
        // sheet's own dismissal, Control Center, an app-switcher peek, a banner. It must
        // NOT re-trigger auth. This closes the grace=0 unlock loop AND the
        // cancelled/failed-state re-prompt loop. Only a new genuine away (which bumps
        // `awayGeneration`) warrants a fresh response; the explicit retry button uses
        // `retryUnlock`, which bypasses this.
        if let handled = handledAwayGeneration, handled == awayGeneration {
            return
        }

        switch lockState {
        case .unlocked:
            // Within the grace window a foreground round-trip stays unlocked (no
            // re-auth, content preserved) — "cover ≠ lock". Past it, re-authenticate.
            if isGracePeriodExpired {
                await runUnlockFlow()
            } else {
                // Genuine away, but within grace → stay unlocked and mark this epoch
                // handled so a later spurious `.active` is a no-op.
                handledAwayGeneration = awayGeneration
            }
        case .locked, .authenticationFailed:
            await runUnlockFlow()
        case .authenticating:
            break
        }
    }

    /// Re-invoke the unlock flow from the lock surface's retry affordance.
    func retryUnlock() async {
        guard !isAuthenticating else {
            return
        }
        await runUnlockFlow()
    }

    /// Lock immediately regardless of the grace interval (macOS "Lock Now" / screen
    /// lock; also the seam for any future explicit-lock affordance).
    func lockNow() {
        #if os(macOS)
        // Clear the deferred away SYNCHRONOUSLY: the queued `enterLocked` also
        // clears it, but a prompts-ended hop could run between this call and that
        // task, and must not process the now-moot deferral into a second relock
        // cycle. An explicit lock always supersedes the deferred decision.
        hasPendingOperationPromptAway = false
        #endif
        // Same reasoning for the away deadline: it must not fire into a second
        // relock cycle while this lock's `enterLocked` is still queued.
        disarmAwayRelock()
        Task { await enterLocked() }
    }

    /// Local Data Reset hook for the lock-state portion of the reset. The
    /// orchestrator clears its own auth record.
    func resetAfterLocalDataReset(preserveAuthentication: Bool = false) {
        awayGeneration &+= 1
        #if os(macOS)
        // Dropping a deferred away here is sound: by the time this runs, Local
        // Data Reset has already relocked the protected-data session (zeroizing
        // the wrapping root key) and deleted all keychain items and protected
        // domains — there is no data left for a lock to protect — and the
        // post-reset restart gate disables all UI interaction until relaunch.
        // `openOperationPromptSessions` is deliberately NOT reset: the hooks are
        // the counter's sole mutators, and any in-flight reset authentication
        // prompt session decrements normally after this method returns.
        hasPendingOperationPromptAway = false
        #endif
        // The reset settles the lock state directly, so any wake-up armed for
        // the pre-reset session is moot.
        disarmAwayRelock()
        discardHandoffContext()
        if preserveAuthentication {
            // Stay unlocked and mark this epoch handled so a post-reset spurious
            // `.active` is a no-op.
            handledAwayGeneration = awayGeneration
            setLockState(.unlocked)
        } else {
            setLockState(.locked)
        }
    }

    // MARK: - Unlock flow

    private func runUnlockFlow() async {
        // Mark the attempt in flight synchronously, BEFORE the first `await`, so a
        // second resume observes `.authenticating` at the `handleForegroundActive`
        // guard and cannot start a duplicate prompt. `.authenticating` is also what
        // the macOS `.authenticating` rule keys off in `handleAwayEvent` — it spans
        // the whole flow (set below, and every exit path settles a different state).
        let attemptAwayGeneration = awayGeneration
        // Mark this away epoch as being handled by a foreground response. Setting it
        // here (not only on success) means a failed/cancelled attempt also marks the
        // epoch, so the dismissal `.active` does not auto-retry; an attempt later
        // invalidated by a genuine away leaves `handledAwayGeneration != awayGeneration`,
        // so the next foreground correctly re-authenticates.
        handledAwayGeneration = attemptAwayGeneration
        setLockState(.authenticating)

        // Fail-closed: clear content and relock Protected App-Data before prompting.
        contentClearHandler()
        await relockProtectedData()

        do {
            let result = try await evaluateAppSessionAuthentication(Self.localizedResumeReason)

            // The app genuinely left the foreground during authentication: discard
            // the result and stay locked ("real background wins"). On macOS the
            // sheet's own resign never bumps the generation (the `.authenticating`
            // rule), so this fires only for a real iOS `.background` or a macOS
            // `lockNow` (screen-lock / "Lock Now") during the prompt.
            guard attemptAwayGeneration == awayGeneration else {
                // The freshly produced context was never handed to the orchestrator
                // (recordSuccessfulAuthentication is skipped on this path), so invalidate
                // it here. Nothing reopened Protected App-Data before this point (the
                // top-of-flow relock still holds), so a state-only `.locked` is fail-closed.
                result.context?.invalidate()
                discardHandoffContext()
                if !isLockedState {
                    setLockState(.locked)
                }
                return
            }

            if result.isAuthenticated {
                recordSuccessfulAuthentication(result.context)
                await postAuthenticationHandler(result.context)
                // A genuine away during the post-auth fan-out: postAuthenticationHandler
                // has already REOPENED Protected App-Data, so fail closed for real —
                // relock, not just a UI state flip ("real background wins"). enterLocked
                // discards the handoff, clears content, awaits the real relock, and
                // settles `.locked`.
                guard attemptAwayGeneration == awayGeneration else {
                    await enterLocked()
                    return
                }
                setLockState(.unlocked)
                // The unlock settled while the app was not foreground-active:
                // the user left during the post-auth fan-out, or this unlock's
                // own system sheet has not handed focus back yet. Both
                // evaluation points would otherwise miss this session — the
                // `.authenticating` rule swallowed every resign in that span, so
                // no away event arms the deadline, and the eventual return finds
                // its epoch already marked (above) and stops before the grace
                // check. Arm here: a genuine return disarms it, the wake-up
                // re-checks that the app is still away, and a relock bumps
                // `awayGeneration` — which is what lets that return
                // re-authenticate. Same ambiguity, same resolution as the
                // operation-prompt rule's decision at the prompts' end.
                if !isForegroundActive {
                    armAwayRelock()
                }
            } else {
                discardHandoffContext()
                setLockState(.authenticationFailed(.authenticationFailed))
            }
        } catch {
            discardHandoffContext()
            guard attemptAwayGeneration == awayGeneration else {
                if !isLockedState {
                    setLockState(.locked)
                }
                return
            }
            setLockState(.authenticationFailed(Self.failureReason(for: error)))
        }
    }

    private func enterLocked() async {
        #if os(macOS)
        // An explicit lock supersedes a pending deferred away (the `.authenticating`
        // rule): the app is locking right now, so the prompts'-end decision is moot —
        // clearing it avoids a redundant second relock cycle at the prompts' end.
        hasPendingOperationPromptAway = false
        #endif
        // The session is closing; there is no longer a grace window to enforce.
        disarmAwayRelock()
        awayGeneration &+= 1
        discardHandoffContext()
        contentClearHandler()
        await relockProtectedData()
        setLockState(.locked)
    }

    // MARK: - Grace

    private func effectiveGracePeriod() -> Int {
        // Fail-closed: an unavailable settings snapshot → 0 (immediate auth).
        gracePeriodProvider() ?? 0
    }

    /// The instant the current grace window ends. A missing authentication date
    /// fails closed to a window that is already over. Both places that decide
    /// whether the session may stay open — the foreground return and the macOS
    /// away deadline — read this one definition, so the two can never drift into
    /// separate rules.
    private var graceDeadline: Date {
        guard let lastAuthenticationDate = lastAuthenticationDateProvider() else {
            return .distantPast
        }
        return lastAuthenticationDate.addingTimeInterval(TimeInterval(effectiveGracePeriod()))
    }

    private var isGracePeriodExpired: Bool {
        Date() > graceDeadline
    }

    // MARK: - State helpers

    private var isLockedState: Bool {
        if case .locked = lockState {
            return true
        }
        return false
    }

    private func setLockState(_ newState: LockState) {
        guard newState != lockState else {
            return
        }
        lockState = newState
        transitionGeneration &+= 1
    }

    private static var localizedResumeReason: String {
        String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume")
    }

    /// Map an authentication error to a user-facing failure reason.
    private static func failureReason(for error: Error) -> AppSessionAuthenticationFailureReason {
        if let authenticationError = error as? AuthenticationError {
            switch authenticationError {
            case .appAccessBiometricsLockedOut:
                return .biometricsLockedOut
            case .biometricsUnavailable,
                 .appAccessBiometricsUnavailable,
                 .cancelled,
                 .failed,
                 .accessControlCreationFailed,
                 .modeSwitchFailed,
                 .noIdentities,
                 .backupRequired:
                return .authenticationFailed
            }
        }

        if let laError = error as? LAError, laError.code == .biometryLockout {
            return .biometricsLockedOut
        }

        return .authenticationFailed
    }
}
