import Foundation
import LocalAuthentication

/// The single source of truth for the app lock state (the auth-lifecycle
/// redesign; shipped model in docs/SECURITY.md §4–§5).
///
/// `AppLockController` replaces the previous, entangled model where "locked" was
/// *inferred* from `AppSessionOrchestrator.isPrivacyScreenBlurred` plus a cluster
/// of disambiguation machinery (the authentication shield, the
/// `PrivacyScreenLifecycleGate`, the prompt union snapshot, and a settle window).
/// Here, lock is an **explicit** state, and the system biometric sheet's transient
/// `.inactive` is never treated as an away event — so there is nothing to
/// disambiguate (the grace=0 "no double-auth" behavior is preserved structurally;
/// see `handleAwayEvent`).
///
/// Subsystem boundary (TARGET §1, ROADMAP §3 P1):
/// - This controller owns the lock state, the auto-lock grace decision, the
///   per-platform away/foreground bookkeeping, the fail-closed Protected App-Data
///   relock on entering `locked`, and the **sequencing** of the authenticated-
///   `LAContext` handoff on unlock.
/// - `AppSessionOrchestrator` keeps the app-session-auth concerns: it remains the
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
    private let evaluateAppSessionAuthentication: (String, String) async throws -> AppSessionAuthenticationResult
    /// Store the authenticated context + record the authentication on the
    /// orchestrator (D1: the orchestrator stays the handoff-context custodian).
    private let recordSuccessfulAuthentication: (LAContext?) -> Void
    /// Discard the orchestrator's pending handoff context (fail-closed) on
    /// away/relock/failure.
    private let discardHandoffContext: (String) -> Void
    /// Fail-closed Protected App-Data relock (fans out to all relock participants
    /// and zeroizes the wrapping root key). The trigger owner moves here; the
    /// fan-out itself stays in `ProtectedDataSessionCoordinator`.
    private let relockProtectedData: () async -> Void
    /// Post-unlock domain-open fan-out (moved verbatim from the orchestrator's
    /// construction). Receives the authenticated context and the source.
    private let postAuthenticationHandler: (LAContext?, String) async -> Void
    /// Ordinary-settings relock side effect (the orchestrator's old
    /// `contentClearHandler`).
    private let contentClearHandler: () -> Void
    /// UI-test bypass (the orchestrator's old `shouldBypassPrivacyAuthentication`).
    private let shouldBypassAuthentication: () -> Bool
    /// Live coordinator query used on macOS to close begin/end hook races. When
    /// absent, tests that exercise the controller directly fall back to the
    /// main-actor mirror.
    private let operationPromptInProgressProvider: (() -> Bool)?
    private let traceStore: AuthLifecycleTraceStore?

    private(set) var lockState: LockState = .locked

    #if os(macOS)
    /// A macOS app-resign arrived while a private-key operation prompt was in
    /// flight (the `.authenticating` rule, TARGET §3). The away decision is
    /// deferred to the prompts' end: `handleOperationPromptsEnded()` processes it
    /// if the app is still not foreground-active, and discards it if the user
    /// returned. Holds the original away source for tracing.
    private var pendingOperationPromptAway: String?

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
    /// `noteForegroundActive(_:)`. The cosmetic cover reads this
    /// (`isCovered = !isForegroundActive`).
    ///
    /// It also gates `handleForegroundActive`: the lock surface auto-invokes
    /// authentication when it appears, but at grace=0 the surface is inserted
    /// *during* the background lock transition. Without this guard that auto-invoke
    /// would start an unlock while the app is hidden and consume the away epoch
    /// (`handledAwayGeneration`), suppressing the genuine foreground return.
    /// Defaults to `true` because a cold launch is foreground.
    private(set) var isForegroundActive = true

    /// Generation of lock-state transitions, used by views/tests as an
    /// `@Observable` change signal independent of equal states.
    private(set) var transitionGeneration = 0

    init(
        gracePeriodProvider: @escaping () -> Int?,
        lastAuthenticationDateProvider: @escaping () -> Date?,
        evaluateAppSessionAuthentication: @escaping (String, String) async throws -> AppSessionAuthenticationResult,
        recordSuccessfulAuthentication: @escaping (LAContext?) -> Void,
        discardHandoffContext: @escaping (String) -> Void,
        relockProtectedData: @escaping () async -> Void,
        postAuthenticationHandler: @escaping (LAContext?, String) async -> Void = { _, _ in },
        contentClearHandler: @escaping () -> Void = {},
        shouldBypassAuthentication: @escaping () -> Bool = { false },
        operationPromptInProgressProvider: (() -> Bool)? = nil,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.gracePeriodProvider = gracePeriodProvider
        self.lastAuthenticationDateProvider = lastAuthenticationDateProvider
        self.evaluateAppSessionAuthentication = evaluateAppSessionAuthentication
        self.recordSuccessfulAuthentication = recordSuccessfulAuthentication
        self.discardHandoffContext = discardHandoffContext
        self.relockProtectedData = relockProtectedData
        self.postAuthenticationHandler = postAuthenticationHandler
        self.contentClearHandler = contentClearHandler
        self.shouldBypassAuthentication = shouldBypassAuthentication
        self.operationPromptInProgressProvider = operationPromptInProgressProvider
        self.traceStore = traceStore
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
        traceStore?.record(
            category: .lifecycle,
            name: "lock.foregroundActiveChanged",
            metadata: ["active": active ? "true" : "false", "state": stateName(lockState)]
        )
    }

    /// A genuine away event for this platform: iOS/iPadOS/visionOS
    /// `ScenePhase.background`; macOS app-resign ∪ screen-lock ∪ "Lock Now".
    /// (A biometric prompt's `.inactive` is NOT routed here — see the observer.)
    func handleAwayEvent(source: String = "awayEvent") {
        #if os(macOS)
        // The `.authenticating` rule (TARGET §3): an app-resign during an
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
            traceStore?.record(
                category: .lifecycle,
                name: "lock.authenticatingRule.resignDuringUnlock",
                metadata: ["source": source]
            )
            return
        }
        // (b) A private-key operation prompt is in flight: the resign is ambiguous
        //     (the prompt's own resign vs. a genuine app switch), so the away
        //     decision is DEFERRED to the prompts' end rather than suppressed
        //     outright. `handleOperationPromptsEnded()` processes the away if the
        //     app is still not foreground-active then, and discards it if the user
        //     returned. This replaces the accepted P1-interim regression (a per-op
        //     prompt at grace=0 used to lock the app mid-operation).
        if isOperationPromptInProgressForAwayRule {
            // First resign wins: later resigns during the same prompt session carry
            // no additional information (the decision at the prompts' end depends
            // only on `isForegroundActive`), and keeping the earliest source makes
            // the trace reflect when the deferral began.
            if pendingOperationPromptAway == nil {
                pendingOperationPromptAway = source
            }
            traceStore?.record(
                category: .lifecycle,
                name: "lock.authenticatingRule.deferredOperationAway",
                metadata: ["source": source]
            )
            return
        }
        #endif

        // Any genuine away invalidates an in-flight unlock attempt.
        awayGeneration &+= 1
        discardHandoffContext("away:\(source)")

        let interval = effectiveGracePeriod()
        traceStore?.record(
            category: .lifecycle,
            name: "lock.awayEvent",
            metadata: [
                "source": source,
                "interval": String(interval),
                "lockImmediately": interval == 0 ? "true" : "false",
                "state": stateName(lockState)
            ]
        )

        // "Immediately" (interval 0) locks on the away event, literally (TARGET §3).
        // For a non-zero interval the relock is evaluated lazily on the next
        // foreground resume (grace check), matching the shipped behavior; the
        // cosmetic cover (owned by the app, not this controller) hides content
        // meanwhile.
        guard interval == 0 else {
            return
        }
        // In UI-test bypass mode the app never locks.
        guard !shouldBypassAuthentication() else {
            return
        }
        Task { await enterLocked(source: "away:\(source)") }
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
    /// and decides a deferred away (the `.authenticating` rule, TARGET §3): if a
    /// resign arrived during the prompts and the app is still not
    /// foreground-active, the away is processed now (normal grace semantics); if
    /// the user returned — or an explicit lock already superseded it — it is
    /// discarded.
    func handleOperationPromptsEnded() {
        #if os(macOS)
        if openOperationPromptSessions > 0 {
            openOperationPromptSessions -= 1
        }
        guard let source = pendingOperationPromptAway else {
            return
        }
        pendingOperationPromptAway = nil
        guard !isLockedState else {
            // An explicit lock (lockNow / screen-lock) or a processed away
            // already locked the app; the deferred decision is moot.
            traceStore?.record(
                category: .lifecycle,
                name: "lock.authenticatingRule.deferredAwaySupersededByLock",
                metadata: ["source": source]
            )
            return
        }
        guard !isForegroundActive else {
            traceStore?.record(
                category: .lifecycle,
                name: "lock.authenticatingRule.deferredAwayDiscarded",
                metadata: ["source": source]
            )
            return
        }
        traceStore?.record(
            category: .lifecycle,
            name: "lock.authenticatingRule.deferredAwayProcessed",
            metadata: ["source": source]
        )
        handleAwayEvent(source: "deferredOperationAway:\(source)")
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
    /// auto-invoke. Replaces the orchestrator's `handleResume`/`handleInitialAppearance`.
    func handleForegroundActive(source: String = "foregroundActive") async {
        traceStore?.record(
            category: .lifecycle,
            name: "lock.foregroundActive",
            metadata: ["source": source, "state": stateName(lockState)]
        )

        if shouldBypassAuthentication() {
            if isLocked {
                setLockState(.unlocked, source: "bypass:\(source)")
            }
            return
        }

        // Only a genuine foreground-active state drives an unlock. The lock surface
        // auto-invokes this on appear, and at grace=0 the surface is inserted during
        // the background lock transition — that call must be a pure no-op (no
        // `handledAwayGeneration` marking, no `runUnlockFlow`) so the away epoch is
        // not consumed and the genuine `.active` return drives auth.
        guard isForegroundActive else {
            traceStore?.record(
                category: .lifecycle,
                name: "lock.foreground.notForegroundActiveIgnored",
                metadata: ["source": source, "state": stateName(lockState)]
            )
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
            traceStore?.record(
                category: .lifecycle,
                name: "lock.foreground.spuriousIgnored",
                metadata: ["source": source, "state": stateName(lockState)]
            )
            return
        }

        switch lockState {
        case .unlocked:
            // Within the grace window a foreground round-trip stays unlocked (no
            // re-auth, content preserved) — "cover ≠ lock". Past it, re-authenticate.
            if isGracePeriodExpired {
                await runUnlockFlow(source: "graceExpired:\(source)")
            } else {
                // Genuine away, but within grace → stay unlocked and mark this epoch
                // handled so a later spurious `.active` is a no-op.
                handledAwayGeneration = awayGeneration
            }
        case .locked, .authenticationFailed:
            await runUnlockFlow(source: source)
        case .authenticating:
            break
        }
    }

    /// Re-invoke the unlock flow from the lock surface's retry affordance.
    func retryUnlock(source: String = "retry") async {
        guard !isAuthenticating else {
            return
        }
        await runUnlockFlow(source: "retry:\(source)")
    }

    /// Lock immediately regardless of the grace interval (macOS "Lock Now" / screen
    /// lock; also the seam for any future explicit-lock affordance).
    func lockNow(source: String = "lockNow") {
        #if os(macOS)
        // Clear the deferred away SYNCHRONOUSLY: the queued `enterLocked` also
        // clears it, but a prompts-ended hop could run between this call and that
        // task, and must not process the now-moot deferral into a second relock
        // cycle. An explicit lock always supersedes the deferred decision.
        pendingOperationPromptAway = nil
        #endif
        Task { await enterLocked(source: "lockNow:\(source)") }
    }

    /// Local Data Reset hook (the lock-state portion of the orchestrator's old
    /// `resetAfterLocalDataReset`). The orchestrator clears its own auth record.
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
        pendingOperationPromptAway = nil
        #endif
        discardHandoffContext("localDataReset")
        if preserveAuthentication {
            // Stay unlocked and mark this epoch handled so a post-reset spurious
            // `.active` is a no-op.
            handledAwayGeneration = awayGeneration
            setLockState(.unlocked, source: "localDataReset")
        } else {
            setLockState(.locked, source: "localDataReset")
        }
    }

    // MARK: - Unlock flow

    private func runUnlockFlow(source: String) async {
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
        setLockState(.authenticating, source: "unlock.begin:\(source)")

        // Fail-closed: clear content and relock Protected App-Data before prompting.
        contentClearHandler()
        await enterRelock(source: "unlock:\(source)")

        let reason = Self.localizedResumeReason
        traceStore?.record(
            category: .lifecycle,
            name: "lock.unlock.evaluate.start",
            metadata: ["source": source]
        )
        do {
            let result = try await evaluateAppSessionAuthentication(reason, source)
            traceStore?.record(
                category: .lifecycle,
                name: "lock.unlock.evaluate.finish",
                metadata: [
                    "source": source,
                    "result": result.isAuthenticated ? "authenticated" : "failed",
                    "hasContext": result.context == nil ? "false" : "true"
                ]
            )

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
                discardHandoffContext("staleUnlock")
                if !isLockedState {
                    setLockState(.locked, source: "unlock.stale:\(source)")
                }
                return
            }

            if result.isAuthenticated {
                recordSuccessfulAuthentication(result.context)
                await postAuthenticationHandler(result.context, source)
                // A genuine away during the post-auth fan-out: postAuthenticationHandler
                // has already REOPENED Protected App-Data, so fail closed for real —
                // relock, not just a UI state flip ("real background wins"). enterLocked
                // discards the handoff, clears content, awaits the real relock, and
                // settles `.locked`.
                guard attemptAwayGeneration == awayGeneration else {
                    traceStore?.record(
                        category: .lifecycle,
                        name: "lock.unlock.stalePostAuth",
                        metadata: ["source": source]
                    )
                    await enterLocked(source: "stalePostAuth:\(source)")
                    return
                }
                setLockState(.unlocked, source: "unlock.success:\(source)")
            } else {
                discardHandoffContext("authReturnedFalse")
                setLockState(.authenticationFailed(.authenticationFailed), source: "unlock.failed:\(source)")
            }
        } catch {
            traceStore?.record(
                category: .lifecycle,
                name: "lock.unlock.evaluate.throw",
                metadata: AuthErrorTraceMetadata.errorMetadata(error, extra: ["source": source])
            )
            discardHandoffContext("authThrew")
            guard attemptAwayGeneration == awayGeneration else {
                if !isLockedState {
                    setLockState(.locked, source: "unlock.staleThrow:\(source)")
                }
                return
            }
            setLockState(
                .authenticationFailed(Self.failureReason(for: error)),
                source: "unlock.threw:\(source)"
            )
        }
    }

    private func enterLocked(source: String) async {
        #if os(macOS)
        // An explicit lock supersedes a pending deferred away (the `.authenticating`
        // rule): the app is locking right now, so the prompts'-end decision is moot —
        // clearing it avoids a redundant second relock cycle at the prompts' end.
        pendingOperationPromptAway = nil
        #endif
        awayGeneration &+= 1
        discardHandoffContext("enterLocked:\(source)")
        contentClearHandler()
        await enterRelock(source: source)
        setLockState(.locked, source: "enterLocked:\(source)")
    }

    private func enterRelock(source: String) async {
        traceStore?.record(
            category: .lifecycle,
            name: "lock.relock.start",
            metadata: ["source": source]
        )
        await relockProtectedData()
        traceStore?.record(
            category: .lifecycle,
            name: "lock.relock.finish",
            metadata: ["source": source]
        )
    }

    // MARK: - Grace

    private func effectiveGracePeriod() -> Int {
        // Fail-closed: an unavailable settings snapshot → 0 (immediate auth), the
        // same `?? 0` semantics the orchestrator used.
        gracePeriodProvider() ?? 0
    }

    private var isGracePeriodExpired: Bool {
        guard let lastAuthenticationDate = lastAuthenticationDateProvider() else {
            return true
        }
        return Date().timeIntervalSince(lastAuthenticationDate) > TimeInterval(effectiveGracePeriod())
    }

    // MARK: - State helpers

    private var isLockedState: Bool {
        if case .locked = lockState {
            return true
        }
        return false
    }

    private func setLockState(_ newState: LockState, source: String) {
        guard newState != lockState else {
            return
        }
        let previous = lockState
        lockState = newState
        transitionGeneration &+= 1
        traceStore?.record(
            category: .lifecycle,
            name: "lock.transition",
            metadata: [
                "from": stateName(previous),
                "to": stateName(newState),
                "source": source
            ]
        )
    }

    private func stateName(_ state: LockState) -> String {
        switch state {
        case .locked:
            return "locked"
        case .authenticating:
            return "authenticating"
        case .unlocked:
            return "unlocked"
        case .authenticationFailed(let reason):
            return "authenticationFailed.\(reason.rawValue)"
        }
    }

    private static var localizedResumeReason: String {
        String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume")
    }

    /// Map an authentication error to a user-facing failure reason (moved verbatim
    /// from `AppSessionOrchestrator.authenticationFailureReason(for:)`).
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
