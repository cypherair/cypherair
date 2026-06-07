import Foundation
import LocalAuthentication

/// The single source of truth for the app lock state (P1 of the auth-lifecycle
/// redesign — see docs/AUTH_LIFECYCLE_REDESIGN_TARGET_DESIGN.md §2/§3).
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
    private let traceStore: AuthLifecycleTraceStore?

    private(set) var lockState: LockState = .locked

    /// True while this controller is driving an app-session authentication it is
    /// awaiting. The macOS detached system auth sheet resigns the app; this guard
    /// makes `handleAwayEvent` ignore that self-induced resign (P1 interim, until
    /// P3 moves macOS auth in-window — see ROADMAP §6 "macOS delivery coupling").
    /// This is an explicit flag keyed off the controller's own in-flight unlock —
    /// NOT the deleted prompt-coordinator/settle disambiguation.
    private var isDrivingAppSessionAuth = false

    /// Monotonic token bumped on every genuine away event. The unlock flow captures
    /// it before the auth `await` and bails if it changed — i.e. the app genuinely
    /// left the foreground mid-authentication, so the just-produced context must be
    /// discarded and not handed off ("real background wins").
    private var awayGeneration = 0

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

    /// A genuine away event for this platform: iOS/iPadOS/visionOS
    /// `ScenePhase.background`; macOS app-resign ∪ screen-lock ∪ "Lock Now".
    /// (A biometric prompt's `.inactive` is NOT routed here — see the observer.)
    func handleAwayEvent(source: String = "awayEvent") {
        #if os(macOS)
        // The macOS detached system auth sheet resigns the app while THIS
        // controller is driving an app-session unlock. Ignore that self-induced
        // resign so the unlock can complete. (Per-operation private-key prompts are
        // not driven here and therefore regress in the P1 interim — accepted; macOS
        // is not shipped until P3 moves auth in-window.)
        if isDrivingAppSessionAuth {
            traceStore?.record(
                category: .lifecycle,
                name: "lock.inFlightGuard.suppressedAway",
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

        // An unlock is already in flight; do not start a second one (the
        // check-then-set is atomic under @MainActor up to the first `await` in
        // `runUnlockFlow`).
        guard !isAuthenticating else {
            return
        }

        switch lockState {
        case .unlocked:
            // Within the grace window a foreground round-trip stays unlocked (no
            // re-auth, content preserved) — "cover ≠ lock". Past it, re-authenticate.
            if isGracePeriodExpired {
                await runUnlockFlow(source: "graceExpired:\(source)")
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
        Task { await enterLocked(source: "lockNow:\(source)") }
    }

    /// Local Data Reset hook (the lock-state portion of the orchestrator's old
    /// `resetAfterLocalDataReset`). The orchestrator clears its own auth record.
    func resetAfterLocalDataReset(preserveAuthentication: Bool = false) {
        awayGeneration &+= 1
        isDrivingAppSessionAuth = false
        discardHandoffContext("localDataReset")
        setLockState(preserveAuthentication ? .unlocked : .locked, source: "localDataReset")
    }

    // MARK: - Unlock flow

    private func runUnlockFlow(source: String) async {
        // Mark the attempt in flight synchronously, BEFORE the first `await`, so a
        // second resume observes `.authenticating` at the `handleForegroundActive`
        // guard and cannot start a duplicate prompt.
        isDrivingAppSessionAuth = true
        let attemptAwayGeneration = awayGeneration
        setLockState(.authenticating, source: "unlock.begin:\(source)")
        defer { isDrivingAppSessionAuth = false }

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
            // self-induced resign is suppressed above, so this only fires for a real
            // iOS `.background`.
            guard attemptAwayGeneration == awayGeneration else {
                discardHandoffContext("staleUnlock")
                if !isLockedState {
                    setLockState(.locked, source: "unlock.stale:\(source)")
                }
                return
            }

            if result.isAuthenticated {
                recordSuccessfulAuthentication(result.context)
                await postAuthenticationHandler(result.context, source)
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
