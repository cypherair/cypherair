import Foundation
import LocalAuthentication

/// App-session authentication concerns for Protected App-Data. The lock state
/// machine — lock state, cover, grace, away/foreground bookkeeping — lives in
/// `AppLockController`. This type owns the app-session-authentication concerns:
///
/// - **Authenticated-`LAContext` handoff custody.** It stores the context a
///   successful app-session unlock produced and hands it to `CypherAirApp` exactly
///   once to authorize Protected App-Data. `AppLockController` drives the unlock
///   and calls `recordSuccessfulAppSessionAuthentication(context:)` on success; it
///   discards the context (fail-closed) on every away/relock/failure path. The
///   context is produced by app-session `evaluatePolicy` and is **never** routed
///   into a private-key operation.
/// - **`lastAuthenticationDate`** — the grace clock the controller reads.
/// - **`contentClearGeneration`** — the relock signal App views observe (via
///   `.onChange`) to clear decrypted content. `requestContentClear()` bumps it.
/// - **Local Data Reset hook** and the **Protected App-Data access gate**.
@Observable
@MainActor
final class AppSessionOrchestrator {
    private let protectedDataAccessGateClassifier: ProtectedDataAccessGateClassifier
    private let traceStore: AuthLifecycleTraceStore?

    private var pendingAuthenticatedContext: LAContext?
    private(set) var contentClearGeneration = 0
    private(set) var postAuthenticationGeneration = 0
    private(set) var lastAuthenticationDate: Date?

    init(
        currentRegistryProvider: @escaping () throws -> ProtectedDataRegistry,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.protectedDataAccessGateClassifier = ProtectedDataAccessGateClassifier(
            currentRegistryProvider: currentRegistryProvider,
            frameworkStateProvider: {
                protectedDataSessionCoordinator.frameworkState
            }
        )
        self.traceStore = traceStore
    }

    // MARK: - App-session authentication record

    func recordAuthentication() {
        lastAuthenticationDate = Date()
        traceStore?.record(
            category: .session,
            name: "session.recordAuthentication",
            metadata: ["hasPendingContext": pendingAuthenticatedContext == nil ? "false" : "true"]
        )
    }

    /// Store the handoff context a successful app-session unlock produced and record
    /// the authentication. Called by `AppLockController` on a successful unlock
    /// (the orchestrator is the handoff-context custodian).
    func recordSuccessfulAppSessionAuthentication(context: LAContext?) {
        replacePendingAuthenticatedContext(with: context, reason: "unlockHandoff")
        recordAuthentication()
    }

    /// Bump the post-authentication generation App views observe (via `.onChange`)
    /// to refresh after the post-unlock domain-open fan-out completes. Called from
    /// the controller's post-authentication handler.
    func recordPostAuthenticationCompletion() {
        postAuthenticationGeneration += 1
        traceStore?.record(
            category: .session,
            name: "session.postAuthentication.complete",
            metadata: ["generation": String(postAuthenticationGeneration)]
        )
    }

    // MARK: - Content clear (the view-observed relock signal)

    /// Discard the handoff context and bump the content-clear generation App views
    /// observe to clear decrypted content on relock. The settings relock is
    /// performed by the caller (the controller's content-clear closure).
    func requestContentClear() {
        discardPendingAuthenticatedContext(reason: "contentClear")
        contentClearGeneration += 1
        traceStore?.record(
            category: .session,
            name: "session.requestContentClear",
            metadata: ["generation": String(contentClearGeneration)]
        )
    }

    func resetAfterLocalDataReset(preserveAuthentication: Bool = false) {
        discardPendingAuthenticatedContext(reason: "localDataReset")
        lastAuthenticationDate = preserveAuthentication ? Date() : nil
        contentClearGeneration += 1
        traceStore?.record(
            category: .session,
            name: "session.localDataReset",
            metadata: [
                "contentClearGeneration": String(contentClearGeneration),
                "preservedAuthentication": preserveAuthentication ? "true" : "false"
            ]
        )
    }

    // MARK: - Authenticated-context handoff custody

    var hasProtectedDataAuthorizationHandoffContext: Bool {
        pendingAuthenticatedContext != nil
    }

    func discardProtectedDataAuthorizationHandoffContextForPolicyChange() {
        discardAuthorizationHandoffContext(reason: "appAccessPolicyChange")
    }

    /// Discard the pending handoff context (fail-closed). Used by the controller's
    /// away / relock / failure paths.
    func discardAuthorizationHandoffContext(reason: String) {
        discardPendingAuthenticatedContext(reason: reason)
    }

    func consumeAuthenticatedContextForProtectedData() -> LAContext? {
        let context = pendingAuthenticatedContext
        pendingAuthenticatedContext = nil
        traceStore?.record(
            category: .session,
            name: "session.consumeAuthenticatedContext",
            metadata: [
                "hadContext": context == nil ? "false" : "true",
                "remainingContext": pendingAuthenticatedContext == nil ? "false" : "true"
            ]
        )
        return context
    }

    // MARK: - Protected App-Data access gate

    func evaluateProtectedDataAccessGate(
        startupBootstrapOutcome: ProtectedDataBootstrapOutcome,
        isFirstProtectedAccessInCurrentProcess: Bool
    ) -> ProtectedDataAccessGateDecision {
        protectedDataAccessGateClassifier.evaluate(
            startupBootstrapOutcome: startupBootstrapOutcome,
            isFirstProtectedAccessInCurrentProcess: isFirstProtectedAccessInCurrentProcess
        )
    }

    // MARK: - Private helpers

    private func replacePendingAuthenticatedContext(with context: LAContext?, reason: String) {
        let hadExistingContext = pendingAuthenticatedContext != nil
        pendingAuthenticatedContext?.invalidate()
        pendingAuthenticatedContext = context
        traceStore?.record(
            category: .session,
            name: "session.pendingContext.store",
            metadata: [
                "reason": reason,
                "hasContext": context == nil ? "false" : "true",
                "replacedExisting": hadExistingContext ? "true" : "false"
            ]
        )
    }

    private func discardPendingAuthenticatedContext(reason: String) {
        let hadContext = pendingAuthenticatedContext != nil
        pendingAuthenticatedContext?.invalidate()
        pendingAuthenticatedContext = nil
        traceStore?.record(
            category: .session,
            name: "session.pendingContext.discard",
            metadata: ["reason": reason, "hadContext": hadContext ? "true" : "false"]
        )
    }
}
