import Foundation
import LocalAuthentication
import os

struct ProtectedDataAuthorizationContextResult: @unchecked Sendable {
    let result: ProtectedDataAuthorizationResult
    let authenticationContext: LAContext
}

@Observable
final class ProtectedDataSessionCoordinator: @unchecked Sendable {
    private let domainKeyManager: ProtectedDomainKeyManager
    private let appSessionPolicyProvider: () -> AppSessionAuthenticationPolicy
    private let traceStore: AuthLifecycleTraceStore?
    private let rootSecretCoordinator: ProtectedDataRootSecretCoordinator

    /// Session wrapping root key, guarded by an unfair lock (issue #610) —
    /// same rationale as `ProtectedDomainKeyManager.unlockedDomainMasterKeys`:
    /// synchronized by construction rather than by main-thread convention.
    private let wrappingRootKeyLock = OSAllocatedUnfairLock<Data?>(initialState: nil)
    private let relockCoordinator = ProtectedDataSessionRelockCoordinator()

    private(set) var frameworkState: ProtectedDataFrameworkState = .sessionLocked

    init(
        rootSecretStore: any ProtectedDataRootSecretStoreProtocol,
        domainKeyManager: ProtectedDomainKeyManager,
        sharedRightIdentifier: String,
        appSessionPolicyProvider: @escaping () -> AppSessionAuthenticationPolicy = { .userPresence },
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.domainKeyManager = domainKeyManager
        self.appSessionPolicyProvider = appSessionPolicyProvider
        self.traceStore = traceStore
        self.rootSecretCoordinator = ProtectedDataRootSecretCoordinator(
            rootSecretStore: rootSecretStore,
            rootSecretIdentifier: sharedRightIdentifier,
            appSessionPolicyProvider: appSessionPolicyProvider,
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            traceStore: traceStore
        )
    }

    func persistSharedRight(secretData: Data) async throws {
        try await rootSecretCoordinator.persistSharedRight(secretData: secretData)
    }

    func removePersistedSharedRight(identifier: String) async throws {
        try await rootSecretCoordinator.removePersistedSharedRight(identifier: identifier)
        clearSessionSecrets()
        frameworkState = .sessionLocked
    }

    func beginProtectedDataAuthorization(
        registry: ProtectedDataRegistry,
        localizedReason: String,
        authenticationContext: LAContext? = nil
    ) async -> ProtectedDataAuthorizationResult {
        let context = authenticationContext ?? makeRootSecretAuthenticationContext(
            localizedReason: localizedReason
        )
        return await authorizeProtectedDataSession(
            registry: registry,
            context: context,
            usesHandoffContext: authenticationContext != nil
        )
    }

    func beginProtectedDataAuthorizationReturningContext(
        registry: ProtectedDataRegistry,
        localizedReason: String,
        authenticationContext: LAContext? = nil
    ) async -> ProtectedDataAuthorizationContextResult {
        let context = authenticationContext ?? makeRootSecretAuthenticationContext(
            localizedReason: localizedReason
        )
        let result = await authorizeProtectedDataSession(
            registry: registry,
            context: context,
            usesHandoffContext: authenticationContext != nil
        )
        return ProtectedDataAuthorizationContextResult(
            result: result,
            authenticationContext: context
        )
    }

    private func authorizeProtectedDataSession(
        registry: ProtectedDataRegistry,
        context: LAContext,
        usesHandoffContext: Bool
    ) async -> ProtectedDataAuthorizationResult {
        traceStore?.record(
            category: .operation,
            name: "protectedSettings.authorization.start",
            metadata: [
                "frameworkState": String(describing: frameworkState),
                "sharedResourceState": registry.sharedResourceLifecycleState.rawValue
            ]
        )
        if frameworkState == .restartRequired {
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "frameworkRecoveryNeeded", "reason": "restartRequired"]
            )
            return .frameworkRecoveryNeeded
        }

        guard registry.sharedResourceLifecycleState == .ready else {
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "frameworkRecoveryNeeded", "reason": "sharedResourceNotReady"]
            )
            return .frameworkRecoveryNeeded
        }

        if usesHandoffContext {
            context.interactionNotAllowed = true
        }
        traceStore?.record(
            category: .operation,
            name: "protectedSettings.authorization.context",
            metadata: [
                "source": usesHandoffContext ? "handoff" : "interactive",
                "interactionNotAllowed": context.interactionNotAllowed ? "true" : "false",
                "policy": appSessionPolicyProvider().rawValue
            ]
        )

        do {
            var rootSecret = try await rootSecretCoordinator.loadRootSecretForAuthorization(
                registry: registry,
                authenticationContext: context,
                usesHandoffContext: usesHandoffContext
            )
            defer {
                rootSecret.protectedDataZeroize()
            }

            let derivedWrappingRootKey = try domainKeyManager.deriveWrappingRootKey(
                from: &rootSecret
            )

            clearSessionSecrets()
            wrappingRootKeyLock.withLock { $0 = derivedWrappingRootKey }
            frameworkState = .sessionAuthorized
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "authorized"]
            )
            return .authorized
        } catch {
            clearSessionSecrets()
            if isAuthorizationCancellationOrDenial(error) {
                traceStore?.record(
                    category: .operation,
                    name: "protectedSettings.authorization.finish",
                    metadata: ["result": "cancelledOrDenied", "reason": "rootSecretAccessDenied"]
                )
                return .cancelledOrDenied
            }

            frameworkState = .frameworkRecoveryNeeded
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "frameworkRecoveryNeeded", "reason": "secretReadFailed"]
            )
            return .frameworkRecoveryNeeded
        }
    }

    func hasPersistedRootSecret(identifier: String? = nil) -> Bool {
        rootSecretCoordinator.hasPersistedRootSecret(identifier: identifier)
    }

    @discardableResult
    func reprotectPersistedRootSecretIfPresent(
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext?
    ) throws -> Bool {
        try rootSecretCoordinator.reprotectPersistedRootSecretIfPresent(
            from: currentPolicy,
            to: newPolicy,
            authenticationContext: authenticationContext
        )
    }

    func authorizeSharedRight(localizedReason: String) async throws {
        if frameworkState == .sessionAuthorized {
            return
        }
        throw ProtectedDataError.authorizingUnavailable
    }

    func wrappingRootKeyData() throws -> Data {
        try wrappingRootKeyLock.withLock { key in
            guard let key else {
                throw ProtectedDataError.missingWrappingRootKey
            }
            return key
        }
    }

    func registerRelockParticipant(_ participant: any ProtectedDataRelockParticipant) {
        relockCoordinator.register(participant)
    }

    func relockCurrentSession() async {
        guard frameworkState != .restartRequired else {
            return
        }

        let participantErrorOccurred = await relockCoordinator.relockParticipants()
        clearSessionSecrets()

        frameworkState = participantErrorOccurred ? .restartRequired : .sessionLocked
    }

    func resetAfterLocalDataReset() {
        clearSessionSecrets()
        frameworkState = .sessionLocked
        traceStore?.record(
            category: .session,
            name: "protectedData.session.localDataReset",
            metadata: ["frameworkState": String(describing: frameworkState)]
        )
    }

    private func clearSessionSecrets() {
        wrappingRootKeyLock.withLock { key in
            if key != nil {
                key?.protectedDataZeroize()
                key = nil
            }
        }
        domainKeyManager.clearUnlockedDomainMasterKeys()
    }

    var hasActiveWrappingRootKey: Bool {
        wrappingRootKeyLock.withLock { $0 != nil }
    }

    private func makeRootSecretAuthenticationContext(localizedReason: String) -> LAContext {
        let context = LAContext()
        let policy = appSessionPolicyProvider()
        policy.configure(context)
        context.localizedReason = localizedReason
        return context
    }

    private func isAuthorizationCancellationOrDenial(_ error: Error) -> Bool {
        if KeychainFailureClassifier.isAuthorizationCancellationOrDenial(error) {
            return true
        }

        if let authenticationError = error as? AuthenticationError {
            switch authenticationError {
            case .cancelled,
                 .failed,
                 .biometricsUnavailable,
                 .appAccessBiometricsUnavailable,
                 .appAccessBiometricsLockedOut:
                return true
            case .accessControlCreationFailed, .modeSwitchFailed, .noIdentities, .backupRequired:
                return false
            }
        }

        if let laError = error as? LAError {
            switch laError.code {
            case .userCancel, .appCancel, .systemCancel, .authenticationFailed, .notInteractive:
                return true
            default:
                return false
            }
        }

        return false
    }
}
