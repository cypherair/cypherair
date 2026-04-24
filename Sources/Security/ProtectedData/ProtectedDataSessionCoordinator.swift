import Foundation
import LocalAuthentication

@Observable
final class ProtectedDataSessionCoordinator {
    private let rootSecretStore: any ProtectedDataRootSecretStoreProtocol
    private let legacyRightStoreClient: (any ProtectedDataRightStoreClientProtocol)?
    private let domainKeyManager: ProtectedDomainKeyManager
    private let rootSecretIdentifier: String
    private let appSessionPolicyProvider: () -> AppSessionAuthenticationPolicy
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let traceStore: AuthLifecycleTraceStore?

    private var wrappingRootKey: Data?
    private var relockParticipants: [any ProtectedDataRelockParticipant] = []

    private(set) var frameworkState: ProtectedDataFrameworkState = .sessionLocked

    init(
        rootSecretStore: any ProtectedDataRootSecretStoreProtocol = KeychainProtectedDataRootSecretStore(),
        legacyRightStoreClient: (any ProtectedDataRightStoreClientProtocol)? = nil,
        domainKeyManager: ProtectedDomainKeyManager,
        sharedRightIdentifier: String,
        appSessionPolicyProvider: @escaping () -> AppSessionAuthenticationPolicy = { .userPresence },
        authenticationPromptCoordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator(),
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.rootSecretStore = rootSecretStore
        self.legacyRightStoreClient = legacyRightStoreClient
        self.domainKeyManager = domainKeyManager
        self.rootSecretIdentifier = sharedRightIdentifier
        self.appSessionPolicyProvider = appSessionPolicyProvider
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.traceStore = traceStore
    }

    func persistSharedRight(secretData: Data) async throws {
        try rootSecretStore.saveRootSecret(
            secretData,
            identifier: rootSecretIdentifier,
            policy: appSessionPolicyProvider()
        )
    }

    func removePersistedSharedRight(identifier: String) async throws {
        do {
            try rootSecretStore.deleteRootSecret(identifier: identifier)
        } catch let error as KeychainError where error == .itemNotFound {
            // Deleting the last protected domain can run against legacy or already
            // cleaned-up state. Missing root secret is not a recovery failure here.
        }
        if let legacyRightStoreClient {
            try? await legacyRightStoreClient.removeRight(forIdentifier: identifier)
        }
        if wrappingRootKey != nil {
            wrappingRootKey?.protectedDataZeroize()
            wrappingRootKey = nil
        }
        frameworkState = .sessionLocked
    }

    func beginProtectedDataAuthorization(
        registry: ProtectedDataRegistry,
        localizedReason: String,
        authenticationContext: LAContext? = nil
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

        let context = authenticationContext ?? makeRootSecretAuthenticationContext(
            localizedReason: localizedReason
        )
        let usesHandoffContext = authenticationContext != nil
        if usesHandoffContext {
            context.interactionNotAllowed = true
        }

        do {
            var rawSecret: Data
            do {
                rawSecret = try await loadRootSecret(
                    identifier: registry.sharedRightIdentifier,
                    authenticationContext: context,
                    usesHandoffContext: usesHandoffContext
                )
            } catch let error as KeychainError where error == .itemNotFound {
                rawSecret = try await migrateLegacySharedRightIfNeeded(
                    registry: registry,
                    localizedReason: localizedReason,
                    authenticationContext: context,
                    usesHandoffContext: usesHandoffContext
                )
            }

            let derivedWrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rawSecret)

            if wrappingRootKey != nil {
                wrappingRootKey?.protectedDataZeroize()
            }
            wrappingRootKey = derivedWrappingRootKey
            frameworkState = .sessionAuthorized
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "authorized"]
            )
            return .authorized
        } catch {
            if wrappingRootKey != nil {
                wrappingRootKey?.protectedDataZeroize()
                wrappingRootKey = nil
            }
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
        rootSecretStore.rootSecretExists(identifier: identifier ?? rootSecretIdentifier)
    }

    @discardableResult
    func reprotectPersistedRootSecretIfPresent(
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext?
    ) throws -> Bool {
        guard rootSecretStore.rootSecretExists(identifier: rootSecretIdentifier) else {
            return false
        }
        guard let authenticationContext else {
            throw ProtectedDataError.authorizingUnavailable
        }
        authenticationContext.interactionNotAllowed = true

        try rootSecretStore.reprotectRootSecret(
            identifier: rootSecretIdentifier,
            from: currentPolicy,
            to: newPolicy,
            authenticationContext: authenticationContext
        )
        return true
    }

    func authorizeSharedRight(localizedReason: String) async throws {
        if frameworkState == .sessionAuthorized {
            return
        }
        throw ProtectedDataError.authorizingUnavailable
    }

    func wrappingRootKeyData() throws -> Data {
        guard let wrappingRootKey else {
            throw ProtectedDataError.missingWrappingRootKey
        }
        return wrappingRootKey
    }

    func registerRelockParticipant(_ participant: any ProtectedDataRelockParticipant) {
        guard !relockParticipants.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(participant) }) else {
            return
        }

        relockParticipants.append(participant)
    }

    func relockCurrentSession() async {
        guard frameworkState != .restartRequired else {
            return
        }

        var participantErrorOccurred = false
        for participant in relockParticipants {
            do {
                try await participant.relockProtectedData()
            } catch {
                participantErrorOccurred = true
            }
        }

        if wrappingRootKey != nil {
            wrappingRootKey?.protectedDataZeroize()
            wrappingRootKey = nil
        }
        domainKeyManager.clearUnlockedDomainMasterKeys()

        frameworkState = participantErrorOccurred ? .restartRequired : .sessionLocked
    }

    var hasActiveWrappingRootKey: Bool {
        wrappingRootKey != nil
    }

    private func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext,
        usesHandoffContext: Bool
    ) async throws -> Data {
        if usesHandoffContext {
            return try rootSecretStore.loadRootSecret(
                identifier: identifier,
                authenticationContext: authenticationContext
            )
        }

        return try await authenticationPromptCoordinator.withOperationPrompt {
            try rootSecretStore.loadRootSecret(
                identifier: identifier,
                authenticationContext: authenticationContext
            )
        }
    }

    private func migrateLegacySharedRightIfNeeded(
        registry: ProtectedDataRegistry,
        localizedReason: String,
        authenticationContext: LAContext,
        usesHandoffContext: Bool
    ) async throws -> Data {
        guard let legacyRightStoreClient else {
            throw KeychainError.itemNotFound
        }

        let legacyRight = try await legacyRightStoreClient.right(
            forIdentifier: registry.sharedRightIdentifier
        )
        try await authenticationPromptCoordinator.withOperationPrompt {
            try await legacyRight.authorize(localizedReason: localizedReason)
        }

        do {
            var legacySecret = try await legacyRight.rawSecretData()
            defer {
                legacySecret.protectedDataZeroize()
            }

            try rootSecretStore.saveRootSecret(
                legacySecret,
                identifier: registry.sharedRightIdentifier,
                policy: appSessionPolicyProvider()
            )

            var verifiedSecret = try await loadRootSecret(
                identifier: registry.sharedRightIdentifier,
                authenticationContext: authenticationContext,
                usesHandoffContext: usesHandoffContext
            )
            guard verifiedSecret == legacySecret else {
                verifiedSecret.protectedDataZeroize()
                throw ProtectedDataError.internalFailure(
                    String(
                        localized: "error.protectedData.rootSecretMigrationVerification",
                        defaultValue: "The protected app data root secret could not be verified after migration."
                    )
                )
            }

            do {
                try await legacyRightStoreClient.removeRight(forIdentifier: registry.sharedRightIdentifier)
            } catch {
                traceStore?.record(
                    category: .operation,
                    name: "protectedSettings.authorization.legacyCleanupFailed",
                    metadata: ["errorType": String(describing: type(of: error))]
                )
            }

            await legacyRight.deauthorize()
            return verifiedSecret
        } catch {
            await legacyRight.deauthorize()
            throw error
        }
    }

    private func makeRootSecretAuthenticationContext(localizedReason: String) -> LAContext {
        let context = LAContext()
        let policy = appSessionPolicyProvider()
        policy.configure(context)
        context.localizedReason = localizedReason
        return context
    }

    private func isAuthorizationCancellationOrDenial(_ error: Error) -> Bool {
        if let keychainError = error as? KeychainError {
            switch keychainError {
            case .userCancelled, .authenticationFailed, .interactionNotAllowed:
                return true
            case .itemNotFound, .duplicateItem, .unhandledError:
                return false
            }
        }

        if let authenticationError = error as? AuthenticationError {
            switch authenticationError {
            case .cancelled, .failed, .biometricsUnavailable, .appAccessBiometricsUnavailable:
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
