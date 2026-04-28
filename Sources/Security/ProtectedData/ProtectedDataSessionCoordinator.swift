import Foundation
import LocalAuthentication

struct ProtectedDataAuthorizationContextResult: @unchecked Sendable {
    let result: ProtectedDataAuthorizationResult
    let authenticationContext: LAContext
}

@Observable
final class ProtectedDataSessionCoordinator: @unchecked Sendable {
    private let rootSecretStore: any ProtectedDataRootSecretStoreProtocol
    private let legacyRightStoreClient: (any ProtectedDataRightStoreClientProtocol)?
    private let domainKeyManager: ProtectedDomainKeyManager
    private let rootSecretIdentifier: String
    private let appSessionPolicyProvider: () -> AppSessionAuthenticationPolicy
    private let recordRootSecretEnvelopeMinimumVersion: @Sendable (Int) async throws -> Void
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
        recordRootSecretEnvelopeMinimumVersion: @escaping @Sendable (Int) async throws -> Void = { _ in },
        authenticationPromptCoordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator(),
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.rootSecretStore = rootSecretStore
        self.legacyRightStoreClient = legacyRightStoreClient
        self.domainKeyManager = domainKeyManager
        self.rootSecretIdentifier = sharedRightIdentifier
        self.appSessionPolicyProvider = appSessionPolicyProvider
        self.recordRootSecretEnvelopeMinimumVersion = recordRootSecretEnvelopeMinimumVersion
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.traceStore = traceStore
    }

    func persistSharedRight(secretData: Data) async throws {
        let policy = appSessionPolicyProvider()
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.save.start",
            metadata: ["policy": policy.rawValue]
        )
        do {
            try rootSecretStore.saveRootSecret(
                secretData,
                identifier: rootSecretIdentifier,
                policy: policy
            )
            try await recordRootSecretEnvelopeMinimumVersion(
                ProtectedDataRootSecretEnvelope.currentFormatVersion
            )
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.save.finish",
                metadata: ["result": "success", "policy": policy.rawValue]
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.save.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "failed", "policy": policy.rawValue])
            )
            throw error
        }
    }

    func removePersistedSharedRight(identifier: String) async throws {
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.delete.start"
        )
        do {
            try rootSecretStore.deleteRootSecret(identifier: identifier)
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.delete.finish",
                metadata: ["result": "success"]
            )
        } catch let error as KeychainError where error == .itemNotFound {
            // Deleting the last protected domain can run against legacy or already
            // cleaned-up state. Missing root secret is not a recovery failure here.
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.delete.finish",
                metadata: ["result": "missing"]
            )
        }
        if let legacyRightStoreClient {
            try? await legacyRightStoreClient.removeRight(forIdentifier: identifier)
        }
        clearSessionSecrets()
        frameworkState = .sessionLocked
    }

    func beginProtectedDataAuthorization(
        registry: ProtectedDataRegistry,
        localizedReason: String,
        authenticationContext: LAContext? = nil,
        allowLegacyMigration: Bool = true
    ) async -> ProtectedDataAuthorizationResult {
        let context = authenticationContext ?? makeRootSecretAuthenticationContext(
            localizedReason: localizedReason
        )
        return await authorizeProtectedDataSession(
            registry: registry,
            localizedReason: localizedReason,
            context: context,
            usesHandoffContext: authenticationContext != nil,
            allowLegacyMigration: allowLegacyMigration
        )
    }

    func beginProtectedDataAuthorizationReturningContext(
        registry: ProtectedDataRegistry,
        localizedReason: String,
        authenticationContext: LAContext? = nil,
        allowLegacyMigration: Bool = true
    ) async -> ProtectedDataAuthorizationContextResult {
        let context = authenticationContext ?? makeRootSecretAuthenticationContext(
            localizedReason: localizedReason
        )
        let result = await authorizeProtectedDataSession(
            registry: registry,
            localizedReason: localizedReason,
            context: context,
            usesHandoffContext: authenticationContext != nil,
            allowLegacyMigration: allowLegacyMigration
        )
        return ProtectedDataAuthorizationContextResult(
            result: result,
            authenticationContext: context
        )
    }

    private func authorizeProtectedDataSession(
        registry: ProtectedDataRegistry,
        localizedReason: String,
        context: LAContext,
        usesHandoffContext: Bool,
        allowLegacyMigration: Bool
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
            var rootSecretResult: ProtectedDataRootSecretLoadResult
            do {
                rootSecretResult = try await loadRootSecret(
                    identifier: registry.sharedRightIdentifier,
                    authenticationContext: context,
                    usesHandoffContext: usesHandoffContext,
                    minimumEnvelopeVersion: registry.rootSecretEnvelopeMinimumVersion
                )
            } catch let error as KeychainError where error == .itemNotFound {
                guard allowLegacyMigration else {
                    clearSessionSecrets()
                    traceStore?.record(
                        category: .operation,
                        name: "protectedSettings.authorization.finish",
                        metadata: ["result": "cancelledOrDenied", "reason": "legacyMigrationDeferred"]
                    )
                    return .cancelledOrDenied
                }
                rootSecretResult = try await migrateLegacySharedRightIfNeeded(
                    registry: registry,
                    localizedReason: localizedReason,
                    authenticationContext: context,
                    usesHandoffContext: usesHandoffContext
                )
            }
            defer {
                rootSecretResult.secretData.protectedDataZeroize()
            }

            if rootSecretResult.storageFormat == .envelopeV2 || rootSecretResult.didMigrate {
                try await recordRootSecretEnvelopeMinimumVersion(
                    ProtectedDataRootSecretEnvelope.currentFormatVersion
                )
            }
            let derivedWrappingRootKey = try domainKeyManager.deriveWrappingRootKey(
                from: &rootSecretResult.secretData
            )

            clearSessionSecrets()
            wrappingRootKey = derivedWrappingRootKey
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
        rootSecretStore.rootSecretExists(identifier: identifier ?? rootSecretIdentifier)
    }

    @discardableResult
    func reprotectPersistedRootSecretIfPresent(
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext?
    ) throws -> Bool {
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.reprotect.start",
            metadata: [
                "currentPolicy": currentPolicy.rawValue,
                "newPolicy": newPolicy.rawValue,
                "hasContext": authenticationContext == nil ? "false" : "true"
            ]
        )
        guard rootSecretStore.rootSecretExists(identifier: rootSecretIdentifier) else {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.reprotect.finish",
                metadata: ["result": "missing", "newPolicy": newPolicy.rawValue]
            )
            return false
        }
        guard let authenticationContext else {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.reprotect.finish",
                metadata: ["result": "missingContext", "newPolicy": newPolicy.rawValue]
            )
            throw ProtectedDataError.authorizingUnavailable
        }
        authenticationContext.interactionNotAllowed = true

        do {
            try rootSecretStore.reprotectRootSecret(
                identifier: rootSecretIdentifier,
                from: currentPolicy,
                to: newPolicy,
                authenticationContext: authenticationContext
            )
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.reprotect.finish",
                metadata: [
                    "result": "success",
                    "newPolicy": newPolicy.rawValue,
                    "interactionNotAllowed": authenticationContext.interactionNotAllowed ? "true" : "false"
                ]
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.reprotect.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "failed", "newPolicy": newPolicy.rawValue])
            )
            throw error
        }
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
        if wrappingRootKey != nil {
            wrappingRootKey?.protectedDataZeroize()
            wrappingRootKey = nil
        }
        domainKeyManager.clearUnlockedDomainMasterKeys()
    }

    var hasActiveWrappingRootKey: Bool {
        wrappingRootKey != nil
    }

    private func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext,
        usesHandoffContext: Bool,
        minimumEnvelopeVersion: Int?
    ) async throws -> ProtectedDataRootSecretLoadResult {
        let metadata = [
            "source": usesHandoffContext ? "handoff" : "interactive",
            "interactionNotAllowed": authenticationContext.interactionNotAllowed ? "true" : "false",
            "minimumEnvelopeVersion": minimumEnvelopeVersion.map(String.init) ?? "none"
        ]
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.load.start",
            metadata: metadata
        )
        if usesHandoffContext {
            do {
                let secret = try rootSecretStore.loadRootSecret(
                    identifier: identifier,
                    authenticationContext: authenticationContext,
                    minimumEnvelopeVersion: minimumEnvelopeVersion
                )
                traceStore?.record(
                    category: .operation,
                    name: "protectedData.rootSecret.load.finish",
                    metadata: metadata.merging(
                        [
                            "result": "success",
                            "storageFormat": secret.storageFormat.rawValue,
                            "didMigrate": secret.didMigrate ? "true" : "false"
                        ],
                        uniquingKeysWith: { _, new in new }
                    )
                )
                return secret
            } catch {
                traceStore?.record(
                    category: .operation,
                    name: "protectedData.rootSecret.load.finish",
                    metadata: traceErrorMetadata(error, extra: metadata.merging(["result": "failed"], uniquingKeysWith: { _, new in new }))
                )
                throw error
            }
        }

        do {
            let secret = try await authenticationPromptCoordinator.withOperationPrompt(
                source: "protectedData.rootSecret.load.interactive"
            ) {
                try rootSecretStore.loadRootSecret(
                    identifier: identifier,
                    authenticationContext: authenticationContext,
                    minimumEnvelopeVersion: minimumEnvelopeVersion
                )
            }
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.load.finish",
                metadata: metadata.merging(
                    [
                        "result": "success",
                        "storageFormat": secret.storageFormat.rawValue,
                        "didMigrate": secret.didMigrate ? "true" : "false"
                    ],
                    uniquingKeysWith: { _, new in new }
                )
            )
            return secret
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.load.finish",
                metadata: traceErrorMetadata(error, extra: metadata.merging(["result": "failed"], uniquingKeysWith: { _, new in new }))
            )
            throw error
        }
    }

    private func migrateLegacySharedRightIfNeeded(
        registry: ProtectedDataRegistry,
        localizedReason: String,
        authenticationContext: LAContext,
        usesHandoffContext: Bool
    ) async throws -> ProtectedDataRootSecretLoadResult {
        guard let legacyRightStoreClient else {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.legacyMigration.finish",
                metadata: ["result": "missingLegacySource"]
            )
            throw KeychainError.itemNotFound
        }

        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.legacyMigration.start",
            metadata: [
                "source": usesHandoffContext ? "handoff" : "interactive",
                "policy": appSessionPolicyProvider().rawValue
            ]
        )
        let legacyRight: any ProtectedDataPersistedRightHandle
        do {
            legacyRight = try await legacyRightStoreClient.right(
                forIdentifier: registry.sharedRightIdentifier
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.legacyMigration.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "failed", "step": "loadLegacyRight"])
            )
            throw error
        }
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.legacyAuthorize.start"
        )
        do {
            try await authenticationPromptCoordinator.withOperationPrompt(source: "protectedData.legacyAuthorize") {
                try await legacyRight.authorize(localizedReason: localizedReason)
            }
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.legacyAuthorize.finish",
                metadata: ["result": "success"]
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.legacyAuthorize.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "failed"])
            )
            throw error
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

            var verifiedResult = try await loadRootSecret(
                identifier: registry.sharedRightIdentifier,
                authenticationContext: authenticationContext,
                usesHandoffContext: usesHandoffContext,
                minimumEnvelopeVersion: registry.rootSecretEnvelopeMinimumVersion
            )
            guard verifiedResult.secretData == legacySecret else {
                verifiedResult.secretData.protectedDataZeroize()
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
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.legacyMigration.finish",
                metadata: ["result": "success"]
            )
            return verifiedResult
        } catch {
            await legacyRight.deauthorize()
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.legacyMigration.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "failed"])
            )
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

    private func traceErrorMetadata(
        _ error: Error,
        extra: [String: String] = [:]
    ) -> [String: String] {
        var metadata = extra
        metadata["errorType"] = String(describing: type(of: error))
        if let keychainError = error as? KeychainError {
            metadata["keychainError"] = String(describing: keychainError)
        }
        if let laError = error as? LAError {
            metadata["laCode"] = String(laError.errorCode)
            metadata["laCodeName"] = String(describing: laError.code)
        }
        return metadata
    }
}
