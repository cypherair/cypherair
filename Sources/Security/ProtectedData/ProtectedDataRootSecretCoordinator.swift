import Foundation
import LocalAuthentication

final class ProtectedDataRootSecretCoordinator: @unchecked Sendable {
    private let rootSecretStore: any ProtectedDataRootSecretStoreProtocol
    private let rootSecretIdentifier: String
    private let appSessionPolicyProvider: () -> AppSessionAuthenticationPolicy
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let traceStore: AuthLifecycleTraceStore?

    init(
        rootSecretStore: any ProtectedDataRootSecretStoreProtocol,
        rootSecretIdentifier: String,
        appSessionPolicyProvider: @escaping () -> AppSessionAuthenticationPolicy,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        traceStore: AuthLifecycleTraceStore?
    ) {
        self.rootSecretStore = rootSecretStore
        self.rootSecretIdentifier = rootSecretIdentifier
        self.appSessionPolicyProvider = appSessionPolicyProvider
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
        } catch where KeychainFailureClassifier.isItemNotFound(error) {
            // Deleting the last protected domain can run against already
            // cleaned-up state. Missing root secret is not a recovery failure here.
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.delete.finish",
                metadata: ["result": "missing"]
            )
        }
    }

    func loadRootSecretForAuthorization(
        registry: ProtectedDataRegistry,
        authenticationContext: LAContext,
        usesHandoffContext: Bool
    ) async throws -> Data {
        try await loadRootSecret(
            identifier: registry.sharedRightIdentifier,
            authenticationContext: authenticationContext,
            usesHandoffContext: usesHandoffContext
        )
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

    private func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext,
        usesHandoffContext: Bool
    ) async throws -> Data {
        let metadata = [
            "source": usesHandoffContext ? "handoff" : "interactive",
            "interactionNotAllowed": authenticationContext.interactionNotAllowed ? "true" : "false"
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
                    authenticationContext: authenticationContext
                )
                traceLoadRootSecretSuccess(metadata: metadata)
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
                    authenticationContext: authenticationContext
                )
            }
            traceLoadRootSecretSuccess(metadata: metadata)
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

    private func traceLoadRootSecretSuccess(
        metadata: [String: String]
    ) {
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.load.finish",
            metadata: metadata.merging(
                ["result": "success"],
                uniquingKeysWith: { _, new in new }
            )
        )
    }

    private func traceErrorMetadata(
        _ error: Error,
        extra: [String: String] = [:]
    ) -> [String: String] {
        var metadata = extra
        metadata["errorType"] = String(describing: type(of: error))
        if let keychainFailureTraceName = KeychainFailureClassifier.traceName(for: error) {
            metadata["keychainError"] = keychainFailureTraceName
        }
        if let laError = error as? LAError {
            metadata["laCode"] = String(laError.errorCode)
            metadata["laCodeName"] = String(describing: laError.code)
        }
        return metadata
    }
}
