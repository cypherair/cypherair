import Foundation
import LocalAuthentication

final class ProtectedDataRootSecretCoordinator: @unchecked Sendable {
    private let rootSecretStore: any ProtectedDataRootSecretStoreProtocol
    private let rootSecretIdentifier: String
    private let appSessionPolicyProvider: () -> AppSessionAuthenticationPolicy
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator

    init(
        rootSecretStore: any ProtectedDataRootSecretStoreProtocol,
        rootSecretIdentifier: String,
        appSessionPolicyProvider: @escaping () -> AppSessionAuthenticationPolicy,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator
    ) {
        self.rootSecretStore = rootSecretStore
        self.rootSecretIdentifier = rootSecretIdentifier
        self.appSessionPolicyProvider = appSessionPolicyProvider
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
    }

    func persistSharedRight(secretData: Data) async throws {
        let policy = appSessionPolicyProvider()
        try rootSecretStore.saveRootSecret(
            secretData,
            identifier: rootSecretIdentifier,
            policy: policy
        )
    }

    func removePersistedSharedRight(identifier: String) async throws {
        do {
            try rootSecretStore.deleteRootSecret(identifier: identifier)
        } catch where KeychainFailureClassifier.isItemNotFound(error) {
            // Deleting the last protected domain can run against already
            // cleaned-up state. Missing root secret is not a recovery failure here.
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
}
