import Foundation
import LocalAuthentication

protocol ProtectedDomainRecoveryHandler: AnyObject, Sendable {
    var protectedDataDomainID: ProtectedDataDomainID { get }

    func continuePendingCreate(
        phase: CreateDomainPhase,
        authenticationContext: LAContext?
    ) async throws
    func deleteDomainArtifactsForRecovery() throws
}

private struct ProtectedDomainRecoveryAuthenticationContext: @unchecked Sendable {
    let value: LAContext?
}

struct ProtectedDomainRecoveryCoordinator {
    private let registryStore: ProtectedDataRegistryStore

    init(registryStore: ProtectedDataRegistryStore) {
        self.registryStore = registryStore
    }

    func performPreAuthBootstrapClassification() throws -> ProtectedDataRegistryBootstrapResult {
        try registryStore.performSynchronousBootstrap()
    }

    func loadCurrentRegistry() throws -> ProtectedDataRegistry {
        try registryStore.loadRegistry()
    }

    func pendingRecoveryAuthorizationRequirement() -> ProtectedDataMutationAuthorizationRequirement {
        do {
            let registry = try registryStore.loadRegistry()
            guard registry.classifyRecoveryDisposition() != .frameworkRecoveryNeeded else {
                return .frameworkRecoveryNeeded
            }
            guard case let pendingMutation? = registry.pendingMutation else {
                return .notRequired
            }

            switch pendingMutation {
            case .createDomain(_, let phase):
                switch phase {
                case .journaled, .sharedResourceProvisioned, .artifactsStaged, .validated:
                    if registry.committedMembership.isEmpty && registry.sharedResourceLifecycleState == .absent {
                        return .notRequired
                    }
                    guard registry.sharedResourceLifecycleState == .ready else {
                        return .frameworkRecoveryNeeded
                    }
                    return .wrappingRootKeyRequired
                case .membershipCommitted:
                    return .notRequired
                }
            case .deleteDomain:
                return .notRequired
            }
        } catch {
            return .frameworkRecoveryNeeded
        }
    }

    func recoverPendingMutation(
        handler: any ProtectedDomainRecoveryHandler,
        authenticationContext: LAContext? = nil,
        removeSharedRight: @escaping @Sendable (String) async throws -> Void
    ) async throws -> PendingRecoveryOutcome {
        let registry = try registryStore.loadRegistry()
        guard case let pendingMutation? = registry.pendingMutation,
                pendingMutation.targetDomainID == handler.protectedDataDomainID else {
            return .frameworkRecoveryNeeded
        }
        let sharedRightIdentifier = registry.sharedRightIdentifier
        let recoveryAuthenticationContext = ProtectedDomainRecoveryAuthenticationContext(
            value: authenticationContext
        )

        return try await registryStore.recoverPendingMutation(
            targetDomainID: handler.protectedDataDomainID,
            continueReadyCreate: { phase in
                try await handler.continuePendingCreate(
                    phase: phase,
                    authenticationContext: recoveryAuthenticationContext.value
                )
            },
            continueDelete: { _ in
                _ = try await registryStore.completePendingDelete(
                    domainID: handler.protectedDataDomainID,
                    deleteArtifacts: {
                        try handler.deleteDomainArtifactsForRecovery()
                    },
                    cleanupSharedResourceIfNeeded: {
                        try await removeSharedRight(sharedRightIdentifier)
                    }
                )
            }
        )
    }

    func recoverPendingMutation(
        handlers: [any ProtectedDomainRecoveryHandler],
        authenticationContext: LAContext? = nil,
        removeSharedRight: @escaping @Sendable (String) async throws -> Void
    ) async throws -> PendingRecoveryOutcome {
        let registry = try registryStore.loadRegistry()
        guard case let pendingMutation? = registry.pendingMutation else {
            return .frameworkRecoveryNeeded
        }
        guard let handler = handlers.first(where: {
            $0.protectedDataDomainID == pendingMutation.targetDomainID
        }) else {
            return .frameworkRecoveryNeeded
        }

        return try await recoverPendingMutation(
            handler: handler,
            authenticationContext: authenticationContext,
            removeSharedRight: removeSharedRight
        )
    }
}
