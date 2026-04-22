import Foundation

struct ProtectedDataRegistryBootstrapResult: Equatable, Sendable {
    let bootstrapOutcome: ProtectedDataBootstrapOutcome
    let frameworkState: ProtectedDataFrameworkState
}

private actor ProtectedDataRegistryMutationGate {
    func run<T: Sendable>(_ operation: @Sendable () async throws -> T) async rethrows -> T {
        try await operation()
    }
}

final class ProtectedDataRegistryStore: @unchecked Sendable {
    private let storageRoot: ProtectedDataStorageRoot
    private let sharedRightIdentifier: String
    private let mutationGate = ProtectedDataRegistryMutationGate()

    init(
        storageRoot: ProtectedDataStorageRoot,
        sharedRightIdentifier: String
    ) {
        self.storageRoot = storageRoot
        self.sharedRightIdentifier = sharedRightIdentifier
    }

    func performSynchronousBootstrap() throws -> ProtectedDataRegistryBootstrapResult {
        try storageRoot.validatePersistentStorageContract()

        if try storageRoot.registryExists() {
            let registry = try loadRegistry()
            let disposition = registry.classifyRecoveryDisposition()
            if disposition == .frameworkRecoveryNeeded {
                return ProtectedDataRegistryBootstrapResult(
                    bootstrapOutcome: .frameworkRecoveryNeeded,
                    frameworkState: .frameworkRecoveryNeeded,
                )
            }

            return ProtectedDataRegistryBootstrapResult(
                bootstrapOutcome: .loadedRegistry(
                    registry: registry,
                    recoveryDisposition: disposition
                ),
                frameworkState: .sessionLocked,
            )
        }

        if try storageRoot.hasProtectedDataArtifactsExcludingRegistry() {
            return ProtectedDataRegistryBootstrapResult(
                bootstrapOutcome: .frameworkRecoveryNeeded,
                frameworkState: .frameworkRecoveryNeeded,
            )
        }

        try storageRoot.ensureRootDirectoryExists()
        let registry = ProtectedDataRegistry.emptySteadyState(sharedRightIdentifier: sharedRightIdentifier)
        try saveRegistry(registry)

        return ProtectedDataRegistryBootstrapResult(
            bootstrapOutcome: .emptySteadyState(
                registry: registry,
                didBootstrap: true
            ),
            frameworkState: .sessionLocked,
        )
    }

    func loadRegistry() throws -> ProtectedDataRegistry {
        try storageRoot.validatePersistentStorageContract()
        let data = try storageRoot.readManagedData(at: storageRoot.registryURL)
        let decoder = PropertyListDecoder()
        let registry = try decoder.decode(ProtectedDataRegistry.self, from: data)

        if let invalidReason = registry.validateConsistency() {
            throw ProtectedDataError.invalidRegistry(invalidReason)
        }

        return registry
    }

    func saveRegistry(_ registry: ProtectedDataRegistry) throws {
        try storageRoot.validatePersistentStorageContract()
        if let invalidReason = registry.validateConsistency() {
            throw ProtectedDataError.invalidRegistry(invalidReason)
        }

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data = try encoder.encode(registry)
        try storageRoot.writeProtectedData(data, to: storageRoot.registryURL)
    }

    func performCreateDomainTransaction(
        domainID: ProtectedDataDomainID,
        initialCommittedState: ProtectedDataCommittedDomainState = .active,
        provisionSharedResourceIfNeeded: @escaping @Sendable () async throws -> Void,
        stageArtifacts: @escaping @Sendable () async throws -> Void,
        validateArtifacts: @escaping @Sendable () async throws -> Void
    ) async throws -> ProtectedDataRegistry {
        try await mutationGate.run { [self] in
            var registry = try loadRegistry()
            try assertMutationPreconditions(registry: registry, targetDomainID: domainID, operation: "create")
            let isFirstCommittedDomain = registry.committedMembership.isEmpty

            registry.pendingMutation = .createDomain(targetDomainID: domainID, phase: .journaled)
            try saveRegistry(registry)

            if isFirstCommittedDomain {
                try await provisionSharedResourceIfNeeded()
                registry = try loadRegistry()
                registry.pendingMutation = .createDomain(
                    targetDomainID: domainID,
                    phase: .sharedResourceProvisioned
                )
                try saveRegistry(registry)
            }

            try await stageArtifacts()
            registry = try loadRegistry()
            registry.pendingMutation = .createDomain(
                targetDomainID: domainID,
                phase: .artifactsStaged
            )
            try saveRegistry(registry)

            try await validateArtifacts()
            registry = try loadRegistry()
            registry.pendingMutation = .createDomain(
                targetDomainID: domainID,
                phase: .validated
            )
            try saveRegistry(registry)

            registry.committedMembership[domainID] = initialCommittedState
            if isFirstCommittedDomain {
                registry.sharedResourceLifecycleState = .ready
            }
            registry.pendingMutation = .createDomain(
                targetDomainID: domainID,
                phase: .membershipCommitted
            )
            try saveRegistry(registry)

            registry.pendingMutation = nil
            try saveRegistry(registry)
            return registry
        }
    }

    func performDeleteDomainTransaction(
        domainID: ProtectedDataDomainID,
        deleteArtifacts: @escaping @Sendable () async throws -> Void,
        cleanupSharedResourceIfNeeded: @escaping @Sendable () async throws -> Void
    ) async throws -> ProtectedDataRegistry {
        try await mutationGate.run { [self] in
            var registry = try loadRegistry()
            try assertMutationPreconditions(registry: registry, targetDomainID: domainID, operation: "delete")
            guard registry.committedMembership[domainID] != nil else {
                throw ProtectedDataError.invalidRegistry(
                    "Delete-domain target \(domainID.rawValue) must already be a committed member."
                )
            }

            registry.pendingMutation = .deleteDomain(targetDomainID: domainID, phase: .journaled)
            try saveRegistry(registry)

            try await deleteArtifacts()
            registry = try loadRegistry()
            registry.pendingMutation = .deleteDomain(
                targetDomainID: domainID,
                phase: .artifactsDeleted
            )
            try saveRegistry(registry)

            registry.committedMembership.removeValue(forKey: domainID)
            let requiresSharedCleanup = registry.committedMembership.isEmpty
            registry.sharedResourceLifecycleState = requiresSharedCleanup ? .cleanupPending : .ready
            registry.pendingMutation = .deleteDomain(
                targetDomainID: domainID,
                phase: .membershipRemoved
            )
            try saveRegistry(registry)

            if requiresSharedCleanup {
                registry.pendingMutation = .deleteDomain(
                    targetDomainID: domainID,
                    phase: .sharedResourceCleanupStarted
                )
                try saveRegistry(registry)

                try await cleanupSharedResourceIfNeeded()
                registry = try loadRegistry()
                registry.sharedResourceLifecycleState = .absent
                registry.pendingMutation = nil
                try saveRegistry(registry)
            } else {
                registry.pendingMutation = nil
                try saveRegistry(registry)
            }

            return registry
        }
    }

    func updateCommittedDomainState(
        domainID: ProtectedDataDomainID,
        to state: ProtectedDataCommittedDomainState
    ) async throws -> ProtectedDataRegistry {
        try await mutationGate.run { [self] in
            var registry = try loadRegistry()
            guard registry.pendingMutation == nil else {
                throw ProtectedDataError.invalidRegistry(
                    "Committed domain state cannot change while a pending mutation exists."
                )
            }
            guard registry.committedMembership[domainID] != nil else {
                throw ProtectedDataError.invalidRegistry(
                    "Committed domain \(domainID.rawValue) is missing."
                )
            }
            registry.committedMembership[domainID] = state
            try saveRegistry(registry)
            return registry
        }
    }

    private func assertMutationPreconditions(
        registry: ProtectedDataRegistry,
        targetDomainID: ProtectedDataDomainID,
        operation: String
    ) throws {
        guard registry.pendingMutation == nil else {
            throw ProtectedDataError.invalidRegistry(
                "Cannot \(operation) domain while another pending mutation exists."
            )
        }

        if operation == "create", registry.committedMembership[targetDomainID] != nil {
            throw ProtectedDataError.invalidRegistry(
                "Create-domain target \(targetDomainID.rawValue) is already committed."
            )
        }
    }
}
