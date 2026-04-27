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
    private let traceStore: AuthLifecycleTraceStore?
    private let mutationGate = ProtectedDataRegistryMutationGate()

    init(
        storageRoot: ProtectedDataStorageRoot,
        sharedRightIdentifier: String,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.storageRoot = storageRoot
        self.sharedRightIdentifier = sharedRightIdentifier
        self.traceStore = traceStore
    }

    func performSynchronousBootstrap() throws -> ProtectedDataRegistryBootstrapResult {
        traceStore?.record(
            category: .lifecycle,
            name: "protectedData.registryBootstrap.start"
        )
        do {
            let result = try performSynchronousBootstrapImpl()
            traceStore?.record(
                category: .lifecycle,
                name: "protectedData.registryBootstrap.finish",
                metadata: ["result": "success"]
            )
            return result
        } catch {
            traceStore?.record(
                category: .lifecycle,
                name: "protectedData.registryBootstrap.finish",
                metadata: AuthTraceMetadata.errorMetadata(
                    error,
                    extra: ["result": "failed", "stage": "registryBootstrap"]
                )
            )
            throw error
        }
    }

    private func performSynchronousBootstrapImpl() throws -> ProtectedDataRegistryBootstrapResult {
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

    @discardableResult
    func recordRootSecretEnvelopeMinimumVersion(_ version: Int) async throws -> ProtectedDataRegistry {
        try await mutationGate.run { [self] in
            var registry = try loadRegistry()
            if let currentVersion = registry.rootSecretEnvelopeMinimumVersion,
               currentVersion >= version {
                return registry
            }
            registry.rootSecretEnvelopeMinimumVersion = version
            try saveRegistry(registry)
            traceStore?.record(
                category: .operation,
                name: "protectedData.registry.rootSecretEnvelopeFloor",
                metadata: ["minimumEnvelopeVersion": String(version), "result": "recorded"]
            )
            return registry
        }
    }

    func performCreateDomainTransaction(
        domainID: ProtectedDataDomainID,
        initialCommittedState: ProtectedDataCommittedDomainState = .active,
        validateBeforeJournal: @escaping @Sendable (ProtectedDataRegistry) throws -> Void = { _ in },
        provisionSharedResourceIfNeeded: @escaping @Sendable () async throws -> Void,
        stageArtifacts: @escaping @Sendable () async throws -> Void,
        validateArtifacts: @escaping @Sendable () async throws -> Void
    ) async throws -> ProtectedDataRegistry {
        try await mutationGate.run { [self] in
            var registry = try loadRegistry()
            try assertMutationPreconditions(registry: registry, targetDomainID: domainID, operation: "create")
            try validateBeforeJournal(registry)
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

    func completePendingCreate(
        domainID: ProtectedDataDomainID,
        initialCommittedState: ProtectedDataCommittedDomainState = .active,
        stageArtifacts: @escaping @Sendable () async throws -> Void,
        validateArtifacts: @escaping @Sendable () async throws -> Void
    ) async throws -> ProtectedDataRegistry {
        try await mutationGate.run { [self] in
            var registry = try loadRegistry()
            guard case let .createDomain(targetDomainID, phase)? = registry.pendingMutation,
                    targetDomainID == domainID else {
                throw ProtectedDataError.invalidRegistry(
                    "Pending create for domain \(domainID.rawValue) is missing."
                )
            }

            if registry.committedMembership.isEmpty && registry.sharedResourceLifecycleState == .absent {
                throw ProtectedDataError.invalidRegistry(
                    "First-domain pending create for \(domainID.rawValue) cannot continue without resetting."
                )
            }

            guard registry.sharedResourceLifecycleState == .ready else {
                throw ProtectedDataError.invalidRegistry(
                    "Pending create for \(domainID.rawValue) requires a ready shared resource."
                )
            }

            var currentPhase = phase
            switch currentPhase {
            case .journaled, .sharedResourceProvisioned:
                try await stageArtifacts()
                registry = try loadRegistry()
                registry.pendingMutation = .createDomain(
                    targetDomainID: domainID,
                    phase: .artifactsStaged
                )
                try saveRegistry(registry)
                currentPhase = .artifactsStaged
            case .artifactsStaged, .validated, .membershipCommitted:
                break
            }

            if currentPhase == .artifactsStaged {
                try await validateArtifacts()
                registry = try loadRegistry()
                registry.pendingMutation = .createDomain(
                    targetDomainID: domainID,
                    phase: .validated
                )
                try saveRegistry(registry)
                currentPhase = .validated
            }

            if currentPhase == .validated {
                registry = try loadRegistry()
                registry.committedMembership[domainID] = initialCommittedState
                registry.sharedResourceLifecycleState = .ready
                registry.pendingMutation = .createDomain(
                    targetDomainID: domainID,
                    phase: .membershipCommitted
                )
                try saveRegistry(registry)
                currentPhase = .membershipCommitted
            }

            if currentPhase == .membershipCommitted {
                registry = try loadRegistry()
                guard registry.committedMembership[domainID] != nil else {
                    throw ProtectedDataError.invalidRegistry(
                        "Pending create membershipCommitted requires \(domainID.rawValue) to be committed."
                    )
                }
                registry.sharedResourceLifecycleState = .ready
                registry.pendingMutation = nil
                try saveRegistry(registry)
            }

            return try loadRegistry()
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

    func recoverPendingMutation(
        targetDomainID: ProtectedDataDomainID,
        continueReadyCreate: @escaping @Sendable (_ phase: CreateDomainPhase) async throws -> Void = { _ in },
        continueDelete: @escaping @Sendable (_ phase: DeleteDomainPhase) async throws -> Void
    ) async throws -> PendingRecoveryOutcome {
        try await mutationGate.run { [self] in
            let registry = try loadRegistry()
            guard case let pendingMutation? = registry.pendingMutation,
                    pendingMutation.targetDomainID == targetDomainID else {
                return .frameworkRecoveryNeeded
            }

            switch pendingMutation {
            case .createDomain(_, let phase):
                // First-domain pending create rows stay reset-only because ordinary
                // shared-root authorization is valid only after the registry is ready.
                if registry.committedMembership.isEmpty && registry.sharedResourceLifecycleState == .absent {
                    return .resetRequired
                }

                if registry.sharedResourceLifecycleState != .ready {
                    return .frameworkRecoveryNeeded
                }

                do {
                    switch phase {
                    case .membershipCommitted:
                        var updatedRegistry = registry
                        updatedRegistry.pendingMutation = nil
                        try saveRegistry(updatedRegistry)
                    case .journaled, .sharedResourceProvisioned, .artifactsStaged, .validated:
                        try await continueReadyCreate(phase)
                    }
                } catch {
                    return try currentPendingRecoveryOutcome(for: targetDomainID)
                }

                return try currentPendingRecoveryOutcome(for: targetDomainID)

            case .deleteDomain(_, let phase):
                do {
                    try await continueDelete(phase)
                } catch {
                    return try currentPendingRecoveryOutcome(for: targetDomainID)
                }

                return try currentPendingRecoveryOutcome(for: targetDomainID)
            }
        }
    }

    func abandonPendingCreate(
        domainID: ProtectedDataDomainID,
        deleteArtifacts: @escaping @Sendable () async throws -> Void,
        cleanupSharedResourceIfNeeded: @escaping @Sendable () async throws -> Void
    ) async throws -> ProtectedDataRegistry {
        try await mutationGate.run { [self] in
            var registry = try loadRegistry()
            guard case let .createDomain(targetDomainID, phase)? = registry.pendingMutation,
                    targetDomainID == domainID else {
                throw ProtectedDataError.invalidRegistry(
                    "Pending create for domain \(domainID.rawValue) is missing."
                )
            }

            if phase == .membershipCommitted {
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
                }

                registry.pendingMutation = nil
                try saveRegistry(registry)
                return registry
            }

            var membershipAfterRemoval = registry.committedMembership
            membershipAfterRemoval.removeValue(forKey: domainID)
            let requiresSharedResourceCleanup = membershipAfterRemoval.isEmpty
                && createPhaseMayHaveProvisionedSharedResource(phase)
            if requiresSharedResourceCleanup {
                try await cleanupSharedResourceIfNeeded()
            }

            try await deleteArtifacts()

            registry = try loadRegistry()
            registry.committedMembership.removeValue(forKey: domainID)
            registry.sharedResourceLifecycleState = registry.committedMembership.isEmpty ? .absent : .ready
            registry.pendingMutation = nil
            try saveRegistry(registry)
            return registry
        }
    }

    func completePendingDelete(
        domainID: ProtectedDataDomainID,
        deleteArtifacts: @escaping @Sendable () async throws -> Void,
        cleanupSharedResourceIfNeeded: @escaping @Sendable () async throws -> Void
    ) async throws -> ProtectedDataRegistry {
        try await mutationGate.run { [self] in
            var registry = try loadRegistry()
            guard case let .deleteDomain(targetDomainID, phase)? = registry.pendingMutation,
                    targetDomainID == domainID else {
                throw ProtectedDataError.invalidRegistry(
                    "Pending delete for domain \(domainID.rawValue) is missing."
                )
            }

            let requiresMembershipRemoval = {
                switch phase {
                case .journaled, .artifactsDeleted:
                    return true
                case .membershipRemoved, .sharedResourceCleanupStarted:
                    return false
                }
            }()

            if requiresMembershipRemoval {
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
            } else {
                try await deleteArtifacts()
            }

            registry = try loadRegistry()
            if registry.sharedResourceLifecycleState == .cleanupPending {
                registry.pendingMutation = .deleteDomain(
                    targetDomainID: domainID,
                    phase: .sharedResourceCleanupStarted
                )
                try saveRegistry(registry)

                try await cleanupSharedResourceIfNeeded()
                registry = try loadRegistry()
                registry.sharedResourceLifecycleState = .absent
            }

            registry.pendingMutation = nil
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

    private func currentPendingRecoveryOutcome(
        for targetDomainID: ProtectedDataDomainID
    ) throws -> PendingRecoveryOutcome {
        let registry = try loadRegistry()
        guard registry.classifyRecoveryDisposition() == .continuePendingMutation,
                registry.pendingMutation?.targetDomainID == targetDomainID else {
            return .resumedToSteadyState
        }

        switch registry.pendingMutation {
        case .some(.createDomain):
            if registry.committedMembership.isEmpty && registry.sharedResourceLifecycleState == .absent {
                return .resetRequired
            }
            return .retryablePending
        case .some(.deleteDomain):
            return .retryablePending
        case nil:
            return .resumedToSteadyState
        }
    }

    private func createPhaseMayHaveProvisionedSharedResource(_ phase: CreateDomainPhase) -> Bool {
        switch phase {
        case .journaled:
            return false
        case .sharedResourceProvisioned, .artifactsStaged, .validated, .membershipCommitted:
            return true
        }
    }
}
