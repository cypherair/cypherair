import Foundation

enum ProtectedDataFirstDomainSharedRightCleanupOutcome: Equatable, Sendable {
    case notNeeded
    case noSharedRightPresent
    case removedOrphanedSharedRight
    case blockedByArtifacts
}

struct ProtectedDataFirstDomainSharedRightCleaner: @unchecked Sendable {
    private let storageRoot: ProtectedDataStorageRoot
    private let hasPersistedSharedRight: @Sendable (_ identifier: String) -> Bool
    private let hasExternalProtectedDataArtifacts: () throws -> Bool
    // The actual root-secret deletion must happen before this closure's first suspension point.
    // Delaying deletion past an await would reopen the first-domain cleanup race.
    private let removePersistedSharedRight: @Sendable (_ identifier: String) async throws -> Void

    init(
        storageRoot: ProtectedDataStorageRoot,
        hasPersistedSharedRight: @escaping @Sendable (_ identifier: String) -> Bool,
        hasExternalProtectedDataArtifacts: @escaping () throws -> Bool = { false },
        removePersistedSharedRight: @escaping @Sendable (_ identifier: String) async throws -> Void
    ) {
        self.storageRoot = storageRoot
        self.hasPersistedSharedRight = hasPersistedSharedRight
        self.hasExternalProtectedDataArtifacts = hasExternalProtectedDataArtifacts
        self.removePersistedSharedRight = removePersistedSharedRight
    }

    func cleanupJournaledFirstDomainSharedRightIfSafe(
        expectedDomainID: ProtectedDataDomainID,
        source: String,
        loadCurrentRegistry: @Sendable () throws -> ProtectedDataRegistry
    ) async throws -> ProtectedDataFirstDomainSharedRightCleanupOutcome {
        let registry = try loadCurrentRegistry()
        guard registry.committedMembership.isEmpty,
              registry.sharedResourceLifecycleState == .absent,
              case let .createDomain(targetDomainID, phase)? = registry.pendingMutation,
              targetDomainID == expectedDomainID,
              phase == .journaled else {
            return .notNeeded
        }

        let sharedRightIdentifier = registry.sharedRightIdentifier
        guard hasPersistedSharedRight(sharedRightIdentifier) else {
            return .noSharedRightPresent
        }

        guard try !storageRoot.hasProtectedDataArtifactsExcludingRegistry(),
              try !hasExternalProtectedDataArtifacts() else {
            return .blockedByArtifacts
        }

        try await removePersistedSharedRight(sharedRightIdentifier)
        return .removedOrphanedSharedRight
    }
}
