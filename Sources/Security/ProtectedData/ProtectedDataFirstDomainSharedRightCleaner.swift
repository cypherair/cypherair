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
    private let traceStore: AuthLifecycleTraceStore?

    init(
        storageRoot: ProtectedDataStorageRoot,
        hasPersistedSharedRight: @escaping @Sendable (_ identifier: String) -> Bool,
        hasExternalProtectedDataArtifacts: @escaping () throws -> Bool = { false },
        removePersistedSharedRight: @escaping @Sendable (_ identifier: String) async throws -> Void,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.storageRoot = storageRoot
        self.hasPersistedSharedRight = hasPersistedSharedRight
        self.hasExternalProtectedDataArtifacts = hasExternalProtectedDataArtifacts
        self.removePersistedSharedRight = removePersistedSharedRight
        self.traceStore = traceStore
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
            traceFinish(.notNeeded, source: source)
            return .notNeeded
        }

        let sharedRightIdentifier = registry.sharedRightIdentifier
        guard hasPersistedSharedRight(sharedRightIdentifier) else {
            traceFinish(.noSharedRightPresent, source: source)
            return .noSharedRightPresent
        }

        guard try !storageRoot.hasProtectedDataArtifactsExcludingRegistry(),
              try !hasExternalProtectedDataArtifacts() else {
            traceFinish(.blockedByArtifacts, source: source)
            return .blockedByArtifacts
        }

        try await removePersistedSharedRight(sharedRightIdentifier)
        traceFinish(.removedOrphanedSharedRight, source: source)
        return .removedOrphanedSharedRight
    }

    private func traceFinish(
        _ outcome: ProtectedDataFirstDomainSharedRightCleanupOutcome,
        source: String
    ) {
        traceStore?.record(
            category: .operation,
            name: "protectedData.firstDomainSharedRightCleanup.finish",
            metadata: [
                "source": source,
                "outcome": Self.traceValue(for: outcome)
            ]
        )
    }

    private static func traceValue(
        for outcome: ProtectedDataFirstDomainSharedRightCleanupOutcome
    ) -> String {
        switch outcome {
        case .notNeeded:
            "notNeeded"
        case .noSharedRightPresent:
            "noSharedRightPresent"
        case .removedOrphanedSharedRight:
            "removedOrphanedSharedRight"
        case .blockedByArtifacts:
            "blockedByArtifacts"
        }
    }
}
