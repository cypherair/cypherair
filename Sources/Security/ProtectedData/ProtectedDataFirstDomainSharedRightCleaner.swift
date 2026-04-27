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
    private let removePersistedSharedRight: @Sendable (_ identifier: String) async throws -> Void
    private let traceStore: AuthLifecycleTraceStore?

    init(
        storageRoot: ProtectedDataStorageRoot,
        hasPersistedSharedRight: @escaping @Sendable (_ identifier: String) -> Bool,
        removePersistedSharedRight: @escaping @Sendable (_ identifier: String) async throws -> Void,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.storageRoot = storageRoot
        self.hasPersistedSharedRight = hasPersistedSharedRight
        self.removePersistedSharedRight = removePersistedSharedRight
        self.traceStore = traceStore
    }

    func cleanupOrphanedSharedRightIfSafe(
        registry: ProtectedDataRegistry,
        source: String
    ) async throws -> ProtectedDataFirstDomainSharedRightCleanupOutcome {
        guard registry.pendingMutation == nil,
              registry.committedMembership.isEmpty,
              registry.sharedResourceLifecycleState == .absent else {
            traceFinish(.notNeeded, source: source)
            return .notNeeded
        }

        let sharedRightIdentifier = registry.sharedRightIdentifier
        guard hasPersistedSharedRight(sharedRightIdentifier) else {
            traceFinish(.noSharedRightPresent, source: source)
            return .noSharedRightPresent
        }

        guard try !storageRoot.hasProtectedDataArtifactsExcludingRegistry() else {
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
