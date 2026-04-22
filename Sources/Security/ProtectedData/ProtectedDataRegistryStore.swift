import Foundation

struct ProtectedDataRegistryBootstrapResult: Equatable, Sendable {
    let bootstrapOutcome: ProtectedDataBootstrapOutcome
    let frameworkState: ProtectedDataFrameworkState
}

struct ProtectedDataRegistryStore {
    private let storageRoot: ProtectedDataStorageRoot
    private let sharedRightIdentifier: String

    init(
        storageRoot: ProtectedDataStorageRoot,
        sharedRightIdentifier: String
    ) {
        self.storageRoot = storageRoot
        self.sharedRightIdentifier = sharedRightIdentifier
    }

    func performSynchronousBootstrap() throws -> ProtectedDataRegistryBootstrapResult {
        if storageRoot.registryExists() {
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
        let data = try Data(contentsOf: storageRoot.registryURL)
        let decoder = PropertyListDecoder()
        let registry = try decoder.decode(ProtectedDataRegistry.self, from: data)

        if let invalidReason = registry.validateConsistency() {
            throw ProtectedDataError.invalidRegistry(invalidReason)
        }

        return registry
    }

    func saveRegistry(_ registry: ProtectedDataRegistry) throws {
        if let invalidReason = registry.validateConsistency() {
            throw ProtectedDataError.invalidRegistry(invalidReason)
        }

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data = try encoder.encode(registry)
        try storageRoot.writeProtectedData(data, to: storageRoot.registryURL)
    }
}
