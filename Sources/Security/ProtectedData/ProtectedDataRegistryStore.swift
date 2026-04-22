import Foundation

struct ProtectedDataRegistryBootstrapResult: Equatable, Sendable {
    let bootstrapState: ProtectedDataBootstrapState
    let frameworkState: ProtectedDataFrameworkState
    let didBootstrapEmptyRegistry: Bool
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
                    bootstrapState: .frameworkRecoveryNeeded,
                    frameworkState: .frameworkRecoveryNeeded,
                    didBootstrapEmptyRegistry: false
                )
            }

            return ProtectedDataRegistryBootstrapResult(
                bootstrapState: .loadedExistingRegistry,
                frameworkState: .sessionLocked,
                didBootstrapEmptyRegistry: false
            )
        }

        if try storageRoot.hasProtectedDataArtifactsExcludingRegistry() {
            return ProtectedDataRegistryBootstrapResult(
                bootstrapState: .frameworkRecoveryNeeded,
                frameworkState: .frameworkRecoveryNeeded,
                didBootstrapEmptyRegistry: false
            )
        }

        try storageRoot.ensureRootDirectoryExists()
        try saveRegistry(.emptySteadyState(sharedRightIdentifier: sharedRightIdentifier))

        return ProtectedDataRegistryBootstrapResult(
            bootstrapState: .bootstrappedEmptyRegistry,
            frameworkState: .sessionLocked,
            didBootstrapEmptyRegistry: true
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
