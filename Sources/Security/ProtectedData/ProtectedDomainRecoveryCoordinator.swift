import Foundation

struct ProtectedDomainRecoveryCoordinator {
    private let registryStore: ProtectedDataRegistryStore

    init(registryStore: ProtectedDataRegistryStore) {
        self.registryStore = registryStore
    }

    func performPreAuthBootstrapClassification() throws -> ProtectedDataRegistryBootstrapResult {
        try registryStore.performSynchronousBootstrap()
    }
}
