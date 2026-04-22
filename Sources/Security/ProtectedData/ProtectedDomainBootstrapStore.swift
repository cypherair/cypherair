import Foundation

struct ProtectedDomainBootstrapMetadata: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let expectedCurrentGenerationIdentifier: String?
    let coarseRecoveryReason: String?
    let wrappedDomainMasterKeyRecordVersion: Int?
}

struct ProtectedDomainBootstrapStore {
    private let storageRoot: ProtectedDataStorageRoot

    init(storageRoot: ProtectedDataStorageRoot) {
        self.storageRoot = storageRoot
    }

    func loadMetadata(for domainID: ProtectedDataDomainID) throws -> ProtectedDomainBootstrapMetadata? {
        try storageRoot.validatePersistentStorageContract()
        let url = storageRoot.bootstrapMetadataURL(for: domainID)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }

        let data = try Data(contentsOf: url)
        return try PropertyListDecoder().decode(ProtectedDomainBootstrapMetadata.self, from: data)
    }

    func saveMetadata(_ metadata: ProtectedDomainBootstrapMetadata, for domainID: ProtectedDataDomainID) throws {
        try storageRoot.validatePersistentStorageContract()
        try storageRoot.ensureDomainDirectoryExists(for: domainID)
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data = try encoder.encode(metadata)
        try storageRoot.writeProtectedData(data, to: storageRoot.bootstrapMetadataURL(for: domainID))
    }

    func removeMetadata(for domainID: ProtectedDataDomainID) throws {
        try storageRoot.validatePersistentStorageContract()
        try storageRoot.removeItemIfPresent(at: storageRoot.bootstrapMetadataURL(for: domainID))
    }
}
