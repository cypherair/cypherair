import Foundation
import LocalAuthentication

/// Owns in-memory key identity state and metadata persistence coordination.
final class KeyCatalogStore {
    private let metadataStore: any KeyMetadataPersistence

    private(set) var keys: [PGPKeyIdentity] = []

    init(metadataStore: any KeyMetadataPersistence) {
        self.metadataStore = metadataStore
    }

    func loadAll() throws {
        keys = try metadataStore.loadAll()
    }

    func clearInMemoryIdentities() {
        keys = []
    }

    func containsKey(fingerprint: String) -> Bool {
        keys.contains(where: { $0.fingerprint == fingerprint })
    }

    func identity(for fingerprint: String) -> PGPKeyIdentity? {
        keys.first(where: { $0.fingerprint == fingerprint })
    }

    func storeNewIdentity(_ identity: PGPKeyIdentity) throws {
        try metadataStore.save(identity)
        keys.append(identity)
    }

    func discardCommittedIdentity(fingerprint: String) throws {
        try metadataStore.delete(fingerprint: fingerprint)
        keys.removeAll { $0.fingerprint == fingerprint }
    }

    func markBackedUp(fingerprint: String) {
        guard let index = keys.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            return
        }

        keys[index].isBackedUp = true
        try? metadataStore.update(keys[index])
    }

    func updateExpiry(
        metadata: PGPKeyMetadata,
        publicKeyData: Data
    ) throws -> PGPKeyIdentity {
        guard let index = keys.firstIndex(where: { $0.fingerprint == metadata.fingerprint }) else {
            throw CypherAirError.keyMetadataUnavailable
        }

        let current = keys[index]
        guard metadata.fingerprint.caseInsensitiveCompare(current.fingerprint) == .orderedSame else {
            throw CypherAirError.invalidKeyData(reason: "Modified certificate fingerprint mismatch.")
        }

        let updated = PGPKeyIdentity(
            fingerprint: current.fingerprint,
            keyVersion: metadata.keyVersion,
            profile: metadata.profile,
            userId: metadata.userId,
            hasEncryptionSubkey: metadata.hasEncryptionSubkey,
            isRevoked: metadata.isRevoked,
            isExpired: metadata.isExpired,
            isDefault: current.isDefault,
            isBackedUp: current.isBackedUp,
            publicKeyData: publicKeyData,
            revocationCert: current.revocationCert,
            primaryAlgo: metadata.primaryAlgo,
            subkeyAlgo: metadata.subkeyAlgo,
            expiryDate: metadata.expiryDate,
            openPGPConfigurationIdentity: current.openPGPConfigurationIdentity,
            privateKeyCustodyKind: current.privateKeyCustodyKind
        )

        try metadataStore.update(updated)
        keys[index] = updated
        return updated
    }

    func removeKey(fingerprint: String) throws {
        try metadataStore.delete(fingerprint: fingerprint)
        keys.removeAll { $0.fingerprint == fingerprint }

        guard !keys.isEmpty, !keys.contains(where: \.isDefault) else {
            return
        }

        keys[0].isDefault = true
        try metadataStore.update(keys[0])
    }

    func setDefaultKey(fingerprint: String) throws {
        var changedIndices: [Int] = []

        for index in keys.indices {
            let newDefault = keys[index].fingerprint == fingerprint
            if keys[index].isDefault != newDefault {
                keys[index].isDefault = newDefault
                changedIndices.append(index)
            }
        }

        for index in changedIndices {
            try metadataStore.update(keys[index])
        }
    }
}
