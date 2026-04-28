import Foundation
import LocalAuthentication

/// Owns in-memory key identity state and metadata persistence coordination.
final class KeyCatalogStore {
    private let metadataStore: any KeyMetadataPersistence

    private(set) var keys: [PGPKeyIdentity] = []

    init(metadataStore: any KeyMetadataPersistence) {
        self.metadataStore = metadataStore
    }

    var defaultKey: PGPKeyIdentity? {
        keys.first(where: \.isDefault)
    }

    func loadAll() throws {
        keys = try metadataStore.loadAll()
    }

    func migrateLegacyMetadataIfNeeded(
        authenticationContext: LAContext?
    ) throws -> KeyMetadataLegacyMigrationOutcome {
        guard let keychainMetadataStore = metadataStore as? KeyMetadataStore else {
            return KeyMetadataLegacyMigrationOutcome(
                legacyServiceCount: 0,
                migratedCount: 0,
                deletedLegacyCount: 0,
                failedItemCount: 0
            )
        }
        let outcome = try keychainMetadataStore.migrateLegacyMetadataIfNeeded(
            authenticationContext: authenticationContext
        )
        if outcome.didChangeDedicatedMetadata {
            keys = try metadataStore.loadAll()
        }
        return outcome
    }

    func containsKey(fingerprint: String) -> Bool {
        keys.contains(where: { $0.fingerprint == fingerprint })
    }

    func identity(for fingerprint: String) -> PGPKeyIdentity? {
        keys.first(where: { $0.fingerprint == fingerprint })
    }

    func storeNewIdentity(
        _ identity: PGPKeyIdentity,
        rollback: () -> Void
    ) throws {
        do {
            try metadataStore.save(identity)
        } catch {
            rollback()
            throw error
        }

        keys.append(identity)
    }

    func markBackedUp(fingerprint: String) {
        guard let index = keys.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            return
        }

        keys[index].isBackedUp = true
        try? metadataStore.update(keys[index])
    }

    func updateRevocation(
        fingerprint: String,
        revocationCert: Data
    ) {
        guard let index = keys.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            return
        }

        let previous = keys[index]
        var updated = previous
        updated.revocationCert = revocationCert
        keys[index] = updated

        do {
            try metadataStore.update(updated)
        } catch {
            try? metadataStore.save(previous)
        }
    }

    func updateExpiry(_ identity: PGPKeyIdentity) throws {
        try metadataStore.update(identity)

        guard let index = keys.firstIndex(where: { $0.fingerprint == identity.fingerprint }) else {
            return
        }

        keys[index] = identity
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
