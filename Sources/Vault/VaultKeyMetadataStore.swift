import Foundation

/// The key list, read from and written through the vault's keys domain.
final class VaultKeyMetadataStore: KeyMetadataPersistence {
    private let vault: AppVault

    init(vault: AppVault) {
        self.vault = vault
    }

    func loadAll() throws -> [PGPKeyIdentity] {
        guard let keys = vault.keys else { throw CypherAirError.keyMetadataUnavailable }
        return keys.sorted { $0.fingerprint < $1.fingerprint }
    }

    func save(_ identity: PGPKeyIdentity) throws {
        var keys = try loadAll()
        guard !keys.contains(where: { $0.fingerprint == identity.fingerprint }) else {
            throw CypherAirError.duplicateKey
        }
        keys.append(identity)
        try vault.saveKeys(keys)
    }

    func update(_ identity: PGPKeyIdentity) throws {
        var keys = try loadAll()
        if let index = keys.firstIndex(where: { $0.fingerprint == identity.fingerprint }) {
            keys[index] = identity
        } else {
            keys.append(identity)
        }
        try vault.saveKeys(keys)
    }

    func delete(fingerprint: String) throws {
        var keys = try loadAll()
        keys.removeAll { $0.fingerprint == fingerprint }
        try vault.saveKeys(keys)
    }
}

enum KeyMetadataLoadState: Equatable {
    case locked
    case loading
    case loaded
    case recoveryNeeded
}

protocol KeyMetadataPersistence: AnyObject {
    func loadAll() throws -> [PGPKeyIdentity]
    func save(_ identity: PGPKeyIdentity) throws
    func update(_ identity: PGPKeyIdentity) throws
    func delete(fingerprint: String) throws
}

/// Key list held in memory only: the tutorial sandbox and UI-test containers.
final class InMemoryKeyMetadataStore: KeyMetadataPersistence {
    private var identities: [PGPKeyIdentity]

    init(identities: [PGPKeyIdentity] = []) {
        self.identities = identities.sorted { $0.fingerprint < $1.fingerprint }
    }

    func loadAll() -> [PGPKeyIdentity] { identities }

    func save(_ identity: PGPKeyIdentity) throws {
        guard !identities.contains(where: { $0.fingerprint == identity.fingerprint }) else {
            throw CypherAirError.duplicateKey
        }
        identities.append(identity)
        identities.sort { $0.fingerprint < $1.fingerprint }
    }

    func update(_ identity: PGPKeyIdentity) {
        if let index = identities.firstIndex(where: { $0.fingerprint == identity.fingerprint }) {
            identities[index] = identity
        } else {
            identities.append(identity)
            identities.sort { $0.fingerprint < $1.fingerprint }
        }
    }

    func delete(fingerprint: String) {
        identities.removeAll { $0.fingerprint == fingerprint }
    }
}
