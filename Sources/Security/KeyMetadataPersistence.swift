import Foundation

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

/// Ephemeral key-metadata persistence for compositions whose metadata lives
/// no longer than the owning container, such as the tutorial sandbox and the
/// UI-test graph.
final class InMemoryKeyMetadataStore: KeyMetadataPersistence {
    private var identities: [PGPKeyIdentity]

    init(identities: [PGPKeyIdentity] = []) {
        self.identities = identities.sorted { $0.fingerprint < $1.fingerprint }
    }

    func loadAll() -> [PGPKeyIdentity] {
        identities
    }

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
