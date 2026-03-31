import Foundation

/// Persistence layer for non-sensitive key metadata stored in the Keychain.
struct KeyMetadataStore {
    private let keychain: any KeychainManageable
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(keychain: any KeychainManageable) {
        self.keychain = keychain
    }

    func loadAll() throws -> [PGPKeyIdentity] {
        let metadataServices = try keychain.listItems(
            servicePrefix: KeychainConstants.metadataPrefix,
            account: KeychainConstants.defaultAccount
        )

        var loaded: [PGPKeyIdentity] = []
        for service in metadataServices {
            do {
                let data = try keychain.load(
                    service: service,
                    account: KeychainConstants.defaultAccount
                )
                loaded.append(try decoder.decode(PGPKeyIdentity.self, from: data))
            } catch {
                // Skip corrupted metadata so the app can still start.
                continue
            }
        }

        return loaded
    }

    func save(_ identity: PGPKeyIdentity) throws {
        let data = try encoder.encode(identity)
        try keychain.save(
            data,
            service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
    }

    func update(_ identity: PGPKeyIdentity) throws {
        do {
            try keychain.delete(
                service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
                account: KeychainConstants.defaultAccount
            )
        } catch KeychainError.itemNotFound {
            // First-time save path.
        }

        try save(identity)
    }
}
