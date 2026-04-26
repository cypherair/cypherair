import Foundation
import LocalAuthentication

struct KeyMetadataLegacyMigrationOutcome: Equatable {
    let legacyServiceCount: Int
    let migratedCount: Int
    let deletedLegacyCount: Int
    let failedItemCount: Int

    var didChangeDedicatedMetadata: Bool {
        migratedCount > 0
    }
}

/// Persistence layer for non-sensitive key metadata stored in the Keychain.
struct KeyMetadataStore {
    private let keychain: any KeychainManageable
    private let traceStore: AuthLifecycleTraceStore?
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(keychain: any KeychainManageable, traceStore: AuthLifecycleTraceStore? = nil) {
        self.keychain = keychain
        self.traceStore = traceStore
    }

    func loadAll() throws -> [PGPKeyIdentity] {
        try loadAll(
            account: KeychainConstants.metadataAccount,
            authenticationContext: nil
        )
    }

    func migrateLegacyMetadataIfNeeded(
        authenticationContext: LAContext?
    ) throws -> KeyMetadataLegacyMigrationOutcome {
        traceStore?.record(
            category: .operation,
            name: "keyMetadata.legacyMigration.start",
            metadata: ["hasAuthenticationContext": authenticationContext == nil ? "false" : "true"]
        )

        let currentIdentities = try loadAll(
            account: KeychainConstants.metadataAccount,
            authenticationContext: nil
        )
        var currentFingerprints = Set(currentIdentities.map(\.fingerprint))
        let legacyServices = try keychain.listItems(
            servicePrefix: KeychainConstants.metadataPrefix,
            account: KeychainConstants.defaultAccount,
            authenticationContext: authenticationContext
        )

        var migratedCount = 0
        var deletedLegacyCount = 0
        var failedItemCount = 0

        for service in legacyServices.sorted() {
            do {
                let data = try keychain.load(
                    service: service,
                    account: KeychainConstants.defaultAccount,
                    authenticationContext: authenticationContext
                )
                let identity = try decoder.decode(PGPKeyIdentity.self, from: data)

                if !currentFingerprints.contains(identity.fingerprint) {
                    try save(identity, account: KeychainConstants.metadataAccount)
                    currentFingerprints.insert(identity.fingerprint)
                    migratedCount += 1
                }

                do {
                    try keychain.delete(
                        service: service,
                        account: KeychainConstants.defaultAccount,
                        authenticationContext: authenticationContext
                    )
                    deletedLegacyCount += 1
                } catch where Self.isItemNotFound(error) {
                } catch {
                    failedItemCount += 1
                    traceStore?.record(
                        category: .operation,
                        name: "keyMetadata.legacyMigration.itemError",
                        metadata: AuthTraceMetadata.errorMetadata(
                            error,
                            extra: ["step": "deleteLegacy", "serviceKind": AuthTraceMetadata.keychainServiceKind(for: service)]
                        )
                    )
                }
            } catch {
                failedItemCount += 1
                traceStore?.record(
                    category: .operation,
                    name: "keyMetadata.legacyMigration.itemError",
                    metadata: AuthTraceMetadata.errorMetadata(
                        error,
                        extra: ["step": "loadOrSave", "serviceKind": AuthTraceMetadata.keychainServiceKind(for: service)]
                    )
                )
                continue
            }
        }

        let outcome = KeyMetadataLegacyMigrationOutcome(
            legacyServiceCount: legacyServices.count,
            migratedCount: migratedCount,
            deletedLegacyCount: deletedLegacyCount,
            failedItemCount: failedItemCount
        )
        traceStore?.record(
            category: .operation,
            name: "keyMetadata.legacyMigration.finish",
            metadata: [
                "result": failedItemCount == 0 ? "success" : "partial",
                "legacyServiceCount": String(outcome.legacyServiceCount),
                "migratedCount": String(outcome.migratedCount),
                "deletedLegacyCount": String(outcome.deletedLegacyCount),
                "failedItemCount": String(outcome.failedItemCount)
            ]
        )
        return outcome
    }

    func save(_ identity: PGPKeyIdentity) throws {
        try save(identity, account: KeychainConstants.metadataAccount)
    }

    func delete(fingerprint: String, account: String = KeychainConstants.metadataAccount) throws {
        try keychain.delete(
            service: KeychainConstants.metadataService(fingerprint: fingerprint),
            account: account
        )
    }

    func save(_ identity: PGPKeyIdentity, account: String) throws {
        let data = try encoder.encode(identity)
        try keychain.save(
            data,
            service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
            account: account,
            accessControl: nil
        )
    }

    func update(_ identity: PGPKeyIdentity) throws {
        do {
            try keychain.delete(
                service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
                account: KeychainConstants.metadataAccount
            )
        } catch where Self.isItemNotFound(error) {
            // First-time save path.
        }

        try save(identity)
    }

    private func loadAll(
        account: String,
        authenticationContext: LAContext?
    ) throws -> [PGPKeyIdentity] {
        let metadataServices = try keychain.listItems(
            servicePrefix: KeychainConstants.metadataPrefix,
            account: account,
            authenticationContext: authenticationContext
        )

        var loaded: [PGPKeyIdentity] = []
        for service in metadataServices.sorted() {
            do {
                let data = try keychain.load(
                    service: service,
                    account: account,
                    authenticationContext: authenticationContext
                )
                loaded.append(try decoder.decode(PGPKeyIdentity.self, from: data))
            } catch {
                // Skip corrupted metadata so the app can still start.
                continue
            }
        }

        return loaded
    }

    private static func isItemNotFound(_ error: Error) -> Bool {
        if let keychainError = error as? KeychainError {
            return keychainError == .itemNotFound
        }
        if let mockKeychainError = error as? MockKeychainError {
            switch mockKeychainError {
            case .itemNotFound:
                return true
            case .duplicateItem, .saveFailed, .deleteFailed:
                return false
            }
        }
        return false
    }
}
