import Foundation

/// Owns key mutation workflows and modify-expiry crash recovery behind the facade.
final class KeyMutationService {
    private let keyAdapter: PGPKeyOperationAdapter
    private let secureEnclave: any SecureEnclaveManageable
    private let keychain: any KeychainManageable
    private let defaults: UserDefaults
    private let bundleStore: KeyBundleStore
    private let migrationCoordinator: KeyMigrationCoordinator
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService
    private let privateKeyControlStore: any PrivateKeyControlStoreProtocol

    init(
        keyAdapter: PGPKeyOperationAdapter,
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        defaults: UserDefaults,
        bundleStore: KeyBundleStore,
        migrationCoordinator: KeyMigrationCoordinator,
        catalogStore: KeyCatalogStore,
        privateKeyAccessService: PrivateKeyAccessService,
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) {
        self.keyAdapter = keyAdapter
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.defaults = defaults
        self.bundleStore = bundleStore
        self.migrationCoordinator = migrationCoordinator
        self.catalogStore = catalogStore
        self.privateKeyAccessService = privateKeyAccessService
        self.privateKeyControlStore = privateKeyControlStore
    }

    func modifyExpiry(
        fingerprint: String,
        newExpirySeconds: UInt64?
    ) async throws -> PGPKeyIdentity {
        let authMode = try privateKeyControlStore.requireUnlockedAuthMode()
        return try await modifyExpiry(
            fingerprint: fingerprint,
            newExpirySeconds: newExpirySeconds,
            authMode: authMode
        )
    }

    func modifyExpiry(
        fingerprint: String,
        newExpirySeconds: UInt64?,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        var secretKey = try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        var result = try await keyAdapter.modifyExpiry(
            certData: secretKey,
            newExpirySeconds: newExpirySeconds
        )
        defer {
            result.certData.resetBytes(in: 0..<result.certData.count)
        }

        guard let existingIdentity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.noMatchingKey
        }

        let accessControl = try authMode.createAccessControl()
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        let bundle = try secureEnclave.wrap(
            privateKey: result.certData,
            using: seHandle,
            fingerprint: fingerprint
        )

        do {
            try bundleStore.saveBundle(
                bundle,
                fingerprint: fingerprint,
                namespace: .pending
            )
        } catch {
            bundleStore.cleanupPendingBundle(fingerprint: fingerprint)
            throw error
        }

        do {
            _ = try bundleStore.loadBundle(
                fingerprint: fingerprint,
                namespace: .pending
            )
        } catch {
            bundleStore.cleanupPendingBundle(fingerprint: fingerprint)
            throw error
        }

        do {
            try privateKeyControlStore.beginModifyExpiry(fingerprint: fingerprint)
        } catch {
            bundleStore.cleanupPendingBundle(fingerprint: fingerprint)
            throw error
        }

        do {
            try bundleStore.deleteBundle(fingerprint: fingerprint)
        } catch {
            throw error
        }

        do {
            try bundleStore.promotePendingToPermanent(fingerprint: fingerprint)
        } catch {
            throw error
        }

        var updated = existingIdentity
        updated.isExpired = result.metadata.isExpired
        updated.publicKeyData = result.publicKeyData
        updated.expiryDate = result.metadata.expiryTimestamp.map {
            Date(timeIntervalSince1970: TimeInterval($0))
        }

        try catalogStore.updateExpiry(updated)
        try privateKeyControlStore.clearModifyExpiryJournal()
        return updated
    }

    func deleteKey(fingerprint: String) throws {
        var deletionErrors = deleteAllPrivateKeychainMaterial(for: fingerprint)
        do {
            try catalogStore.removeKey(fingerprint: fingerprint)
        } catch {
            deletionErrors.append(error)
        }
        cleanupLegacyMetadataRows(for: fingerprint, deletionErrors: &deletionErrors)
        clearRecoveryStateIfNeeded(afterDeleting: fingerprint)

        if let firstError = deletionErrors.first {
            throw CypherAirError.keychainError(
                "Partial key deletion: \(deletionErrors.count) item(s) could not be removed — \(firstError.localizedDescription)"
            )
        }
    }

    func setDefaultKey(fingerprint: String) throws {
        try catalogStore.setDefaultKey(fingerprint: fingerprint)
    }

    func checkAndRecoverFromInterruptedModifyExpiry() -> KeyMigrationRecoveryOutcome? {
        guard let entry = try? privateKeyControlStore.recoveryJournal().modifyExpiry else {
            return nil
        }

        guard let fingerprint = entry.fingerprint,
              !fingerprint.isEmpty else {
            try? privateKeyControlStore.clearModifyExpiryJournal()
            return .unrecoverable
        }

        let recoveryOutcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        if recoveryOutcome.shouldClearRecoveryFlag {
            try? privateKeyControlStore.clearModifyExpiryJournal()
        }

        return recoveryOutcome
    }

    private func deleteAllPrivateKeychainMaterial(for fingerprint: String) -> [Error] {
        var deletionErrors: [Error] = []

        for service in allPrivateKeychainServices(for: fingerprint) {
            do {
                try keychain.delete(service: service, account: KeychainConstants.defaultAccount)
            } catch {
                guard !Self.isItemNotFound(error) else {
                    continue
                }
                deletionErrors.append(error)
            }
        }

        return deletionErrors
    }

    private func cleanupLegacyMetadataRows(
        for fingerprint: String,
        deletionErrors: inout [Error]
    ) {
        let service = KeychainConstants.metadataService(fingerprint: fingerprint)
        for account in [KeychainConstants.defaultAccount, KeychainConstants.metadataAccount] {
            do {
                try keychain.delete(service: service, account: account)
            } catch {
                guard !Self.isItemNotFound(error) else {
                    continue
                }
                deletionErrors.append(error)
            }
        }
    }

    private func allPrivateKeychainServices(for fingerprint: String) -> [String] {
        [
            KeychainConstants.seKeyService(fingerprint: fingerprint),
            KeychainConstants.saltService(fingerprint: fingerprint),
            KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint)
        ]
    }

    private func clearRecoveryStateIfNeeded(afterDeleting fingerprint: String) {
        try? privateKeyControlStore.clearModifyExpiryJournalIfMatches(fingerprint: fingerprint)

        if catalogStore.keys.isEmpty {
            try? privateKeyControlStore.clearRewrapJournal()
        }
    }

    private static func isItemNotFound(_ error: Error) -> Bool {
        if let keychainError = error as? KeychainError,
           case .itemNotFound = keychainError {
            return true
        }
        if let mockError = error as? MockKeychainError,
           case .itemNotFound = mockError {
            return true
        }
        return false
    }
}
