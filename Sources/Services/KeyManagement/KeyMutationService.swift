import Foundation

/// Owns key mutation workflows and modify-expiry crash recovery behind the facade.
final class KeyMutationService {
    private let engine: PgpEngine
    private let secureEnclave: any SecureEnclaveManageable
    private let keychain: any KeychainManageable
    private let defaults: UserDefaults
    private let bundleStore: KeyBundleStore
    private let migrationCoordinator: KeyMigrationCoordinator
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService

    init(
        engine: PgpEngine,
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        defaults: UserDefaults,
        bundleStore: KeyBundleStore,
        migrationCoordinator: KeyMigrationCoordinator,
        catalogStore: KeyCatalogStore,
        privateKeyAccessService: PrivateKeyAccessService
    ) {
        self.engine = engine
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.defaults = defaults
        self.bundleStore = bundleStore
        self.migrationCoordinator = migrationCoordinator
        self.catalogStore = catalogStore
        self.privateKeyAccessService = privateKeyAccessService
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

        var result = try await Self.modifyExpiryOffMainActor(
            engine: engine,
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

        defaults.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        defaults.set(fingerprint, forKey: AuthPreferences.modifyExpiryFingerprintKey)

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

        defaults.set(false, forKey: AuthPreferences.modifyExpiryInProgressKey)
        defaults.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)

        var updated = existingIdentity
        updated.isExpired = result.keyInfo.isExpired
        updated.publicKeyData = result.publicKeyData
        updated.expiryDate = result.keyInfo.expiryTimestamp.map {
            Date(timeIntervalSince1970: TimeInterval($0))
        }

        try catalogStore.updateExpiry(updated)
        return updated
    }

    func deleteKey(fingerprint: String) throws {
        let deletionErrors = deleteAllKeychainMaterial(for: fingerprint)
        catalogStore.removeKey(fingerprint: fingerprint)
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
        guard defaults.bool(forKey: AuthPreferences.modifyExpiryInProgressKey) else {
            return nil
        }

        guard let fingerprint = defaults.string(forKey: AuthPreferences.modifyExpiryFingerprintKey),
              !fingerprint.isEmpty else {
            defaults.set(false, forKey: AuthPreferences.modifyExpiryInProgressKey)
            defaults.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)
            return .unrecoverable
        }

        let recoveryOutcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        if recoveryOutcome.shouldClearRecoveryFlag {
            defaults.set(false, forKey: AuthPreferences.modifyExpiryInProgressKey)
            defaults.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)
        }

        return recoveryOutcome
    }

    private func deleteAllKeychainMaterial(for fingerprint: String) -> [Error] {
        var deletionErrors: [Error] = []

        for service in allKeychainServices(for: fingerprint) {
            do {
                try keychain.delete(service: service, account: KeychainConstants.defaultAccount)
            } catch {
                guard !Self.isItemNotFound(error) else {
                    continue
                }
                deletionErrors.append(error)
            }
        }
        do {
            try keychain.delete(
                service: KeychainConstants.metadataService(fingerprint: fingerprint),
                account: KeychainConstants.metadataAccount
            )
        } catch {
            guard !Self.isItemNotFound(error) else {
                return deletionErrors
            }
            deletionErrors.append(error)
        }

        return deletionErrors
    }

    private func allKeychainServices(for fingerprint: String) -> [String] {
        [
            KeychainConstants.seKeyService(fingerprint: fingerprint),
            KeychainConstants.saltService(fingerprint: fingerprint),
            KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            KeychainConstants.metadataService(fingerprint: fingerprint)
        ]
    }

    private func clearRecoveryStateIfNeeded(afterDeleting fingerprint: String) {
        if defaults.bool(forKey: AuthPreferences.modifyExpiryInProgressKey),
           defaults.string(forKey: AuthPreferences.modifyExpiryFingerprintKey) == fingerprint {
            defaults.set(false, forKey: AuthPreferences.modifyExpiryInProgressKey)
            defaults.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)
        }

        if defaults.bool(forKey: AuthPreferences.rewrapInProgressKey),
           catalogStore.keys.isEmpty {
            defaults.set(false, forKey: AuthPreferences.rewrapInProgressKey)
            defaults.removeObject(forKey: AuthPreferences.rewrapTargetModeKey)
        }
    }

    @concurrent
    private static func modifyExpiryOffMainActor(
        engine: PgpEngine,
        certData: Data,
        newExpirySeconds: UInt64?
    ) async throws -> ModifyExpiryResult {
        do {
            return try engine.modifyExpiry(
                certData: certData,
                newExpirySeconds: newExpirySeconds
            )
        } catch {
            throw CypherAirError.from(error) { .keyGenerationFailed(reason: $0) }
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
