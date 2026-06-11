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
    private var expiryMutationService: (any PrivateKeyExpiryMutationRouting)?

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

    func configureExpiryMutationService(_ service: any PrivateKeyExpiryMutationRouting) {
        expiryMutationService = service
    }

    func modifyExpiry(
        fingerprint: String,
        newExpirySeconds: UInt64?
    ) async throws -> PGPKeyIdentity {
        return try await modifyExpiry(
            fingerprint: fingerprint,
            newExpirySeconds: newExpirySeconds,
            authMode: nil
        )
    }

    func modifyExpiry(
        fingerprint: String,
        newExpirySeconds: UInt64?,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        try await modifyExpiry(
            fingerprint: fingerprint,
            newExpirySeconds: newExpirySeconds,
            authMode: Optional(authMode)
        )
    }

    private func modifyExpiry(
        fingerprint: String,
        newExpirySeconds: UInt64?,
        authMode: AuthenticationMode?
    ) async throws -> PGPKeyIdentity {
        switch routeModifyExpiry(fingerprint: fingerprint) {
        case .softwareSecretCertificate(let route):
            let effectiveAuthMode: AuthenticationMode
            if let authMode {
                effectiveAuthMode = authMode
            } else {
                effectiveAuthMode = try privateKeyControlStore.requireUnlockedAuthMode()
            }
            return try await modifySoftwareExpiry(
                route: route,
                newExpirySeconds: newExpirySeconds,
                authMode: effectiveAuthMode
            )

        case .secureEnclaveSigner(let route):
            return try await modifySecureEnclaveExpiry(
                route: route,
                newExpirySeconds: newExpirySeconds
            )

        case .secureEnclaveKeyAgreement:
            throw CypherAirError.keyOperationUnavailable(category: .privateOperationRoleMismatch)

        case .blocked(let resolution):
            throw CypherAirError.keyOperationUnavailable(
                category: resolution.failureCategory ?? .operationUnavailableByPolicy
            )
        }
    }

    private func modifySoftwareExpiry(
        route: SoftwareSecretCertificateRoute,
        newExpirySeconds: UInt64?,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        let fingerprint = route.identity.fingerprint
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

        guard catalogStore.containsKey(fingerprint: fingerprint) else {
            throw CypherAirError.noMatchingKey
        }

        let accessControl = try authMode.createAccessControl()
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl, authenticationContext: nil)
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

        let updated = try catalogStore.updateExpiry(
            metadata: result.metadata,
            publicKeyData: result.publicKeyData
        )

        try privateKeyControlStore.clearModifyExpiryJournal()
        return updated
    }

    private func modifySecureEnclaveExpiry(
        route: SecureEnclaveSignerRoute,
        newExpirySeconds: UInt64?
    ) async throws -> PGPKeyIdentity {
        guard let expiryMutationService else {
            throw CypherAirError.keyOperationUnavailable(category: .operationNotImplementedForCustody)
        }

        let result = try await expiryMutationService.modifySecureEnclaveExpiry(
            route: route,
            newExpirySeconds: newExpirySeconds
        )

        let updated = try catalogStore.updateExpiry(
            metadata: result.metadata,
            publicKeyData: result.publicKeyData
        )

        return updated
    }

    private func routeModifyExpiry(fingerprint: String) -> PrivateKeyOperationRoute {
        if let expiryMutationService {
            return expiryMutationService.routeModifyExpiry(fingerprint: fingerprint)
        }

        guard let identity = catalogStore.identity(for: fingerprint) else {
            return .blocked(.unavailable(.metadataAssociationMismatch))
        }

        let resolution = PGPKeyCapabilityResolver().resolution(
            for: .modifyExpiry,
            identity: identity
        )
        guard resolution.support == .supported else {
            return .blocked(resolution)
        }

        switch identity.privateKeyCustodyKind {
        case .softwareSecretCertificate:
            return .softwareSecretCertificate(
                SoftwareSecretCertificateRoute(
                    identity: identity,
                    operation: .modifyExpiry
                )
            )
        case .appleSecureEnclavePrivateOperations:
            return .blocked(.unavailable(.operationUnavailableByPolicy))
        }
    }

    func deleteKey(fingerprint: String) throws {
        var deletionErrors = deleteAllPrivateKeychainMaterial(for: fingerprint)
        do {
            try catalogStore.removeKey(fingerprint: fingerprint)
        } catch {
            deletionErrors.append(error)
        }
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
        KeychainFailureClassifier.isItemNotFound(error)
    }
}
