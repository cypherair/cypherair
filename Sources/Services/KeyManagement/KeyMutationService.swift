import Foundation
import LocalAuthentication
import Security

struct SecureEnclaveCustodyDeletionContext {
    let publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting
    let handleStore: SecureEnclaveCustodyHandleStore
    // Device-Bound Post-Quantum split custody; nil until the composition root
    // wires the composite stores (the classical component envelope itself is
    // removed by the shared keychain-material path, keyed by fingerprint).
    let compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)?
    let compositeHandleStore: SecureEnclaveCompositeHandleStore?

    init(
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting,
        handleStore: SecureEnclaveCustodyHandleStore,
        compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)? = nil,
        compositeHandleStore: SecureEnclaveCompositeHandleStore? = nil
    ) {
        self.publicBindingInspector = publicBindingInspector
        self.handleStore = handleStore
        self.compositeBindingInspector = compositeBindingInspector
        self.compositeHandleStore = compositeHandleStore
    }
}

/// Owns key mutation workflows and modify-expiry crash recovery behind the facade.
final class KeyMutationService {
    /// Modify-expiry pre-authentication: evaluates the persisted mode's access
    /// control once and returns the authenticated context, which the flow
    /// threads into the short Secure Enclave unwrap and rewrap windows.
    /// `nil` keeps implicit per-operation authentication for unwired test and
    /// bypass graphs; production wiring passes
    /// `systemAccessControlExpiryAuthenticator`.
    typealias ExpiryAuthenticator = (SecAccessControl, String) async throws -> LAContext

    private let keyAdapter: PGPKeyOperationAdapter
    private let secureEnclave: any SecureEnclaveManageable
    private let keychain: any KeychainManageable
    private let defaults: UserDefaults
    private let bundleStore: KeyBundleStore
    private let migrationCoordinator: KeyMigrationCoordinator
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService
    private let privateKeyControlStore: any PrivateKeyControlStoreProtocol
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let expiryAuthenticator: ExpiryAuthenticator?
    private let secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext?
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
        privateKeyControlStore: any PrivateKeyControlStoreProtocol,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        expiryAuthenticator: ExpiryAuthenticator? = nil,
        secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext? = nil
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
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.expiryAuthenticator = expiryAuthenticator
        self.secureEnclaveCustodyDeletionContext = secureEnclaveCustodyDeletionContext
    }

    /// The production `ExpiryAuthenticator`: one system access-control
    /// `evaluateAccessControl(.useKeyKeyExchange)` against the persisted mode's
    /// access control (a biometric satisfies both the Standard OR-gate and the
    /// High Security flag set). Biometric reuse is disabled: this is exactly one
    /// fresh authentication for exactly one user action.
    static var systemAccessControlExpiryAuthenticator: ExpiryAuthenticator {
        { accessControl, reason in
            let context = LAContext()
            context.touchIDAuthenticationAllowableReuseDuration = 0
            do {
                let success = try await context.evaluateAccessControl(
                    accessControl,
                    operation: .useKeyKeyExchange,
                    localizedReason: reason
                )
                guard success else {
                    throw CypherAirError.authenticationFailed
                }
                return context
            } catch {
                // Every failure path invalidates the never-returned context
                // exactly once; only a returned (authenticated) context is the
                // caller's to invalidate.
                context.invalidate()
                if let laError = error as? LAError {
                    if [.userCancel, .appCancel, .systemCancel].contains(laError.code) {
                        // The user dismissed their own prompt: abort the action
                        // silently (the modify-expiry screen swallows
                        // operationCancelled by design) instead of surfacing a
                        // misleading storage/authentication alert.
                        throw CypherAirError.operationCancelled
                    }
                    // Any other LocalAuthentication failure (failed match,
                    // lockout, …) surfaces as an authentication failure — a
                    // raw LAError would fall through the screen model's
                    // fallback to the misleading "Failed to access secure
                    // storage." keychain message.
                    throw CypherAirError.authenticationFailed
                }
                throw error
            }
        }
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
        let operationRoute = await routeModifyExpiry(fingerprint: fingerprint)
        defer {
            operationRoute.endAuthorizedOperation()
        }
        switch operationRoute {
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

        case .secureEnclaveCompositeSigner(let route):
            return try await modifySecureEnclaveCompositeExpiry(
                route: route,
                newExpirySeconds: newExpirySeconds
            )

        case .secureEnclaveKeyAgreement, .secureEnclaveCompositeKeyAgreement:
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
        try await performModifySoftwareExpiry(
            route: route,
            newExpirySeconds: newExpirySeconds,
            authMode: authMode
        )
    }

    private func performModifySoftwareExpiry(
        route: SoftwareSecretCertificateRoute,
        newExpirySeconds: UInt64?,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        let fingerprint = route.identity.fingerprint
        let accessControl = try authMode.createAccessControl()

        // Authenticate before touching secret material, but scope the
        // operation-prompt session only to the access-control prompt. The
        // unwrap and rewrap Secure Enclave windows below have their own short
        // enrollment; certificate mutation and durable storage do not.
        var authenticationContext: LAContext?
        authenticationContext = try await authenticateModifyExpiryIfConfigured(
            accessControl: accessControl
        )
        defer {
            authenticationContext?.invalidate()
        }

        var secretKey = try await privateKeyAccessService.unwrapPrivateKey(
            fingerprint: fingerprint,
            authenticationContext: authenticationContext
        )
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
            // Not a decrypt-recipient mismatch: the key vanished from the catalog
            // mid-action (typically the key-metadata domain relocked underneath
            // the flow). Surface that honestly instead of `noMatchingKey`'s
            // decrypt-flavored message.
            throw CypherAirError.keyMetadataUnavailable
        }

        let bundle = try await rewrapModifiedExpiryResult(
            certData: result.certData,
            fingerprint: fingerprint,
            accessControl: accessControl,
            authenticationContext: authenticationContext
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

    private func authenticateModifyExpiryIfConfigured(
        accessControl: SecAccessControl
    ) async throws -> LAContext? {
        guard let expiryAuthenticator else {
            return nil
        }
        return try await authenticationPromptCoordinator.withOperationPrompt(
            source: "modifyExpiry.authenticate"
        ) {
            try await expiryAuthenticator(
                accessControl,
                String(
                    localized: "keydetail.expiry.auth.reason",
                    defaultValue: "Authenticate to change the key's expiry."
                )
            )
        }
    }

    private func rewrapModifiedExpiryResult(
        certData: Data,
        fingerprint: String,
        accessControl: SecAccessControl,
        authenticationContext: LAContext?
    ) async throws -> WrappedKeyBundle {
        try await authenticationPromptCoordinator.withOperationPrompt(
            source: "modifyExpiry.rewrap"
        ) {
            let seHandle = try secureEnclave.generateWrappingKey(
                accessControl: accessControl,
                authenticationContext: authenticationContext
            )
            return try secureEnclave.wrap(
                privateKey: certData,
                using: seHandle,
                fingerprint: fingerprint
            )
        }
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

    private func modifySecureEnclaveCompositeExpiry(
        route: SecureEnclaveCompositeSignerRoute,
        newExpirySeconds: UInt64?
    ) async throws -> PGPKeyIdentity {
        guard let expiryMutationService else {
            throw CypherAirError.keyOperationUnavailable(category: .operationNotImplementedForCustody)
        }

        let result = try await expiryMutationService.modifySecureEnclaveCompositeExpiry(
            route: route,
            newExpirySeconds: newExpirySeconds
        )

        let updated = try catalogStore.updateExpiry(
            metadata: result.metadata,
            publicKeyData: result.publicKeyData
        )

        return updated
    }

    private func routeModifyExpiry(fingerprint: String) async -> PrivateKeyOperationRoute {
        if let expiryMutationService {
            return await expiryMutationService.routeModifyExpiry(fingerprint: fingerprint)
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
        guard let identity = catalogStore.identity(for: fingerprint) else {
            try deleteKeychainMaterialAndMetadata(fingerprint: fingerprint)
            return
        }

        switch identity.privateKeyCustodyKind {
        case .softwareSecretCertificate:
            try deleteKeychainMaterialAndMetadata(fingerprint: fingerprint)
        case .appleSecureEnclavePrivateOperations:
            try deleteSecureEnclaveCustodyKey(identity)
        }
    }

    private func deleteKeychainMaterialAndMetadata(fingerprint: String) throws {
        try reportPartialDeletionIfNeeded(
            collectKeychainMaterialAndMetadataDeletionErrors(fingerprint: fingerprint)
        )
    }

    /// Removes all private keychain material and the catalog metadata for `fingerprint`,
    /// accumulating (never throwing) every removal failure so callers can merge error
    /// sets and report once. Catalog metadata removal is attempted unconditionally — a
    /// keychain failure never short-circuits it — so a key can never become permanently
    /// undeletable.
    private func collectKeychainMaterialAndMetadataDeletionErrors(fingerprint: String) -> [Error] {
        var deletionErrors = deleteAllPrivateKeychainMaterial(for: fingerprint)
        do {
            try catalogStore.removeKey(fingerprint: fingerprint)
        } catch {
            deletionErrors.append(error)
        }
        clearRecoveryStateIfNeeded(afterDeleting: fingerprint)
        return deletionErrors
    }

    private func deleteSecureEnclaveCustodyKey(_ identity: PGPKeyIdentity) throws {
        // Collect Secure Enclave handle-deletion failures, then ALWAYS run keychain +
        // catalog metadata removal (orphan-cleanup fallback), mirroring the software-key
        // path. Merge both error sets and report once — so the key always leaves the
        // catalog (stays deletable) while a partial deletion still surfaces to the caller.
        var deletionErrors = deleteSecureEnclaveCustodyHandles(for: identity)
        deletionErrors.append(
            contentsOf: collectKeychainMaterialAndMetadataDeletionErrors(fingerprint: identity.fingerprint)
        )
        try reportPartialDeletionIfNeeded(deletionErrors)
    }

    private func deleteSecureEnclaveCustodyHandles(for identity: PGPKeyIdentity) -> [Error] {
        guard let secureEnclaveCustodyDeletionContext else {
            return []
        }
        if identity.openPGPConfiguration.algorithmSuite == .mldsa65Ed25519Mlkem768X25519 {
            return deleteSecureEnclaveCompositeHandles(
                for: identity,
                context: secureEnclaveCustodyDeletionContext
            )
        }

        do {
            let inspection = try secureEnclaveCustodyDeletionContext.publicBindingInspector.inspectPublicBindings(
                publicKeyData: identity.publicKeyData
            )
            guard inspection.fingerprint.caseInsensitiveCompare(identity.fingerprint) == .orderedSame,
                  inspection.keyVersion == identity.keyVersion else {
                return [CypherAirError.keyOperationUnavailable(category: .metadataAssociationMismatch)]
            }

            try secureEnclaveCustodyDeletionContext.handleStore.deleteHandlePair(
                signingPublicKeyX963: inspection.signingPublicKeyX963,
                keyAgreementPublicKeyX963: inspection.keyAgreementPublicKeyX963
            )
            return []
        } catch let error as SecureEnclaveCustodyHandleError where error.isMissing {
            return []
        } catch {
            return [error]
        }
    }

    private func deleteSecureEnclaveCompositeHandles(
        for identity: PGPKeyIdentity,
        context: SecureEnclaveCustodyDeletionContext
    ) -> [Error] {
        guard let compositeBindingInspector = context.compositeBindingInspector,
              let compositeHandleStore = context.compositeHandleStore else {
            return [CypherAirError.keyOperationUnavailable(category: .operationUnavailableByPolicy)]
        }

        do {
            let inspection = try compositeBindingInspector.inspectCompositeBindings(
                publicKeyData: identity.publicKeyData
            )
            guard inspection.fingerprint.caseInsensitiveCompare(identity.fingerprint) == .orderedSame,
                  inspection.keyVersion == identity.keyVersion else {
                return [CypherAirError.keyOperationUnavailable(category: .metadataAssociationMismatch)]
            }

            try compositeHandleStore.deleteHandles(
                signingPublicKeyRaw: inspection.mldsa65SigningPublicKey,
                keyAgreementPublicKeyRaw: inspection.mlkem768KeyAgreementPublicKey
            )
            return []
        } catch let error as SecureEnclaveCustodyHandleError where error.isMissing {
            return []
        } catch {
            return [error]
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
            KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint)
        ]
    }

    private func clearRecoveryStateIfNeeded(afterDeleting fingerprint: String) {
        try? privateKeyControlStore.clearModifyExpiryJournalIfMatches(fingerprint: fingerprint)

        if catalogStore.keys.isEmpty {
            try? privateKeyControlStore.clearRewrapJournal()
        }
    }

    private func reportPartialDeletionIfNeeded(_ deletionErrors: [Error]) throws {
        if let firstError = deletionErrors.first {
            throw CypherAirError.keychainError(
                "Partial key deletion: \(deletionErrors.count) item(s) could not be removed — \(firstError.localizedDescription)"
            )
        }
    }

    private static func isItemNotFound(_ error: Error) -> Bool {
        KeychainFailureClassifier.isItemNotFound(error)
    }
}
