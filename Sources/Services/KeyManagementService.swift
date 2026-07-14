import Foundation
import LocalAuthentication

/// Manages the full key lifecycle: generation, import, export, deletion, and default selection.
/// Coordinates OpenPGP adapters and Security layer for SE wrapping/Keychain storage.
///
/// All private key material is SE-wrapped before storage and zeroized from memory after use.
@Observable
final class KeyManagementService: @unchecked Sendable {

    /// All key identities stored on this device.
    private(set) var keys: [PGPKeyIdentity] = []
    private(set) var metadataLoadState: KeyMetadataLoadState = .locked

    private let certificateAdapter: PGPCertificateOperationAdapter
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService
    private let provisioningService: KeyProvisioningService
    private let secureEnclaveCustodyGenerationService: SecureEnclaveCustodyGenerationService?
    private let secureEnclaveCustodyRecoveryService: (any SecureEnclaveCustodyGenerationRecoveryClassifying)?
    private let exportService: KeyExportService
    private let selectiveRevocationService: SelectiveRevocationService
    private let mutationService: KeyMutationService
    private let privateKeyControlStore: any PrivateKeyControlStoreProtocol
    private let provisioningInvalidationGate: KeyProvisioningInvalidationGate
    private let provisioningCommitCoordinator: KeyProvisioningCommitCoordinator
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let beforeAuthModeReadCheckpoint: KeyProvisioningService.ProvisioningCheckpoint?
    private let postProvisioningCheckpoint: KeyProvisioningService.ProvisioningCheckpoint?
    private let commitDrainWaiterRegisteredCheckpoint: KeyProvisioningService.ProvisioningCheckpoint?
    private let relockInvalidationCheckpoint: KeyProvisioningService.ProvisioningCheckpoint?
    private let secureEnclaveCustodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator?
    private let compositeCustodyRouterContext: CompositeCustodyRouterContext?
    private let traceStore: AuthLifecycleTraceStore?
    private(set) var secureEnclaveCustodyRecoveryReport: SecureEnclaveCustodyGenerationRecoveryReport = .empty

    /// Whether device-bound Secure Enclave custody generation is wired for this
    /// container. UI uses this to decide whether device-bound families are offered.
    var isSecureEnclaveCustodyGenerationAvailable: Bool {
        secureEnclaveCustodyGenerationService != nil
    }

    init(
        keyAdapter: PGPKeyOperationAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo(),
        authenticationPromptCoordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator(),
        privateKeyControlStore: any PrivateKeyControlStoreProtocol,
        expiryAuthenticator: KeyMutationService.ExpiryAuthenticator? = nil,
        secureEnclaveCustodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator? = nil,
        compositeCustodyRouterContext: CompositeCustodyRouterContext? = nil,
        secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext? = nil,
        authLifecycleTraceStore: AuthLifecycleTraceStore? = nil,
        metadataPersistence: any KeyMetadataPersistence,
        beforeAuthModeReadCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        provisioningCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        provisioningWrappingPromptCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        afterImportOffMainActorCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        afterPermanentBundleStoreCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        identityStoreCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        postProvisioningCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        commitDrainWaiterRegisteredCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        relockInvalidationCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        secureEnclaveCustodyGenerationServiceFactory: ((
            KeyCatalogStore,
            KeyProvisioningInvalidationGate,
            KeyProvisioningCommitCoordinator
        ) -> SecureEnclaveCustodyGenerationService)? = nil,
        secureEnclaveCustodyRecoveryService: (any SecureEnclaveCustodyGenerationRecoveryClassifying)? = nil
    ) {
        let bundleStore = KeyBundleStore(keychain: keychain)
        let migrationCoordinator = KeyMigrationCoordinator(bundleStore: bundleStore)
        let catalogStore = KeyCatalogStore(metadataStore: metadataPersistence)
        let privateKeyAccessService = PrivateKeyAccessService(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore,
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            certificatePrimaryFingerprint: keyAdapter.certificatePrimaryFingerprintInspector(),
            traceStore: authLifecycleTraceStore
        )
        let effectivePrivateKeyControlStore = privateKeyControlStore
        let provisioningInvalidationGate = KeyProvisioningInvalidationGate()
        let provisioningCommitCoordinator = KeyProvisioningCommitCoordinator()
        self.certificateAdapter = certificateAdapter
        self.catalogStore = catalogStore
        self.privateKeyAccessService = privateKeyAccessService
        self.privateKeyControlStore = effectivePrivateKeyControlStore
        self.provisioningInvalidationGate = provisioningInvalidationGate
        self.provisioningCommitCoordinator = provisioningCommitCoordinator
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.beforeAuthModeReadCheckpoint = beforeAuthModeReadCheckpoint
        self.postProvisioningCheckpoint = postProvisioningCheckpoint
        self.commitDrainWaiterRegisteredCheckpoint = commitDrainWaiterRegisteredCheckpoint
        self.relockInvalidationCheckpoint = relockInvalidationCheckpoint
        self.secureEnclaveCustodyOperationAuthenticator = secureEnclaveCustodyOperationAuthenticator
        self.compositeCustodyRouterContext = compositeCustodyRouterContext
        self.provisioningService = KeyProvisioningService(
            keyAdapter: keyAdapter,
            secureEnclave: secureEnclave,
            memoryInfo: memoryInfo,
            bundleStore: bundleStore,
            catalogStore: catalogStore,
            invalidationGate: provisioningInvalidationGate,
            commitCoordinator: provisioningCommitCoordinator,
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            beforePermanentStorageCheckpoint: provisioningCheckpoint,
            wrappingPromptCheckpoint: provisioningWrappingPromptCheckpoint,
            afterImportOffMainActorCheckpoint: afterImportOffMainActorCheckpoint,
            afterPermanentBundleStoreCheckpoint: afterPermanentBundleStoreCheckpoint,
            afterIdentityStoreCheckpoint: identityStoreCheckpoint
        )
        self.secureEnclaveCustodyGenerationService = secureEnclaveCustodyGenerationServiceFactory?(
            catalogStore,
            provisioningInvalidationGate,
            provisioningCommitCoordinator
        )
        self.secureEnclaveCustodyRecoveryService = secureEnclaveCustodyRecoveryService
        self.exportService = KeyExportService(
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            catalogStore: catalogStore,
            privateKeyAccessService: privateKeyAccessService
        )
        self.selectiveRevocationService = SelectiveRevocationService(
            certificateAdapter: certificateAdapter,
            catalogStore: catalogStore,
            privateKeyAccessService: privateKeyAccessService
        )
        self.mutationService = KeyMutationService(
            keyAdapter: keyAdapter,
            secureEnclave: secureEnclave,
            keychain: keychain,
            bundleStore: bundleStore,
            migrationCoordinator: migrationCoordinator,
            catalogStore: catalogStore,
            privateKeyAccessService: privateKeyAccessService,
            privateKeyControlStore: effectivePrivateKeyControlStore,
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            expiryAuthenticator: expiryAuthenticator,
            secureEnclaveCustodyDeletionContext: secureEnclaveCustodyDeletionContext
        )
        self.traceStore = authLifecycleTraceStore
    }

    // MARK: - Key Enumeration

    /// Load all key identities from the configured metadata persistence layer.
    func loadKeys() throws {
        metadataLoadState = .loading
        do {
            try catalogStore.loadAll()
            syncKeysAndSecureEnclaveRecoveryReport()
            metadataLoadState = .loaded
        } catch {
            catalogStore.clearInMemoryIdentities()
            keys = []
            secureEnclaveCustodyRecoveryReport = .empty
            metadataLoadState = .recoveryNeeded
            throw error
        }
    }

    func beginKeyMetadataLoad() {
        metadataLoadState = .loading
    }

    func markKeyMetadataLocked() {
        catalogStore.clearInMemoryIdentities()
        keys = []
        secureEnclaveCustodyRecoveryReport = .empty
        metadataLoadState = .locked
    }

    func markKeyMetadataRecoveryNeeded() {
        catalogStore.clearInMemoryIdentities()
        keys = []
        secureEnclaveCustodyRecoveryReport = .empty
        metadataLoadState = .recoveryNeeded
    }

    func completeKeyMetadataLoad(
        source: String
    ) throws {
        try loadKeys()
        traceStore?.record(
            category: .operation,
            name: "keyMetadata.protectedDomain.sessionUpdate",
            metadata: [
                "source": source,
                "keyCount": String(keys.count)
            ]
        )
    }

    func resetInMemoryStateAfterLocalDataReset() {
        provisioningInvalidationGate.invalidate()
        catalogStore.clearInMemoryIdentities()
        keys = []
        secureEnclaveCustodyRecoveryReport = .empty
        metadataLoadState = .locked
    }

    // MARK: - Key Generation

    /// Single generation entry point: dispatches to the portable software
    /// path or the Secure Enclave custody path by the family's custody model.
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        family: PGPKeyConfiguration.Identity
    ) async throws -> PGPKeyIdentity {
        if let profile = family.equivalentSoftwareProfile {
            return try await generateKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                profile: profile
            )
        }
        return try await generateSecureEnclaveCustodyKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            configurationIdentity: family
        )
    }

    /// Generate a new key pair with the specified profile.
    /// The private key is immediately SE-wrapped and stored in Keychain.
    ///
    /// Uses the unlocked private-key control domain for the SE access-control mode.
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: PGPKeyProfile
    ) async throws -> PGPKeyIdentity {
        let token = provisioningInvalidationGate.makeToken()
        if let beforeAuthModeReadCheckpoint {
            await beforeAuthModeReadCheckpoint()
        }
        try Task.checkCancellation()
        try provisioningInvalidationGate.checkValid(token)
        let authMode = try privateKeyControlStore.requireUnlockedAuthMode()
        try Task.checkCancellation()
        try provisioningInvalidationGate.checkValid(token)
        return try await generateKeyWithValidatedAuthMode(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            profile: profile,
            authMode: authMode,
            token: token
        )
    }

    private func generateKeyWithValidatedAuthMode(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: PGPKeyProfile,
        authMode: AuthenticationMode,
        token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        let identity = try await provisioningService.generateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            profile: profile,
            authMode: authMode,
            invalidationToken: token
        )
        if let postProvisioningCheckpoint {
            await postProvisioningCheckpoint()
        }
        try provisioningInvalidationGate.checkValid(token)
        syncKeysAndSecureEnclaveRecoveryReport()
        return identity
    }

    func generateSecureEnclaveCustodyKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        configurationIdentity: PGPKeyConfiguration.Identity
    ) async throws -> PGPKeyIdentity {
        guard let secureEnclaveCustodyGenerationService else {
            throw CypherAirError.keyOperationUnavailable(category: .operationUnavailableByPolicy)
        }
        let token = provisioningInvalidationGate.makeToken()
        let identity: PGPKeyIdentity
        do {
            identity = try await secureEnclaveCustodyGenerationService.generateKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                configurationIdentity: configurationIdentity,
                invalidationToken: token
            )
        } catch let error as SecureEnclaveCustodyHandleError {
            // Normalize handle-store failures to the sanitized category
            // vocabulary so the per-category presentation copy survives.
            throw CypherAirError.keyOperationUnavailable(category: error.failureCategory)
        }
        if let postProvisioningCheckpoint {
            await postProvisioningCheckpoint()
        }
        try provisioningInvalidationGate.checkValid(token)
        syncKeysAndSecureEnclaveRecoveryReport()
        return identity
    }

    // MARK: - Key Import

    /// Import a passphrase-protected secret key.
    /// Validates Argon2id memory requirements before import.
    ///
    /// Uses the unlocked private-key control domain for the SE access-control mode.
    func importKey(
        armoredData: Data,
        passphrase: String
    ) async throws -> PGPKeyIdentity {
        let token = provisioningInvalidationGate.makeToken()
        if let beforeAuthModeReadCheckpoint {
            await beforeAuthModeReadCheckpoint()
        }
        try Task.checkCancellation()
        try provisioningInvalidationGate.checkValid(token)
        let authMode = try privateKeyControlStore.requireUnlockedAuthMode()
        try Task.checkCancellation()
        try provisioningInvalidationGate.checkValid(token)
        return try await importKeyWithValidatedAuthMode(
            armoredData: armoredData,
            passphrase: passphrase,
            authMode: authMode,
            token: token
        )
    }

    private func importKeyWithValidatedAuthMode(
        armoredData: Data,
        passphrase: String,
        authMode: AuthenticationMode,
        token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        let identity = try await provisioningService.importKey(
            armoredData: armoredData,
            passphrase: passphrase,
            authMode: authMode,
            invalidationToken: token
        )
        if let postProvisioningCheckpoint {
            await postProvisioningCheckpoint()
        }
        try provisioningInvalidationGate.checkValid(token)
        syncKeysAndSecureEnclaveRecoveryReport()
        return identity
    }

    // MARK: - Key Export (Backup)

    /// Export a secret key protected with a passphrase for backup.
    /// Requires device authentication to access the SE-wrapped key.
    ///
    /// - Parameters:
    ///   - fingerprint: Fingerprint of the key to export.
    ///   - passphrase: User-provided passphrase for S2K protection.
    /// - Returns: ASCII-armored passphrase-protected secret key data.
    func exportKey(fingerprint: String, passphrase: String) async throws -> Data {
        let exported = try await exportService.exportKey(
            fingerprint: fingerprint,
            passphrase: passphrase,
            markBackedUp: true
        )
        syncKeysAndSecureEnclaveRecoveryReport()
        return exported
    }

    func exportKeyBackupData(fingerprint: String, passphrase: String) async throws -> Data {
        try await exportService.exportKey(
            fingerprint: fingerprint,
            passphrase: passphrase,
            markBackedUp: false
        )
    }

    func confirmKeyBackupExported(fingerprint: String) {
        catalogStore.markBackedUp(fingerprint: fingerprint)
        syncKeysAndSecureEnclaveRecoveryReport()
    }

    /// Export the key's revocation signature as an ASCII-armored signature.
    /// Fails closed with `revocationArtifactUnavailable` when no revocation artifact is
    /// stored for the key; no secret-key access or persistence side effect occurs.
    func exportRevocationCertificate(fingerprint: String) async throws -> Data {
        let armoredRevocation = try await exportService.exportRevocationCertificate(
            fingerprint: fingerprint
        )
        syncKeysAndSecureEnclaveRecoveryReport()
        return armoredRevocation
    }

    // MARK: - Selective Revocation Export (Subkey / User ID)

    /// Generate and armor a subkey-scoped revocation signature for an existing key.
    ///
    /// Selector validation happens against the stored public certificate *before* SE unwrap —
    /// an invalid `subkeySelection` throws `CypherAirError.invalidKeyData(...)` without
    /// triggering device authentication. Requires device authentication only when the
    /// selector matches the stored certificate.
    ///
    /// v1 policy: this operation is export-on-demand. It does not persist a new revocation
    /// artifact on `PGPKeyIdentity` or in the Keychain, and it does not mutate catalog state.
    ///
    /// - Parameters:
    ///   - fingerprint: Fingerprint of the key whose subkey is being revoked.
    ///   - subkeySelection: Selector-bearing option obtained from `selectionCatalog(fingerprint:)`.
    /// - Returns: ASCII-armored subkey revocation signature bytes.
    func exportSubkeyRevocationCertificate(
        fingerprint: String,
        subkeySelection: SubkeySelectionOption
    ) async throws -> Data {
        try await selectiveRevocationService.exportSubkeyRevocationCertificate(
            fingerprint: fingerprint,
            subkeySelection: subkeySelection
        )
    }

    /// Generate and armor a User ID-scoped revocation signature for an existing key.
    ///
    /// Selector validation happens against the stored public certificate *before* SE unwrap —
    /// an invalid `userIdSelection` throws `CypherAirError.invalidKeyData(...)` without
    /// triggering device authentication. Requires device authentication only when the
    /// selector matches the stored certificate.
    ///
    /// v1 policy: this operation is export-on-demand. It does not persist a new revocation
    /// artifact on `PGPKeyIdentity` or in the Keychain, and it does not mutate catalog state.
    ///
    /// - Parameters:
    ///   - fingerprint: Fingerprint of the key whose User ID is being revoked.
    ///   - userIdSelection: Selector-bearing option obtained from `selectionCatalog(fingerprint:)`.
    /// - Returns: ASCII-armored User ID revocation signature bytes.
    func exportUserIdRevocationCertificate(
        fingerprint: String,
        userIdSelection: UserIdSelectionOption
    ) async throws -> Data {
        try await selectiveRevocationService.exportUserIdRevocationCertificate(
            fingerprint: fingerprint,
            userIdSelection: userIdSelection
        )
    }

    // MARK: - Key Expiry Modification

    /// Modify the expiration time of an existing certificate.
    ///
    /// Software custody unwraps the SE-wrapped secret certificate using the unlocked
    /// private-key control domain. Secure Enclave custody uses the public-only
    /// external signer route and does not create a pending bundle or recovery journal.
    func modifyExpiry(
        fingerprint: String,
        newExpirySeconds: UInt64?
    ) async throws -> PGPKeyIdentity {
        defer {
            syncKeysAndSecureEnclaveRecoveryReport()
        }
        return try await mutationService.modifyExpiry(
            fingerprint: fingerprint,
            newExpirySeconds: newExpirySeconds
        )
    }

    /// Modify the expiration time of an existing certificate.
    ///
    /// SECURITY: Software custody needs the full certificate to re-sign binding
    /// signatures, then re-wraps and promotes the updated secret certificate through
    /// the pending-item recovery pattern. Secure Enclave custody keeps the secret key
    /// non-exportable and mutates only the public certificate via the external signer
    /// route, without pending software bundles or modify-expiry recovery journal entries.
    ///
    /// - Parameters:
    ///   - fingerprint: Fingerprint of the key to modify.
    ///   - newExpirySeconds: New expiry duration from now in seconds, or nil to remove expiry.
    ///   - authMode: Current authentication mode for SE key access control.
    /// - Returns: The updated key identity with new expiry information.
    func modifyExpiry(
        fingerprint: String,
        newExpirySeconds: UInt64?,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        defer {
            syncKeysAndSecureEnclaveRecoveryReport()
        }
        return try await mutationService.modifyExpiry(
            fingerprint: fingerprint,
            newExpirySeconds: newExpirySeconds,
            authMode: authMode
        )
    }

    // MARK: - Key Deletion

    /// Permanently delete a key and all of its Keychain items, including
    /// any pending migration bundles and related crash-recovery state.
    /// Keychain deletions are best-effort: `itemNotFound` is benign (idempotent delete),
    /// but other errors are collected and reported after all items are attempted.
    func deleteKey(fingerprint: String) throws {
        defer { syncKeysAndSecureEnclaveRecoveryReport() }
        try mutationService.deleteKey(fingerprint: fingerprint)
    }

    // MARK: - Default Key

    /// Set a key as the default signing/encryption identity.
    /// Persists the change to Keychain metadata so it survives cold restart.
    func setDefaultKey(fingerprint: String) throws {
        defer { syncKeysAndSecureEnclaveRecoveryReport() }
        try mutationService.setDefaultKey(fingerprint: fingerprint)
    }

    /// The current default key identity.
    var defaultKey: PGPKeyIdentity? {
        keys.first(where: \.isDefault)
    }

    // MARK: - Public Key Export

    /// Export the public key in ASCII-armored format for sharing.
    /// Does NOT require authentication (public key only).
    func exportPublicKey(fingerprint: String) throws -> Data {
        try exportService.exportPublicKey(fingerprint: fingerprint)
    }

    /// Discover selector-bearing subkey and User ID metadata for an existing key.
    /// This is a read-only operation that uses stored public key bytes only.
    func selectionCatalog(fingerprint: String) throws -> CertificateSelectionCatalog {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.keyMetadataUnavailable
        }

        let catalog = try certificateAdapter.validatedCatalog(
            certData: identity.publicKeyData,
            expectedFingerprint: identity.fingerprint
        )

        return catalog
    }

    /// Discover selector-bearing subkey and User ID metadata off the main actor.
    /// This is a read-only operation that uses stored public key bytes only.
    func loadSelectionCatalog(fingerprint: String) async throws -> CertificateSelectionCatalog {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.keyMetadataUnavailable
        }

        let catalog = try await Self.discoverSelectionCatalogOffMainActor(
            certificateAdapter: certificateAdapter,
            certData: identity.publicKeyData,
            expectedFingerprint: identity.fingerprint
        )

        return catalog
    }

    // MARK: - Crash Recovery

    /// Check for an interrupted modifyExpiry operation and recover.
    /// Call from the app's initialization path, after loadKeys().
    ///
    /// Recovery logic mirrors AuthenticationManager.checkAndRecoverFromInterruptedRewrap:
    /// - Old + pending both exist: interrupted before old deletion. Delete pending. Originals intact.
    /// - Only pending exists: interrupted after old deletion. Promote pending to permanent.
    /// - Neither exists: catastrophic loss. Clear flag. User must restore from backup.
    func checkAndRecoverFromInterruptedModifyExpiry() -> KeyMigrationRecoveryOutcome? {
        mutationService.checkAndRecoverFromInterruptedModifyExpiry()
    }

    /// Triggers device authentication (Face ID / Touch ID) and returns the unwrapped
    /// secret certificate material for the selected key.
    /// The caller MUST zeroize the returned data after use.
    func unwrapPrivateKey(fingerprint: String) async throws -> Data {
        try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
    }

    func makePrivateKeyOperationRouter(
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting,
        handleStore: SecureEnclaveCustodyHandleStore
    ) -> PrivateKeyOperationRouter {
        PrivateKeyOperationRouter(
            catalogStore: catalogStore,
            resolver: resolver,
            publicBindingInspector: publicBindingInspector,
            handleStore: handleStore,
            compositeBindingInspector: compositeCustodyRouterContext?.bindingInspector,
            compositeHandleStore: compositeCustodyRouterContext?.handleStore,
            compositeHighHandleStore: compositeCustodyRouterContext?.highHandleStore,
            compositeClassicalComponentStore: compositeCustodyRouterContext?.classicalComponentStore,
            custodyOperationAuthenticator: secureEnclaveCustodyOperationAuthenticator,
            authenticationPromptCoordinator: authenticationPromptCoordinator
        )
    }

    func configurePrivateKeyExpiryMutationService(_ service: any PrivateKeyExpiryMutationRouting) {
        mutationService.configureExpiryMutationService(service)
    }

    func configurePrivateKeySelectiveRevocationService(
        _ service: any PrivateKeySelectiveRevocationRouting
    ) {
        selectiveRevocationService.configureRevocationRoutingService(service)
    }

    @concurrent
    private static func discoverSelectionCatalogOffMainActor(
        certificateAdapter: PGPCertificateOperationAdapter,
        certData: Data,
        expectedFingerprint: String
    ) async throws -> CertificateSelectionCatalog {
        try certificateAdapter.validatedCatalog(
            certData: certData,
            expectedFingerprint: expectedFingerprint
        )
    }

    private func syncKeysAndSecureEnclaveRecoveryReport() {
        keys = catalogStore.keys
        guard let secureEnclaveCustodyRecoveryService else {
            secureEnclaveCustodyRecoveryReport = .empty
            return
        }
        secureEnclaveCustodyRecoveryReport = secureEnclaveCustodyRecoveryService.classify(
            identities: keys
        )
    }
}

extension KeyManagementService: ProtectedDataRelockParticipant {
    func relockProtectedData() async throws {
        provisioningInvalidationGate.invalidate()
        if let relockInvalidationCheckpoint {
            await relockInvalidationCheckpoint()
        }
        await provisioningCommitCoordinator.waitForActiveCommitsToFinish(
            waiterRegisteredCheckpoint: commitDrainWaiterRegisteredCheckpoint
        )
        markKeyMetadataLocked()
    }
}
