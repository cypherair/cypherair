import Foundation

/// Manages the full key lifecycle: generation, import, export, deletion, and default selection.
/// Coordinates PgpEngine (Rust) for crypto operations and Security layer for SE wrapping/Keychain storage.
///
/// All private key material is SE-wrapped before storage and zeroized from memory after use.
@Observable
final class KeyManagementService {

    /// All key identities stored on this device.
    private(set) var keys: [PGPKeyIdentity] = []

    private let engine: PgpEngine
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService
    private let provisioningService: KeyProvisioningService
    private let exportService: KeyExportService
    private let mutationService: KeyMutationService

    init(
        engine: PgpEngine,
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        authenticator: any AuthenticationEvaluable,
        memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo(),
        defaults: UserDefaults = .standard
    ) {
        let bundleStore = KeyBundleStore(keychain: keychain)
        let metadataStore = KeyMetadataStore(keychain: keychain)
        let migrationCoordinator = KeyMigrationCoordinator(bundleStore: bundleStore)
        let catalogStore = KeyCatalogStore(metadataStore: metadataStore)
        let privateKeyAccessService = PrivateKeyAccessService(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore
        )

        self.engine = engine
        self.catalogStore = catalogStore
        self.privateKeyAccessService = privateKeyAccessService
        self.provisioningService = KeyProvisioningService(
            engine: engine,
            secureEnclave: secureEnclave,
            memoryInfo: memoryInfo,
            bundleStore: bundleStore,
            catalogStore: catalogStore
        )
        self.exportService = KeyExportService(
            engine: engine,
            catalogStore: catalogStore,
            privateKeyAccessService: privateKeyAccessService
        )
        self.mutationService = KeyMutationService(
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults,
            bundleStore: bundleStore,
            migrationCoordinator: migrationCoordinator,
            catalogStore: catalogStore,
            privateKeyAccessService: privateKeyAccessService
        )
    }

    // MARK: - Key Enumeration

    /// Load all key identities from Keychain metadata items.
    /// Called on cold launch — does NOT require SE authentication.
    func loadKeys() throws {
        try catalogStore.loadAll()
        syncKeys()
    }

    // MARK: - Key Generation

    /// Generate a new key pair with the specified profile.
    /// The private key is immediately SE-wrapped and stored in Keychain.
    ///
    /// - Parameters:
    ///   - name: User's name (required).
    ///   - email: User's email (optional).
    ///   - expirySeconds: Key validity duration in seconds (nil = default 2 years).
    ///   - profile: Encryption profile (.universal or .advanced).
    ///   - authMode: Current authentication mode for SE key access control.
    /// - Returns: The newly created key identity.
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: KeyProfile,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        let identity = try await provisioningService.generateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            profile: profile,
            authMode: authMode
        )
        syncKeys()
        return identity
    }

    // MARK: - Key Import

    /// Import a passphrase-protected secret key.
    /// Validates Argon2id memory requirements before import.
    ///
    /// - Parameters:
    ///   - armoredData: The ASCII-armored secret key data.
    ///   - passphrase: The passphrase protecting the key.
    ///   - authMode: Current authentication mode for SE key access control.
    /// - Returns: The imported key identity.
    func importKey(
        armoredData: Data,
        passphrase: String,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        let identity = try await provisioningService.importKey(
            armoredData: armoredData,
            passphrase: passphrase,
            authMode: authMode
        )
        syncKeys()
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
            passphrase: passphrase
        )
        syncKeys()
        return exported
    }

    /// Export the key's revocation signature as an ASCII-armored signature.
    /// If the key predates revocation-construction support, this lazily backfills
    /// the binary revocation signature, persists it, and then exports the armored form.
    func exportRevocationCertificate(fingerprint: String) async throws -> Data {
        let armoredRevocation = try await exportService.exportRevocationCertificate(
            fingerprint: fingerprint
        )
        syncKeys()
        return armoredRevocation
    }

    // MARK: - Key Expiry Modification

    /// Modify the expiration time of an existing certificate.
    /// Requires device authentication to access the SE-wrapped private key.
    ///
    /// SECURITY: The full certificate (with secret key) is needed to re-sign binding signatures.
    /// After modification, the updated cert is re-wrapped with a new SE key and stored.
    /// Uses the pending-item pattern to prevent key loss on crash: new items are stored
    /// under temporary names before old items are deleted.
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
        let updated = try await mutationService.modifyExpiry(
            fingerprint: fingerprint,
            newExpirySeconds: newExpirySeconds,
            authMode: authMode
        )
        syncKeys()
        return updated
    }

    // MARK: - Key Deletion

    /// Permanently delete a key and all of its Keychain items, including
    /// any pending migration bundles and related crash-recovery state.
    /// Keychain deletions are best-effort: `itemNotFound` is benign (idempotent delete),
    /// but other errors are collected and reported after all items are attempted.
    func deleteKey(fingerprint: String) throws {
        defer { syncKeys() }
        try mutationService.deleteKey(fingerprint: fingerprint)
    }

    // MARK: - Default Key

    /// Set a key as the default signing/encryption identity.
    /// Persists the change to Keychain metadata so it survives cold restart.
    func setDefaultKey(fingerprint: String) throws {
        defer { syncKeys() }
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
            throw CypherAirError.noMatchingKey
        }

        let discovered: DiscoveredCertificateSelectors
        do {
            discovered = try engine.discoverCertificateSelectors(certData: identity.publicKeyData)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }

        guard discovered.certificateFingerprint == identity.fingerprint else {
            throw CypherAirError.invalidKeyData(
                reason: "Stored key metadata fingerprint does not match certificate data"
            )
        }

        return CertificateSelectionCatalogMapper.map(discovered)
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
    func unwrapPrivateKey(fingerprint: String) throws -> Data {
        try privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
    }

    private func syncKeys() {
        keys = catalogStore.keys
    }
}
