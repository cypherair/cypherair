import Foundation
import Security

/// Manages the full key lifecycle: generation, import, export, deletion, and default selection.
/// Coordinates PgpEngine (Rust) for crypto operations and Security layer for SE wrapping/Keychain storage.
///
/// All private key material is SE-wrapped before storage and zeroized from memory after use.
@Observable
final class KeyManagementService {

    /// All key identities stored on this device.
    private(set) var keys: [PGPKeyIdentity] = []

    private let engine: PgpEngine
    private let secureEnclave: any SecureEnclaveManageable
    private let keychain: any KeychainManageable
    private let authenticator: any AuthenticationEvaluable
    private let memoryInfo: any MemoryInfoProvidable
    private let defaults: UserDefaults
    private let bundleStore: KeyBundleStore
    private let metadataStore: KeyMetadataStore
    private let migrationCoordinator: KeyMigrationCoordinator

    init(
        engine: PgpEngine,
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        authenticator: any AuthenticationEvaluable,
        memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo(),
        defaults: UserDefaults = .standard
    ) {
        self.engine = engine
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.authenticator = authenticator
        self.memoryInfo = memoryInfo
        self.defaults = defaults
        let bundleStore = KeyBundleStore(keychain: keychain)
        self.bundleStore = bundleStore
        self.metadataStore = KeyMetadataStore(keychain: keychain)
        self.migrationCoordinator = KeyMigrationCoordinator(bundleStore: bundleStore)
    }

    // MARK: - Key Enumeration

    /// Load all key identities from Keychain metadata items.
    /// Called on cold launch — does NOT require SE authentication.
    func loadKeys() throws {
        keys = try metadataStore.loadAll()
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
        // PGP engine calls — off main thread via @concurrent static helper
        var (generated, keyInfo) = try await Self.generateKeyOffMainActor(
            engine: engine,
            name: name, email: email,
            expirySeconds: expirySeconds, profile: profile
        )
        defer {
            // Zeroize the raw secret key material
            generated.certData.resetBytes(in: 0..<generated.certData.count)
        }

        // Create access control for SE key
        let accessControl = try authMode.createAccessControl()

        // SE-wrap the private key (certData contains public+secret)
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        let bundle = try secureEnclave.wrap(
            privateKey: generated.certData,
            using: seHandle,
            fingerprint: keyInfo.fingerprint
        )

        // Store all three Keychain items atomically (rollback on partial failure).
        let fp = keyInfo.fingerprint
        try bundleStore.saveBundle(bundle, fingerprint: fp)

        let identity = PGPKeyIdentity(
            fingerprint: keyInfo.fingerprint,
            keyVersion: keyInfo.keyVersion,
            profile: profile,
            userId: keyInfo.userId,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            isRevoked: false,
            isExpired: false,
            isDefault: keys.isEmpty,
            isBackedUp: false,
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo,
            expiryDate: keyInfo.expiryTimestamp.map {
                Date(timeIntervalSince1970: TimeInterval($0))
            }
        )

        // Persist metadata for cold-launch enumeration.
        // If metadata save fails, roll back the SE bundle too.
        do {
            try metadataStore.save(identity)
        } catch {
            bundleStore.rollbackPermanentBundle(fingerprint: fp)
            throw error
        }

        keys.append(identity)

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
        // Check Argon2id memory requirements before import (fast, <1ms — stays on main actor)
        let s2kInfo: S2kInfo
        do {
            s2kInfo = try engine.parseS2kParams(armoredData: armoredData)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: memoryInfo)
        try memoryGuard.validate(s2kInfo: s2kInfo)

        // Heavy engine calls — off main thread via @concurrent static helper
        var (secretKeyData, keyInfo, profile, publicKeyData) = try await Self.importKeyOffMainActor(
            engine: engine, armoredData: armoredData, passphrase: passphrase
        )
        defer {
            // Zeroize the raw secret key material
            secretKeyData.resetBytes(in: 0..<secretKeyData.count)
        }

        // Guard against duplicate import: check before SE wrapping
        // to avoid creating an orphaned SE key on Keychain duplicateItem failure.
        if keys.contains(where: { $0.fingerprint == keyInfo.fingerprint }) {
            throw CypherAirError.duplicateKey
        }

        // SE-wrap the imported key
        let accessControl = try authMode.createAccessControl()
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        let bundle = try secureEnclave.wrap(
            privateKey: secretKeyData,
            using: seHandle,
            fingerprint: keyInfo.fingerprint
        )

        // Store all three Keychain items atomically (rollback on partial failure).
        let fp = keyInfo.fingerprint
        try bundleStore.saveBundle(bundle, fingerprint: fp)

        let identity = PGPKeyIdentity(
            fingerprint: keyInfo.fingerprint,
            keyVersion: keyInfo.keyVersion,
            profile: profile,
            userId: keyInfo.userId,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            isRevoked: false,
            isExpired: keyInfo.isExpired,
            isDefault: keys.isEmpty,
            isBackedUp: false,
            publicKeyData: publicKeyData,
            revocationCert: Data(),
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo,
            expiryDate: keyInfo.expiryTimestamp.map {
                Date(timeIntervalSince1970: TimeInterval($0))
            }
        )

        // Persist metadata for cold-launch enumeration.
        // If metadata save fails, roll back the SE bundle too.
        do {
            try metadataStore.save(identity)
        } catch {
            bundleStore.rollbackPermanentBundle(fingerprint: fp)
            throw error
        }

        keys.append(identity)

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
        var secretKey = try unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        guard let identity = keys.first(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.noMatchingKey
        }

        // S2K protection — off main thread via @concurrent static helper
        let exported = try await Self.exportKeyOffMainActor(
            engine: engine, certData: secretKey, passphrase: passphrase, profile: identity.profile
        )

        // Mark as backed up and persist metadata change.
        // try? rationale: The export operation above already succeeded — the user
        // has their backup. In-memory isBackedUp is correct for the current session.
        // If the app crashes before the next metadata write, isBackedUp resets to false
        // on cold launch — this is conservative and safe (triggers an unnecessary backup
        // reminder rather than data loss). A throwing failure here should not invalidate
        // the successful export.
        if let index = keys.firstIndex(where: { $0.fingerprint == fingerprint }) {
            keys[index].isBackedUp = true
            try? metadataStore.update(keys[index])
        }

        return exported
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
        // 1. Unwrap private key (triggers Face ID / Touch ID)
        var secretKey = try unwrapPrivateKey(fingerprint: fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }

        // 2. Modify expiry — off main thread via @concurrent static helper
        var result = try await Self.modifyExpiryOffMainActor(
            engine: engine, certData: secretKey, newExpirySeconds: newExpirySeconds
        )
        defer { result.certData.resetBytes(in: 0..<result.certData.count) }

        // 3. Look up existing identity
        guard let index = keys.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.noMatchingKey
        }
        let existingIdentity = keys[index]

        // 4. Re-wrap updated cert with SE and store under PENDING names.
        // If anything fails here, old items are intact — clean up pending and abort.
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

        // 5. Verify all pending items stored successfully.
        do {
            _ = try bundleStore.loadBundle(
                fingerprint: fingerprint,
                namespace: .pending
            )
        } catch {
            bundleStore.cleanupPendingBundle(fingerprint: fingerprint)
            throw error
        }

        // 6. Set crash recovery flag before entering the danger zone.
        // If the app crashes between here and the flag-clear below,
        // checkAndRecoverFromInterruptedModifyExpiry() runs on next launch.
        defaults.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        defaults.set(fingerprint, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        // 7. Delete old permanent items. Pending items are confirmed stored.
        do {
            try bundleStore.deleteBundle(fingerprint: fingerprint)
        } catch {
            // Pending items remain. Leave the crash-recovery flag set.
            throw error
        }

        // 8. Promote pending → permanent.
        do {
            try bundleStore.promotePendingToPermanent(fingerprint: fingerprint)
        } catch {
            // If promotion fails, pending items remain. They are the only copy.
            // Leave the flag set so crash recovery can handle it on next launch.
            throw error
        }

        // 9. Clear crash recovery flag — danger zone complete.
        defaults.set(false, forKey: AuthPreferences.modifyExpiryInProgressKey)
        defaults.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)

        // 10. Update identity metadata
        var updated = existingIdentity
        updated.isExpired = result.keyInfo.isExpired
        updated.publicKeyData = result.publicKeyData
        updated.expiryDate = result.keyInfo.expiryTimestamp.map {
            Date(timeIntervalSince1970: TimeInterval($0))
        }

        // 11. Persist metadata and update in-memory state
        try metadataStore.update(updated)
        keys[index] = updated

        return updated
    }

    // MARK: - Key Deletion

    /// Permanently delete a key and all of its Keychain items, including
    /// any pending migration bundles and related crash-recovery state.
    /// Keychain deletions are best-effort: `itemNotFound` is benign (idempotent delete),
    /// but other errors are collected and reported after all items are attempted.
    func deleteKey(fingerprint: String) throws {
        let deletionErrors = deleteAllKeychainMaterial(for: fingerprint)

        // Always update in-memory state (the key is logically deleted).
        keys.removeAll { $0.fingerprint == fingerprint }
        clearRecoveryStateIfNeeded(afterDeleting: fingerprint)

        // If the deleted key was default, assign a new default
        if !keys.isEmpty && !keys.contains(where: { $0.isDefault }) {
            keys[0].isDefault = true
            // Persist the promoted default so it survives cold restart.
            // try? because key deletion already succeeded — failing to persist
            // the new default only affects the next cold launch (user sees no default).
            try? metadataStore.update(keys[0])
        }

        // Report partial deletion failure to the caller.
        if let firstError = deletionErrors.first {
            throw CypherAirError.keychainError(
                "Partial key deletion: \(deletionErrors.count) item(s) could not be removed — \(firstError.localizedDescription)"
            )
        }
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
           keys.isEmpty {
            defaults.set(false, forKey: AuthPreferences.rewrapInProgressKey)
            defaults.removeObject(forKey: AuthPreferences.rewrapTargetModeKey)
        }
    }

    // MARK: - Default Key

    /// Set a key as the default signing/encryption identity.
    /// Persists the change to Keychain metadata so it survives cold restart.
    func setDefaultKey(fingerprint: String) throws {
        var changedIndices: [Int] = []
        for i in keys.indices {
            let newDefault = (keys[i].fingerprint == fingerprint)
            if keys[i].isDefault != newDefault {
                keys[i].isDefault = newDefault
                changedIndices.append(i)
            }
        }
        for i in changedIndices {
            try metadataStore.update(keys[i])
        }
    }

    /// The current default key identity.
    var defaultKey: PGPKeyIdentity? {
        keys.first(where: { $0.isDefault })
    }

    // MARK: - Public Key Export

    /// Export the public key in ASCII-armored format for sharing.
    /// Does NOT require authentication (public key only).
    func exportPublicKey(fingerprint: String) throws -> Data {
        guard let identity = keys.first(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.noMatchingKey
        }
        do {
            return try engine.armorPublicKey(certData: identity.publicKeyData)
        } catch {
            throw CypherAirError.from(error) { .armorError(reason: $0) }
        }
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
        guard defaults.bool(forKey: AuthPreferences.modifyExpiryInProgressKey) else {
            return nil
        }

        guard let fingerprint = defaults.string(forKey: AuthPreferences.modifyExpiryFingerprintKey),
              !fingerprint.isEmpty else {
            // No fingerprint recorded — cannot recover. Clear flag.
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

    // MARK: - Off-Main-Actor Engine Helpers

    /// Run key generation off the main actor.
    /// Error wrapping (Issue 2) lives here so PgpError never escapes.
    @concurrent
    private static func generateKeyOffMainActor(
        engine: PgpEngine, name: String, email: String?,
        expirySeconds: UInt64?, profile: KeyProfile
    ) async throws -> (GeneratedKey, KeyInfo) {
        do {
            let generated = try engine.generateKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                profile: profile
            )
            let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
            return (generated, keyInfo)
        } catch {
            throw CypherAirError.from(error) { .keyGenerationFailed(reason: $0) }
        }
    }

    /// Run key import + parsing off the main actor.
    /// Includes importSecretKey (Argon2id ~3s for Profile B), parseKeyInfo,
    /// detectProfile, and public key extraction (binary format).
    @concurrent
    private static func importKeyOffMainActor(
        engine: PgpEngine, armoredData: Data, passphrase: String
    ) async throws -> (secretKeyData: Data, keyInfo: KeyInfo, profile: KeyProfile, publicKeyData: Data) {
        do {
            let secretKeyData = try engine.importSecretKey(
                armoredData: armoredData,
                passphrase: passphrase
            )
            let keyInfo = try engine.parseKeyInfo(keyData: secretKeyData)
            let profile = try engine.detectProfile(certData: secretKeyData)
            // Extract binary public key: armor strips secret material, dearmor converts back to binary.
            // This ensures publicKeyData is binary OpenPGP format, consistent with key generation path.
            let armoredPubKey = try engine.armorPublicKey(certData: secretKeyData)
            let publicKeyData = try engine.dearmor(armored: armoredPubKey)
            return (secretKeyData, keyInfo, profile, publicKeyData)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }
    }

    /// Run secret key export (S2K protection) off the main actor.
    @concurrent
    private static func exportKeyOffMainActor(
        engine: PgpEngine, certData: Data, passphrase: String, profile: KeyProfile
    ) async throws -> Data {
        do {
            return try engine.exportSecretKey(
                certData: certData,
                passphrase: passphrase,
                profile: profile
            )
        } catch {
            throw CypherAirError.from(error) { .s2kError(reason: $0) }
        }
    }

    /// Run expiry modification off the main actor.
    @concurrent
    private static func modifyExpiryOffMainActor(
        engine: PgpEngine, certData: Data, newExpirySeconds: UInt64?
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

    // MARK: - Private Key Access (SE Unwrap)

    /// Unwrap a private key from SE for use in crypto operations.
    /// Triggers device authentication (Face ID / Touch ID).
    /// The caller MUST zeroize the returned data after use.
    func unwrapPrivateKey(fingerprint: String) throws -> Data {
        let fp = fingerprint
        let bundle = try bundleStore.loadBundle(fingerprint: fp)
        let handle = try secureEnclave.reconstructKey(from: bundle.seKeyData)
        return try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fp)
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
