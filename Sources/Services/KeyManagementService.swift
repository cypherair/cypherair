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

    private let jsonEncoder = JSONEncoder()
    private let jsonDecoder = JSONDecoder()

    init(
        engine: PgpEngine,
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        authenticator: any AuthenticationEvaluable,
        memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo()
    ) {
        self.engine = engine
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.authenticator = authenticator
        self.memoryInfo = memoryInfo
    }

    // MARK: - Key Enumeration

    /// Load all key identities from Keychain metadata items.
    /// Called on cold launch — does NOT require SE authentication.
    func loadKeys() throws {
        let metadataServices = try keychain.listItems(
            servicePrefix: KeychainConstants.metadataPrefix,
            account: KeychainConstants.defaultAccount
        )

        var loadedKeys: [PGPKeyIdentity] = []
        for service in metadataServices {
            do {
                let data = try keychain.load(
                    service: service,
                    account: KeychainConstants.defaultAccount
                )
                let identity = try jsonDecoder.decode(PGPKeyIdentity.self, from: data)
                loadedKeys.append(identity)
            } catch {
                // Skip corrupted metadata items silently
                continue
            }
        }

        keys = loadedKeys
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
    @concurrent
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: KeyProfile,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        // PGP engine calls — off main thread via @concurrent helper
        var (generated, keyInfo) = try await generateKeyOffMainActor(
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
        try saveWrappedKeyBundle(bundle, fingerprint: fp)

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
            try saveMetadata(identity)
        } catch {
            rollbackKeychainBundle(fingerprint: fp)
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
    @concurrent
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

        // Heavy engine calls — off main thread via @concurrent helper
        var (secretKeyData, keyInfo, profile, publicKeyData) = try await importKeyOffMainActor(
            armoredData: armoredData, passphrase: passphrase
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
        try saveWrappedKeyBundle(bundle, fingerprint: fp)

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
            try saveMetadata(identity)
        } catch {
            rollbackKeychainBundle(fingerprint: fp)
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
    @concurrent
    func exportKey(fingerprint: String, passphrase: String) async throws -> Data {
        var secretKey = try unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        guard let identity = keys.first(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.noMatchingKey
        }

        // S2K protection — off main thread via @concurrent helper
        let exported = try await exportKeyOffMainActor(
            certData: secretKey, passphrase: passphrase, profile: identity.profile
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
            try? updateMetadata(keys[index])
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
    @concurrent
    func modifyExpiry(
        fingerprint: String,
        newExpirySeconds: UInt64?,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        // 1. Unwrap private key (triggers Face ID / Touch ID)
        var secretKey = try unwrapPrivateKey(fingerprint: fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }

        // 2. Modify expiry — off main thread via @concurrent helper
        var result = try await modifyExpiryOffMainActor(
            certData: secretKey, newExpirySeconds: newExpirySeconds
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
            try savePendingKeyBundle(bundle, fingerprint: fingerprint)
        } catch {
            cleanupPendingItems(fingerprint: fingerprint)
            throw error
        }

        // 5. Verify all pending items stored successfully.
        do {
            _ = try keychain.load(
                service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount)
            _ = try keychain.load(
                service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount)
            _ = try keychain.load(
                service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount)
        } catch {
            cleanupPendingItems(fingerprint: fingerprint)
            throw error
        }

        // 6. Set crash recovery flag before entering the danger zone.
        // If the app crashes between here and the flag-clear below,
        // checkAndRecoverFromInterruptedModifyExpiry() runs on next launch.
        UserDefaults.standard.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.set(fingerprint, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        // 7. Delete old permanent items. Pending items are confirmed stored.
        rollbackKeychainBundle(fingerprint: fingerprint)

        // 8. Promote pending → permanent.
        do {
            try promotePendingToPermanent(fingerprint: fingerprint)
        } catch {
            // If promotion fails, pending items remain. They are the only copy.
            // Leave the flag set so crash recovery can handle it on next launch.
            throw error
        }

        // 9. Clear crash recovery flag — danger zone complete.
        UserDefaults.standard.set(false, forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)

        // 10. Update identity metadata
        var updated = existingIdentity
        updated.isExpired = result.keyInfo.isExpired
        updated.publicKeyData = result.publicKeyData
        updated.expiryDate = result.keyInfo.expiryTimestamp.map {
            Date(timeIntervalSince1970: TimeInterval($0))
        }

        // 11. Persist metadata and update in-memory state
        try updateMetadata(updated)
        keys[index] = updated

        return updated
    }

    // MARK: - Key Deletion

    /// Permanently delete a key and all its Keychain items.
    /// Keychain deletions are best-effort: `itemNotFound` is benign (idempotent delete),
    /// but other errors are collected and reported after all items are attempted.
    func deleteKey(fingerprint: String) throws {
        let services = [
            KeychainConstants.seKeyService(fingerprint: fingerprint),
            KeychainConstants.saltService(fingerprint: fingerprint),
            KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            KeychainConstants.metadataService(fingerprint: fingerprint)
        ]

        var deletionErrors: [Error] = []
        for service in services {
            do {
                try keychain.delete(service: service, account: KeychainConstants.defaultAccount)
            } catch KeychainError.itemNotFound {
                // Benign: item already absent. Continue.
            } catch {
                deletionErrors.append(error)
            }
        }

        // Always update in-memory state (the key is logically deleted).
        keys.removeAll { $0.fingerprint == fingerprint }

        // If the deleted key was default, assign a new default
        if !keys.isEmpty && !keys.contains(where: { $0.isDefault }) {
            keys[0].isDefault = true
            // Persist the promoted default so it survives cold restart.
            // try? because key deletion already succeeded — failing to persist
            // the new default only affects the next cold launch (user sees no default).
            try? updateMetadata(keys[0])
        }

        // Report partial deletion failure to the caller.
        if let firstError = deletionErrors.first {
            throw CypherAirError.keychainError(
                "Partial key deletion: \(deletionErrors.count) item(s) could not be removed — \(firstError.localizedDescription)"
            )
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
            try updateMetadata(keys[i])
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
    func checkAndRecoverFromInterruptedModifyExpiry() {
        let defaults = UserDefaults.standard
        guard defaults.bool(forKey: AuthPreferences.modifyExpiryInProgressKey) else {
            return
        }

        guard let fingerprint = defaults.string(forKey: AuthPreferences.modifyExpiryFingerprintKey),
              !fingerprint.isEmpty else {
            // No fingerprint recorded — cannot recover. Clear flag.
            defaults.set(false, forKey: AuthPreferences.modifyExpiryInProgressKey)
            defaults.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)
            return
        }

        let account = KeychainConstants.defaultAccount
        let oldExists = keychain.exists(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account
        )
        let pendingExists = keychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account
        )

        if oldExists && pendingExists {
            // Case 1: Interrupted before old items deleted.
            // Delete temporary items. Original keys are intact.
            cleanupPendingItems(fingerprint: fingerprint)

        } else if !oldExists && pendingExists {
            // Case 2: Interrupted after old deletion but before promotion.
            // Verify all 3 pending items exist before attempting promotion.
            let pendingSaltExists = keychain.exists(
                service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
                account: account
            )
            let pendingSealedExists = keychain.exists(
                service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
                account: account
            )

            if pendingSaltExists && pendingSealedExists {
                // All 3 pending items present — safe to promote.
                try? promotePendingToPermanent(fingerprint: fingerprint)
            }
            // else: Incomplete pending set — catastrophic partial write.
            // Cannot promote. User must restore from backup.
        }
        // Case 3: Neither exists — catastrophic loss. Nothing we can do.

        // Always clear the flags after recovery attempt.
        defaults.set(false, forKey: AuthPreferences.modifyExpiryInProgressKey)
        defaults.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)
    }

    // MARK: - Off-Main-Actor Engine Helpers

    /// Run key generation on the cooperative thread pool.
    /// Error wrapping (Issue 2) lives here so PgpError never escapes.
    @concurrent
    private func generateKeyOffMainActor(
        name: String, email: String?,
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

    /// Run key import + parsing on the cooperative thread pool.
    /// Includes importSecretKey (Argon2id ~3s for Profile B), parseKeyInfo,
    /// detectProfile, and armorPublicKey.
    @concurrent
    private func importKeyOffMainActor(
        armoredData: Data, passphrase: String
    ) async throws -> (secretKeyData: Data, keyInfo: KeyInfo, profile: KeyProfile, publicKeyData: Data) {
        do {
            let secretKeyData = try engine.importSecretKey(
                armoredData: armoredData,
                passphrase: passphrase
            )
            let keyInfo = try engine.parseKeyInfo(keyData: secretKeyData)
            let profile = try engine.detectProfile(certData: secretKeyData)
            let publicKeyData = try engine.armorPublicKey(certData: secretKeyData)
            return (secretKeyData, keyInfo, profile, publicKeyData)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }
    }

    /// Run secret key export (S2K protection) on the cooperative thread pool.
    @concurrent
    private func exportKeyOffMainActor(
        certData: Data, passphrase: String, profile: KeyProfile
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

    /// Run expiry modification on the cooperative thread pool.
    @concurrent
    private func modifyExpiryOffMainActor(
        certData: Data, newExpirySeconds: UInt64?
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
        let seKeyData = try keychain.load(
            service: KeychainConstants.seKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount)
        let salt = try keychain.load(
            service: KeychainConstants.saltService(fingerprint: fp),
            account: KeychainConstants.defaultAccount)
        let sealedBox = try keychain.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount)

        let handle = try secureEnclave.reconstructKey(from: seKeyData)
        let bundle = WrappedKeyBundle(seKeyData: seKeyData, salt: salt, sealedBox: sealedBox)
        return try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fp)
    }

    // MARK: - Keychain Bundle Helpers

    /// Save the three SE-wrapped key items to Keychain.
    /// If any write fails, rolls back the ones that succeeded.
    private func saveWrappedKeyBundle(_ bundle: WrappedKeyBundle, fingerprint: String) throws {
        do {
            try keychain.save(
                bundle.seKeyData,
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            throw error
        }

        do {
            try keychain.save(
                bundle.salt,
                service: KeychainConstants.saltService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            try? keychain.delete(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )
            throw error
        }

        do {
            try keychain.save(
                bundle.sealedBox,
                service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            try? keychain.delete(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )
            try? keychain.delete(
                service: KeychainConstants.saltService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )
            throw error
        }
    }

    /// Save the three SE-wrapped key items under PENDING Keychain names.
    /// If any write fails, rolls back the ones that succeeded.
    private func savePendingKeyBundle(_ bundle: WrappedKeyBundle, fingerprint: String) throws {
        do {
            try keychain.save(
                bundle.seKeyData,
                service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            throw error
        }

        do {
            try keychain.save(
                bundle.salt,
                service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            try? keychain.delete(
                service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )
            throw error
        }

        do {
            try keychain.save(
                bundle.sealedBox,
                service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            try? keychain.delete(
                service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )
            try? keychain.delete(
                service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )
            throw error
        }
    }

    /// Promote pending Keychain items to permanent names for one identity.
    /// Sequence: load all pending → save as permanent → delete pending.
    ///
    /// - Note: `AuthenticationManager.promoteFromPending` is a parallel implementation
    ///   of the same pending→permanent promotion pattern for auth mode switching.
    ///   They are kept separate to avoid a circular dependency between KMS and AuthManager.
    ///   If the promotion logic changes, update both implementations.
    private func promotePendingToPermanent(fingerprint: String) throws {
        let account = KeychainConstants.defaultAccount

        // Load all 3 pending items first.
        let seKeyData = try keychain.load(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account
        )
        let saltData = try keychain.load(
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account
        )
        let sealedData = try keychain.load(
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account
        )

        // Save under permanent names, rolling back on partial failure.
        var savedPermanentServices: [String] = []

        do {
            try keychain.save(
                seKeyData,
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: account,
                accessControl: nil
            )
            savedPermanentServices.append(KeychainConstants.seKeyService(fingerprint: fingerprint))

            try keychain.save(
                saltData,
                service: KeychainConstants.saltService(fingerprint: fingerprint),
                account: account,
                accessControl: nil
            )
            savedPermanentServices.append(KeychainConstants.saltService(fingerprint: fingerprint))

            try keychain.save(
                sealedData,
                service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
                account: account,
                accessControl: nil
            )
        } catch {
            for service in savedPermanentServices {
                try? keychain.delete(service: service, account: account)
            }
            throw error
        }

        // All 3 permanent items saved. Delete pending items.
        try? keychain.delete(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account
        )
        try? keychain.delete(
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account
        )
        try? keychain.delete(
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account
        )
    }

    /// Best-effort cleanup of pending Keychain items for one identity.
    private func cleanupPendingItems(fingerprint: String) {
        let account = KeychainConstants.defaultAccount
        try? keychain.delete(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account
        )
        try? keychain.delete(
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account
        )
        try? keychain.delete(
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account
        )
    }

    /// Best-effort rollback: remove all three SE bundle items from Keychain.
    private func rollbackKeychainBundle(fingerprint: String) {
        try? keychain.delete(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
        try? keychain.delete(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
        try? keychain.delete(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
    }

    // MARK: - Metadata Persistence

    /// Save key identity metadata to Keychain (no sensitive data).
    /// Used for cold-launch key enumeration.
    private func saveMetadata(_ identity: PGPKeyIdentity) throws {
        let data = try jsonEncoder.encode(identity)
        try keychain.save(
            data,
            service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
    }

    /// Update existing metadata (delete + re-save).
    /// Used when mutable properties like isBackedUp change.
    private func updateMetadata(_ identity: PGPKeyIdentity) throws {
        do {
            try keychain.delete(
                service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
                account: KeychainConstants.defaultAccount
            )
        } catch KeychainError.itemNotFound {
            // Benign: first-time save, nothing to delete.
        }
        try saveMetadata(identity)
    }


}
