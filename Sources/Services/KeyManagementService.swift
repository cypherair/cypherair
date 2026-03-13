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

    private let jsonEncoder = JSONEncoder()
    private let jsonDecoder = JSONDecoder()

    init(
        engine: PgpEngine = PgpEngine(),
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        authenticator: any AuthenticationEvaluable
    ) {
        self.engine = engine
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.authenticator = authenticator
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
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: KeyProfile,
        authMode: AuthenticationMode
    ) throws -> PGPKeyIdentity {
        // Generate key pair via Rust engine
        var generated = try engine.generateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            profile: profile
        )
        defer {
            // Zeroize the raw secret key material
            generated.certData.resetBytes(in: 0..<generated.certData.count)
        }

        // Parse key info for metadata
        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)

        // Create access control for SE key
        let accessControl = try createAccessControl(mode: authMode)

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
            subkeyAlgo: keyInfo.subkeyAlgo
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
    func importKey(
        armoredData: Data,
        passphrase: String,
        authMode: AuthenticationMode
    ) throws -> PGPKeyIdentity {
        // Check Argon2id memory requirements before import
        let s2kInfo = try engine.parseS2kParams(armoredData: armoredData)
        let memoryGuard = Argon2idMemoryGuard()
        try memoryGuard.validate(s2kInfo: s2kInfo)

        // Import (decrypt) the secret key
        var secretKeyData = try engine.importSecretKey(
            armoredData: armoredData,
            passphrase: passphrase
        )
        defer {
            // Zeroize the raw secret key material
            secretKeyData.resetBytes(in: 0..<secretKeyData.count)
        }

        // Parse key info
        let keyInfo = try engine.parseKeyInfo(keyData: secretKeyData)
        let profile = try engine.detectProfile(certData: secretKeyData)

        // Extract public key before SE wrapping (needs certData)
        let publicKeyData = try engine.armorPublicKey(certData: secretKeyData)

        // SE-wrap the imported key
        let accessControl = try createAccessControl(mode: authMode)
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
            isExpired: false,
            isDefault: keys.isEmpty,
            isBackedUp: false,
            publicKeyData: publicKeyData,
            revocationCert: Data(),
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo
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
    func exportKey(fingerprint: String, passphrase: String) throws -> Data {
        var secretKey = try unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        guard let identity = keys.first(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.noMatchingKey
        }

        let exported = try engine.exportSecretKey(
            certData: secretKey,
            passphrase: passphrase,
            profile: identity.profile
        )

        // Mark as backed up and persist metadata change
        if let index = keys.firstIndex(where: { $0.fingerprint == fingerprint }) {
            keys[index].isBackedUp = true
            try? updateMetadata(keys[index])
        }

        return exported
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
    func setDefaultKey(fingerprint: String) {
        for i in keys.indices {
            keys[i].isDefault = (keys[i].fingerprint == fingerprint)
        }
    }

    /// The current default key identity.
    var defaultKey: PGPKeyIdentity? {
        keys.first(where: { $0.isDefault })
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

    // MARK: - Access Control

    private func createAccessControl(mode: AuthenticationMode) throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = switch mode {
        case .standard:
            [.privateKeyUsage, .biometryAny, .or, .devicePasscode]
        case .highSecurity:
            [.privateKeyUsage, .biometryAny]
        }

        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            throw CypherAirError.secureEnclaveUnavailable
        }

        return accessControl
    }
}
