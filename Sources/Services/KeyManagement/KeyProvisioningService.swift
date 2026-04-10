import Foundation

/// Owns key generation and import workflows behind the key-management facade.
final class KeyProvisioningService {
    private let engine: PgpEngine
    private let secureEnclave: any SecureEnclaveManageable
    private let memoryInfo: any MemoryInfoProvidable
    private let bundleStore: KeyBundleStore
    private let catalogStore: KeyCatalogStore

    init(
        engine: PgpEngine,
        secureEnclave: any SecureEnclaveManageable,
        memoryInfo: any MemoryInfoProvidable,
        bundleStore: KeyBundleStore,
        catalogStore: KeyCatalogStore
    ) {
        self.engine = engine
        self.secureEnclave = secureEnclave
        self.memoryInfo = memoryInfo
        self.bundleStore = bundleStore
        self.catalogStore = catalogStore
    }

    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: KeyProfile,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        var (generated, keyInfo) = try await Self.generateKeyOffMainActor(
            engine: engine,
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            profile: profile
        )
        defer {
            generated.certData.resetBytes(in: 0..<generated.certData.count)
        }

        let accessControl = try authMode.createAccessControl()
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        let bundle = try secureEnclave.wrap(
            privateKey: generated.certData,
            using: seHandle,
            fingerprint: keyInfo.fingerprint
        )

        let fingerprint = keyInfo.fingerprint
        try bundleStore.saveBundle(bundle, fingerprint: fingerprint)

        let identity = PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: keyInfo.keyVersion,
            profile: profile,
            userId: keyInfo.userId,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            isRevoked: false,
            isExpired: false,
            isDefault: catalogStore.keys.isEmpty,
            isBackedUp: false,
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo,
            expiryDate: keyInfo.expiryTimestamp.map {
                Date(timeIntervalSince1970: TimeInterval($0))
            }
        )

        try catalogStore.storeNewIdentity(identity) {
            self.bundleStore.rollbackPermanentBundle(fingerprint: fingerprint)
        }

        return identity
    }

    func importKey(
        armoredData: Data,
        passphrase: String,
        authMode: AuthenticationMode
    ) async throws -> PGPKeyIdentity {
        let s2kInfo: S2kInfo
        do {
            s2kInfo = try engine.parseS2kParams(armoredData: armoredData)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }

        let memoryGuard = Argon2idMemoryGuard(memoryInfo: memoryInfo)
        try memoryGuard.validate(s2kInfo: s2kInfo)

        var (secretKeyData, keyInfo, profile, publicKeyData, revocationCert) = try await Self.importKeyOffMainActor(
            engine: engine,
            armoredData: armoredData,
            passphrase: passphrase
        )
        defer {
            secretKeyData.resetBytes(in: 0..<secretKeyData.count)
        }

        if catalogStore.containsKey(fingerprint: keyInfo.fingerprint) {
            throw CypherAirError.duplicateKey
        }

        let accessControl = try authMode.createAccessControl()
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        let bundle = try secureEnclave.wrap(
            privateKey: secretKeyData,
            using: seHandle,
            fingerprint: keyInfo.fingerprint
        )

        let fingerprint = keyInfo.fingerprint
        try bundleStore.saveBundle(bundle, fingerprint: fingerprint)

        let identity = PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: keyInfo.keyVersion,
            profile: profile,
            userId: keyInfo.userId,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            isRevoked: false,
            isExpired: keyInfo.isExpired,
            isDefault: catalogStore.keys.isEmpty,
            isBackedUp: false,
            publicKeyData: publicKeyData,
            revocationCert: revocationCert,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo,
            expiryDate: keyInfo.expiryTimestamp.map {
                Date(timeIntervalSince1970: TimeInterval($0))
            }
        )

        try catalogStore.storeNewIdentity(identity) {
            self.bundleStore.rollbackPermanentBundle(fingerprint: fingerprint)
        }

        return identity
    }

    @concurrent
    private static func generateKeyOffMainActor(
        engine: PgpEngine,
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: KeyProfile
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

    @concurrent
    private static func importKeyOffMainActor(
        engine: PgpEngine,
        armoredData: Data,
        passphrase: String
    ) async throws -> (
        secretKeyData: Data,
        keyInfo: KeyInfo,
        profile: KeyProfile,
        publicKeyData: Data,
        revocationCert: Data
    ) {
        do {
            let secretKeyData = try engine.importSecretKey(
                armoredData: armoredData,
                passphrase: passphrase
            )
            let keyInfo = try engine.parseKeyInfo(keyData: secretKeyData)
            let profile = try engine.detectProfile(certData: secretKeyData)
            let armoredPubKey = try engine.armorPublicKey(certData: secretKeyData)
            let publicKeyData = try engine.dearmor(armored: armoredPubKey)
            let revocationCert = try engine.generateKeyRevocation(secretCert: secretKeyData)
            return (secretKeyData, keyInfo, profile, publicKeyData, revocationCert)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }
    }
}
