import Foundation

private final class KeyProvisioningCommitDrain: @unchecked Sendable {
    private let lock = NSLock()
    private var activeCommitCount = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func enterCommit() {
        lock.lock()
        activeCommitCount += 1
        lock.unlock()
    }

    func leaveCommit() {
        var continuationsToResume: [CheckedContinuation<Void, Never>] = []

        lock.lock()
        activeCommitCount = max(activeCommitCount - 1, 0)
        if activeCommitCount == 0 {
            continuationsToResume = waiters
            waiters.removeAll()
        }
        lock.unlock()

        for continuation in continuationsToResume {
            continuation.resume()
        }
    }

    func waitForActiveCommitsToFinish() async {
        await withCheckedContinuation { continuation in
            var shouldResumeImmediately = false

            lock.lock()
            if activeCommitCount == 0 {
                shouldResumeImmediately = true
            } else {
                waiters.append(continuation)
            }
            lock.unlock()

            if shouldResumeImmediately {
                continuation.resume()
            }
        }
    }
}

/// Owns key generation and import workflows behind the key-management facade.
final class KeyProvisioningService {
    typealias ProvisioningCheckpoint = @Sendable () async -> Void

    private let engine: PgpEngine
    private let secureEnclave: any SecureEnclaveManageable
    private let memoryInfo: any MemoryInfoProvidable
    private let bundleStore: KeyBundleStore
    private let catalogStore: KeyCatalogStore
    private let invalidationGate: KeyProvisioningInvalidationGate
    private let beforePermanentStorageCheckpoint: ProvisioningCheckpoint?
    private let afterIdentityStoreCheckpoint: ProvisioningCheckpoint?
    private let commitDrain = KeyProvisioningCommitDrain()

    init(
        engine: PgpEngine,
        secureEnclave: any SecureEnclaveManageable,
        memoryInfo: any MemoryInfoProvidable,
        bundleStore: KeyBundleStore,
        catalogStore: KeyCatalogStore,
        invalidationGate: KeyProvisioningInvalidationGate,
        beforePermanentStorageCheckpoint: ProvisioningCheckpoint? = nil,
        afterIdentityStoreCheckpoint: ProvisioningCheckpoint? = nil
    ) {
        self.engine = engine
        self.secureEnclave = secureEnclave
        self.memoryInfo = memoryInfo
        self.bundleStore = bundleStore
        self.catalogStore = catalogStore
        self.invalidationGate = invalidationGate
        self.beforePermanentStorageCheckpoint = beforePermanentStorageCheckpoint
        self.afterIdentityStoreCheckpoint = afterIdentityStoreCheckpoint
    }

    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: KeyProfile,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

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

        try await prepareForPermanentStorage(token: token)
        let accessControl = try authMode.createAccessControl()
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        let bundle = try secureEnclave.wrap(
            privateKey: generated.certData,
            using: seHandle,
            fingerprint: keyInfo.fingerprint
        )
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let fingerprint = keyInfo.fingerprint
        let bundleReceipt = try bundleStore.saveNewBundle(bundle, fingerprint: fingerprint)

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

        try await commitIdentity(identity, bundleReceipt: bundleReceipt, token: token)

        return identity
    }

    func importKey(
        armoredData: Data,
        passphrase: String,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let s2kInfo: S2kInfo
        do {
            s2kInfo = try engine.parseS2kParams(armoredData: armoredData)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }

        let memoryGuard = Argon2idMemoryGuard(memoryInfo: memoryInfo)
        try memoryGuard.validate(s2kInfo: s2kInfo)
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

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

        try await prepareForPermanentStorage(token: token)
        let accessControl = try authMode.createAccessControl()
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        let bundle = try secureEnclave.wrap(
            privateKey: secretKeyData,
            using: seHandle,
            fingerprint: keyInfo.fingerprint
        )
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let fingerprint = keyInfo.fingerprint
        let bundleReceipt = try bundleStore.saveNewBundle(bundle, fingerprint: fingerprint)

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

        try await commitIdentity(identity, bundleReceipt: bundleReceipt, token: token)

        return identity
    }

    private func prepareForPermanentStorage(
        token: KeyProvisioningInvalidationGate.Token
    ) async throws {
        if let beforePermanentStorageCheckpoint {
            await beforePermanentStorageCheckpoint()
        }
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)
    }

    private func commitIdentity(
        _ identity: PGPKeyIdentity,
        bundleReceipt: KeyBundleWriteReceipt,
        token: KeyProvisioningInvalidationGate.Token
    ) async throws {
        commitDrain.enterCommit()
        var didStoreIdentity = false
        do {
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            try catalogStore.storeNewIdentity(identity)
            didStoreIdentity = true
            if let afterIdentityStoreCheckpoint {
                await afterIdentityStoreCheckpoint()
            }
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            commitDrain.leaveCommit()
        } catch {
            if didStoreIdentity {
                catalogStore.discardCommittedIdentity(fingerprint: identity.fingerprint)
            }
            bundleStore.rollback(bundleReceipt)
            commitDrain.leaveCommit()
            throw error
        }
    }

    func waitForActiveIdentityCommitsToFinish() async {
        await commitDrain.waitForActiveCommitsToFinish()
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
