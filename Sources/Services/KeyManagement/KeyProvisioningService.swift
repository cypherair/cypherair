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

    func waitForActiveCommitsToFinish(
        waiterRegisteredCheckpoint: (@Sendable () async -> Void)? = nil
    ) async {
        await withCheckedContinuation { continuation in
            var shouldResumeImmediately = false
            var didRegisterWaiter = false

            lock.lock()
            if activeCommitCount == 0 {
                shouldResumeImmediately = true
            } else {
                waiters.append(continuation)
                didRegisterWaiter = true
            }
            lock.unlock()

            if shouldResumeImmediately {
                continuation.resume()
            } else if didRegisterWaiter, let waiterRegisteredCheckpoint {
                Task {
                    await waiterRegisteredCheckpoint()
                }
            }
        }
    }
}

/// Owns key generation and import workflows behind the key-management facade.
final class KeyProvisioningService {
    typealias ProvisioningCheckpoint = @Sendable () async -> Void

    private let engine: PgpEngine
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let secureEnclave: any SecureEnclaveManageable
    private let memoryInfo: any MemoryInfoProvidable
    private let bundleStore: KeyBundleStore
    private let catalogStore: KeyCatalogStore
    private let invalidationGate: KeyProvisioningInvalidationGate
    private let beforePermanentStorageCheckpoint: ProvisioningCheckpoint?
    private let afterImportOffMainActorCheckpoint: ProvisioningCheckpoint?
    private let afterPermanentBundleStoreCheckpoint: ProvisioningCheckpoint?
    private let afterIdentityStoreCheckpoint: ProvisioningCheckpoint?
    private let commitDrainWaiterRegisteredCheckpoint: ProvisioningCheckpoint?
    private let commitDrain = KeyProvisioningCommitDrain()

    init(
        engine: PgpEngine,
        certificateAdapter: PGPCertificateOperationAdapter,
        secureEnclave: any SecureEnclaveManageable,
        memoryInfo: any MemoryInfoProvidable,
        bundleStore: KeyBundleStore,
        catalogStore: KeyCatalogStore,
        invalidationGate: KeyProvisioningInvalidationGate,
        beforePermanentStorageCheckpoint: ProvisioningCheckpoint? = nil,
        afterImportOffMainActorCheckpoint: ProvisioningCheckpoint? = nil,
        afterPermanentBundleStoreCheckpoint: ProvisioningCheckpoint? = nil,
        afterIdentityStoreCheckpoint: ProvisioningCheckpoint? = nil,
        commitDrainWaiterRegisteredCheckpoint: ProvisioningCheckpoint? = nil
    ) {
        self.engine = engine
        self.certificateAdapter = certificateAdapter
        self.secureEnclave = secureEnclave
        self.memoryInfo = memoryInfo
        self.bundleStore = bundleStore
        self.catalogStore = catalogStore
        self.invalidationGate = invalidationGate
        self.beforePermanentStorageCheckpoint = beforePermanentStorageCheckpoint
        self.afterImportOffMainActorCheckpoint = afterImportOffMainActorCheckpoint
        self.afterPermanentBundleStoreCheckpoint = afterPermanentBundleStoreCheckpoint
        self.afterIdentityStoreCheckpoint = afterIdentityStoreCheckpoint
        self.commitDrainWaiterRegisteredCheckpoint = commitDrainWaiterRegisteredCheckpoint
    }

    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: PGPKeyProfile,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        var (generated, metadata) = try await Self.generateKeyOffMainActor(
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
            fingerprint: metadata.fingerprint
        )
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let fingerprint = metadata.fingerprint
        let identity = PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: metadata.keyVersion,
            profile: profile,
            userId: metadata.userId,
            hasEncryptionSubkey: metadata.hasEncryptionSubkey,
            isRevoked: false,
            isExpired: false,
            isDefault: catalogStore.keys.isEmpty,
            isBackedUp: false,
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            primaryAlgo: metadata.primaryAlgo,
            subkeyAlgo: metadata.subkeyAlgo,
            expiryDate: metadata.expiryDate
        )

        try await commitIdentity(identity, bundle: bundle, token: token)

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

        var (secretKeyData, metadata, publicKeyData, revocationCert) = try await Self.importKeyOffMainActor(
            engine: engine,
            certificateAdapter: certificateAdapter,
            armoredData: armoredData,
            passphrase: passphrase
        )
        defer {
            secretKeyData.resetBytes(in: 0..<secretKeyData.count)
        }
        if let afterImportOffMainActorCheckpoint {
            await afterImportOffMainActorCheckpoint()
        }
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        if catalogStore.containsKey(fingerprint: metadata.fingerprint) {
            throw CypherAirError.duplicateKey
        }

        try await prepareForPermanentStorage(token: token)
        let accessControl = try authMode.createAccessControl()
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        let bundle = try secureEnclave.wrap(
            privateKey: secretKeyData,
            using: seHandle,
            fingerprint: metadata.fingerprint
        )
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let fingerprint = metadata.fingerprint
        let identity = PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: metadata.keyVersion,
            profile: metadata.profile,
            userId: metadata.userId,
            hasEncryptionSubkey: metadata.hasEncryptionSubkey,
            isRevoked: false,
            isExpired: metadata.isExpired,
            isDefault: catalogStore.keys.isEmpty,
            isBackedUp: false,
            publicKeyData: publicKeyData,
            revocationCert: revocationCert,
            primaryAlgo: metadata.primaryAlgo,
            subkeyAlgo: metadata.subkeyAlgo,
            expiryDate: metadata.expiryDate
        )

        try await commitIdentity(identity, bundle: bundle, token: token)

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
        bundle: WrappedKeyBundle,
        token: KeyProvisioningInvalidationGate.Token
    ) async throws {
        commitDrain.enterCommit()
        defer {
            commitDrain.leaveCommit()
        }

        var bundleReceipt: KeyBundleWriteReceipt?
        var didStoreIdentity = false
        do {
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            bundleReceipt = try bundleStore.saveNewBundle(bundle, fingerprint: identity.fingerprint)
            if let afterPermanentBundleStoreCheckpoint {
                await afterPermanentBundleStoreCheckpoint()
            }
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            try catalogStore.storeNewIdentity(identity)
            didStoreIdentity = true
            if let afterIdentityStoreCheckpoint {
                await afterIdentityStoreCheckpoint()
            }
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
        } catch {
            if didStoreIdentity {
                try catalogStore.discardCommittedIdentity(fingerprint: identity.fingerprint)
            }
            if let bundleReceipt {
                bundleStore.rollback(bundleReceipt)
            }
            throw error
        }
    }

    func waitForActiveProvisioningCommitsToFinish() async {
        await commitDrain.waitForActiveCommitsToFinish(
            waiterRegisteredCheckpoint: commitDrainWaiterRegisteredCheckpoint
        )
    }

    @concurrent
    private static func generateKeyOffMainActor(
        engine: PgpEngine,
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: PGPKeyProfile
    ) async throws -> (GeneratedKey, PGPKeyMetadata) {
        do {
            let generated = try engine.generateKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                profile: profile.ffiValue
            )
            let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
            let metadata = PGPKeyMetadataAdapter.metadata(
                from: keyInfo,
                profile: profile.ffiValue
            )
            return (generated, metadata)
        } catch {
            throw CypherAirError.from(error) { .keyGenerationFailed(reason: $0) }
        }
    }

    @concurrent
    private static func importKeyOffMainActor(
        engine: PgpEngine,
        certificateAdapter: PGPCertificateOperationAdapter,
        armoredData: Data,
        passphrase: String
    ) async throws -> (
        secretKeyData: Data,
        metadata: PGPKeyMetadata,
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
            let metadata = PGPKeyMetadataAdapter.metadata(
                from: keyInfo,
                profile: profile
            )
            let armoredPubKey = try engine.armorPublicKey(certData: secretKeyData)
            let publicKeyData = try engine.dearmor(armored: armoredPubKey)
            let revocationCert = try await certificateAdapter.generateKeyRevocation(
                secretCert: secretKeyData
            )
            return (secretKeyData, metadata, publicKeyData, revocationCert)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }
    }
}
