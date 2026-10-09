import Foundation
import Sealing
import Vault

/// Generates and imports portable keys: the engine produces the secret
/// certificate, the vault seals it against the identity wrapping key, and the
/// key list records it. Sealing is software, so provisioning never prompts.
final class KeyProvisioningService {
    typealias ProvisioningCheckpoint = @Sendable () async -> Void

    private let keyAdapter: PGPKeyOperationAdapter
    private let vault: AppVault
    private let memoryInfo: any MemoryInfoProvidable
    private let catalogStore: KeyCatalogStore
    private let invalidationGate: KeyProvisioningInvalidationGate
    private let commitCoordinator: KeyProvisioningCommitCoordinator
    private let beforePermanentStorageCheckpoint: ProvisioningCheckpoint?
    private let afterImportOffMainActorCheckpoint: ProvisioningCheckpoint?
    private let afterPermanentStoreCheckpoint: ProvisioningCheckpoint?
    private let afterIdentityStoreCheckpoint: ProvisioningCheckpoint?

    init(
        keyAdapter: PGPKeyOperationAdapter,
        vault: AppVault,
        memoryInfo: any MemoryInfoProvidable,
        catalogStore: KeyCatalogStore,
        invalidationGate: KeyProvisioningInvalidationGate,
        commitCoordinator: KeyProvisioningCommitCoordinator,
        beforePermanentStorageCheckpoint: ProvisioningCheckpoint? = nil,
        afterImportOffMainActorCheckpoint: ProvisioningCheckpoint? = nil,
        afterPermanentStoreCheckpoint: ProvisioningCheckpoint? = nil,
        afterIdentityStoreCheckpoint: ProvisioningCheckpoint? = nil
    ) {
        self.keyAdapter = keyAdapter
        self.vault = vault
        self.memoryInfo = memoryInfo
        self.catalogStore = catalogStore
        self.invalidationGate = invalidationGate
        self.commitCoordinator = commitCoordinator
        self.beforePermanentStorageCheckpoint = beforePermanentStorageCheckpoint
        self.afterImportOffMainActorCheckpoint = afterImportOffMainActorCheckpoint
        self.afterPermanentStoreCheckpoint = afterPermanentStoreCheckpoint
        self.afterIdentityStoreCheckpoint = afterIdentityStoreCheckpoint
    }

    func generateKey(
        name: String,
        email: String?,
        validity: PGPKeyValidity,
        suite: PGPKeySuite,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)
        var generated = try await keyAdapter.generateKey(name: name, email: email, validity: validity, suite: suite)
        // The raw certificate leaves the engine's result the moment it arrives, so
        // no exit from this function, cancellation included, can free it intact.
        let secretCertificate = SensitiveKeyBox(SensitiveBuffer(consuming: &generated.certData))
        try await prepareForPermanentStorage(token: token)
        let identity = PGPKeyIdentity(
            fingerprint: generated.metadata.fingerprint,
            userId: generated.metadata.userId,
            hasEncryptionSubkey: generated.metadata.hasEncryptionSubkey,
            isRevoked: false,
            isExpired: false,
            isDefault: catalogStore.keys.isEmpty,
            isBackedUp: false,
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            primaryAlgo: generated.metadata.primaryAlgo,
            subkeyAlgo: generated.metadata.subkeyAlgo,
            expiryDate: generated.metadata.expiryDate,
            keyFamily: suite.portableFamily,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
        try await commitIdentity(identity, secret: secretCertificate, token: token)
        return identity
    }

    func importKey(
        armoredData: Data,
        passphrase: String,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)
        let protectionInfo = try keyAdapter.importProtectionInfo(armoredData: armoredData)
        try Argon2idMemoryGuard(memoryInfo: memoryInfo).validate(protectionInfo: protectionInfo)
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)
        var imported = try await keyAdapter.importSecretKey(armoredData: armoredData, passphrase: passphrase)
        let secretCertificate = SensitiveKeyBox(SensitiveBuffer(consuming: &imported.secretKeyData))
        if let afterImportOffMainActorCheckpoint {
            await afterImportOffMainActorCheckpoint()
        }
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)
        if catalogStore.containsKey(fingerprint: imported.metadata.fingerprint) {
            throw CypherAirError.duplicateKey
        }
        try await prepareForPermanentStorage(token: token)
        guard let detectedSuite = imported.metadata.suite else {
            throw CypherAirError.invalidKeyData(reason: "Imported certificate has no software suite classification.")
        }
        let identity = PGPKeyIdentity(
            fingerprint: imported.metadata.fingerprint,
            userId: imported.metadata.userId,
            hasEncryptionSubkey: imported.metadata.hasEncryptionSubkey,
            isRevoked: false,
            isExpired: imported.metadata.isExpired,
            isDefault: catalogStore.keys.isEmpty,
            isBackedUp: false,
            publicKeyData: imported.publicKeyData,
            revocationCert: imported.revocationCert,
            primaryAlgo: imported.metadata.primaryAlgo,
            subkeyAlgo: imported.metadata.subkeyAlgo,
            expiryDate: imported.metadata.expiryDate,
            keyFamily: detectedSuite.portableFamily,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
        try await commitIdentity(identity, secret: secretCertificate, token: token)
        return identity
    }

    private func prepareForPermanentStorage(token: KeyProvisioningInvalidationGate.Token) async throws {
        if let beforePermanentStorageCheckpoint {
            await beforePermanentStorageCheckpoint()
        }
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)
    }

    /// Seals the secret, then records the identity; either failure undoes the
    /// other so no half-provisioned key survives.
    private func commitIdentity(
        _ identity: PGPKeyIdentity,
        secret: SensitiveKeyBox,
        token: KeyProvisioningInvalidationGate.Token
    ) async throws {
        try await commitCoordinator.performCommit {
            var didSeal = false
            var didStoreIdentity = false
            do {
                try Task.checkCancellation()
                try invalidationGate.checkValid(token)
                do {
                    try vault.portableKeys.seal(secret.buffer, fingerprint: identity.fingerprint, session: try vault.requireSession())
                } catch {
                    throw CypherAirError.fromStore(error)
                }
                didSeal = true
                if let afterPermanentStoreCheckpoint {
                    await afterPermanentStoreCheckpoint()
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
                if didSeal {
                    try? vault.portableKeys.delete(fingerprint: identity.fingerprint)
                }
                throw error
            }
        }
    }
}
