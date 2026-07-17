import Foundation
import Security

/// Owns key generation and import workflows behind the key-management facade.
final class KeyProvisioningService {
    typealias ProvisioningCheckpoint = @Sendable () async -> Void

    private let keyAdapter: PGPKeyOperationAdapter
    private let secureEnclave: any SecureEnclaveManageable
    private let memoryInfo: any MemoryInfoProvidable
    private let bundleStore: KeyBundleStore
    private let catalogStore: KeyCatalogStore
    private let invalidationGate: KeyProvisioningInvalidationGate
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let beforePermanentStorageCheckpoint: ProvisioningCheckpoint?
    private let wrappingPromptCheckpoint: ProvisioningCheckpoint?
    private let afterImportOffMainActorCheckpoint: ProvisioningCheckpoint?
    private let afterPermanentBundleStoreCheckpoint: ProvisioningCheckpoint?
    private let afterIdentityStoreCheckpoint: ProvisioningCheckpoint?
    private let commitCoordinator: KeyProvisioningCommitCoordinator

    init(
        keyAdapter: PGPKeyOperationAdapter,
        secureEnclave: any SecureEnclaveManageable,
        memoryInfo: any MemoryInfoProvidable,
        bundleStore: KeyBundleStore,
        catalogStore: KeyCatalogStore,
        invalidationGate: KeyProvisioningInvalidationGate,
        commitCoordinator: KeyProvisioningCommitCoordinator,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        beforePermanentStorageCheckpoint: ProvisioningCheckpoint? = nil,
        wrappingPromptCheckpoint: ProvisioningCheckpoint? = nil,
        afterImportOffMainActorCheckpoint: ProvisioningCheckpoint? = nil,
        afterPermanentBundleStoreCheckpoint: ProvisioningCheckpoint? = nil,
        afterIdentityStoreCheckpoint: ProvisioningCheckpoint? = nil
    ) {
        self.keyAdapter = keyAdapter
        self.secureEnclave = secureEnclave
        self.memoryInfo = memoryInfo
        self.bundleStore = bundleStore
        self.catalogStore = catalogStore
        self.invalidationGate = invalidationGate
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.beforePermanentStorageCheckpoint = beforePermanentStorageCheckpoint
        self.wrappingPromptCheckpoint = wrappingPromptCheckpoint
        self.afterImportOffMainActorCheckpoint = afterImportOffMainActorCheckpoint
        self.afterPermanentBundleStoreCheckpoint = afterPermanentBundleStoreCheckpoint
        self.afterIdentityStoreCheckpoint = afterIdentityStoreCheckpoint
        self.commitCoordinator = commitCoordinator
    }

    /// Only the Secure Enclave wrapping window is enrolled in an
    /// operation-prompt session. Long Rust generation and durable storage stay
    /// outside that window so a genuine macOS away still locks immediately when
    /// grace period is 0.
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        suite: PGPKeySuite,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try await performGenerateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            suite: suite,
            authMode: authMode,
            invalidationToken: token
        )
    }

    private func performGenerateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        suite: PGPKeySuite,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        var generated = try await keyAdapter.generateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            suite: suite
        )
        defer {
            generated.certData.resetBytes(in: 0..<generated.certData.count)
        }

        try await prepareForPermanentStorage(token: token)
        let accessControl = try authMode.createAccessControl()
        let bundle = try await wrapForProvisioning(
            privateKey: generated.certData,
            fingerprint: generated.metadata.fingerprint,
            accessControl: accessControl,
            source: "keyProvisioning.generate.wrap"
        )
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let fingerprint = generated.metadata.fingerprint
        let identity = PGPKeyIdentity(
            fingerprint: fingerprint,
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

        try await commitIdentity(identity, bundle: bundle, token: token)

        return identity
    }

    /// See `generateKey` — import parsing stays outside the prompt session; the
    /// Secure Enclave wrap is the only enrolled window.
    func importKey(
        armoredData: Data,
        passphrase: String,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try await performImportKey(
            armoredData: armoredData,
            passphrase: passphrase,
            authMode: authMode,
            invalidationToken: token
        )
    }

    private func performImportKey(
        armoredData: Data,
        passphrase: String,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let protectionInfo = try keyAdapter.importProtectionInfo(armoredData: armoredData)

        let memoryGuard = Argon2idMemoryGuard(memoryInfo: memoryInfo)
        try memoryGuard.validate(protectionInfo: protectionInfo)
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        var imported = try await keyAdapter.importSecretKey(
            armoredData: armoredData,
            passphrase: passphrase
        )
        defer {
            imported.secretKeyData.resetBytes(in: 0..<imported.secretKeyData.count)
        }
        if let afterImportOffMainActorCheckpoint {
            await afterImportOffMainActorCheckpoint()
        }
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        if catalogStore.containsKey(fingerprint: imported.metadata.fingerprint) {
            throw CypherAirError.duplicateKey
        }

        try await prepareForPermanentStorage(token: token)
        let accessControl = try authMode.createAccessControl()
        let bundle = try await wrapForProvisioning(
            privateKey: imported.secretKeyData,
            fingerprint: imported.metadata.fingerprint,
            accessControl: accessControl,
            source: "keyProvisioning.import.wrap"
        )
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let fingerprint = imported.metadata.fingerprint
        // Imports are always portable software certificates, so the engine's
        // detected suite must be present; its absence means the certificate
        // has no software suite classification and cannot become an owned
        // software key.
        guard let detectedSuite = imported.metadata.suite else {
            throw CypherAirError.invalidKeyData(
                reason: "Imported certificate has no software suite classification."
            )
        }
        let identity = PGPKeyIdentity(
            fingerprint: fingerprint,
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

        try await commitIdentity(identity, bundle: bundle, token: token)

        return identity
    }

    private func wrapForProvisioning(
        privateKey: Data,
        fingerprint: String,
        accessControl: SecAccessControl,
        source: String
    ) async throws -> WrappedKeyBundle {
        try await authenticationPromptCoordinator.withOperationPrompt(source: source) {
            if let wrappingPromptCheckpoint {
                await wrappingPromptCheckpoint()
            }
            let seHandle = try secureEnclave.generateWrappingKey(
                accessControl: accessControl,
                authenticationContext: nil
            )
            return try secureEnclave.wrap(
                privateKey: privateKey,
                using: seHandle,
                fingerprint: fingerprint
            )
        }
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
        try await commitCoordinator.performCommit {
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
    }

}
