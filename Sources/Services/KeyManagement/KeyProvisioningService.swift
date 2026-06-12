import Foundation

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
        self.afterImportOffMainActorCheckpoint = afterImportOffMainActorCheckpoint
        self.afterPermanentBundleStoreCheckpoint = afterPermanentBundleStoreCheckpoint
        self.afterIdentityStoreCheckpoint = afterIdentityStoreCheckpoint
        self.commitCoordinator = commitCoordinator
    }

    /// Each whole provisioning action runs inside ONE operation-prompt session
    /// (the uniform rule, TARGET §3): the new wrapping key's first self-ECDH
    /// inside `wrap` presents the system prompt, and that sheet's own resign
    /// must be attributed to this action — deferred to the session's end, never
    /// a mid-action lock. A long key generation extends the deferral window by
    /// design: a user who switches away and stays away is locked at the
    /// action's end (stage-1 fail-closed-at-decision semantics).
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: PGPKeyProfile,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try await authenticationPromptCoordinator.withOperationPrompt(source: "keyProvisioning.generate") {
            try await performGenerateKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                profile: profile,
                authMode: authMode,
                invalidationToken: token
            )
        }
    }

    private func performGenerateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: PGPKeyProfile,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        var generated = try await keyAdapter.generateKey(
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
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: generated.certData,
            using: seHandle,
            fingerprint: generated.metadata.fingerprint
        )
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let fingerprint = generated.metadata.fingerprint
        let identity = PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: generated.metadata.keyVersion,
            profile: profile,
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
            openPGPConfigurationIdentity: profile.openPGPConfiguration.identity,
            privateKeyCustodyKind: .softwareSecretCertificate
        )

        try await commitIdentity(identity, bundle: bundle, token: token)

        return identity
    }

    /// See `generateKey` — the same one-session-per-action enrollment applies
    /// to the import's wrap prompt.
    func importKey(
        armoredData: Data,
        passphrase: String,
        authMode: AuthenticationMode,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try await authenticationPromptCoordinator.withOperationPrompt(source: "keyProvisioning.import") {
            try await performImportKey(
                armoredData: armoredData,
                passphrase: passphrase,
                authMode: authMode,
                invalidationToken: token
            )
        }
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
        let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: imported.secretKeyData,
            using: seHandle,
            fingerprint: imported.metadata.fingerprint
        )
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let fingerprint = imported.metadata.fingerprint
        let identity = PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: imported.metadata.keyVersion,
            profile: imported.metadata.profile,
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
            openPGPConfigurationIdentity: imported.metadata.profile.openPGPConfiguration.identity,
            privateKeyCustodyKind: .softwareSecretCertificate
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
