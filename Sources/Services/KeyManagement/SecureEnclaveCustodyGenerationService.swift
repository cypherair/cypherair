import Foundation

/// Internal hidden generation path for Secure Enclave custody public-only keys.
final class SecureEnclaveCustodyGenerationService: @unchecked Sendable {
    typealias GenerationCheckpoint = @Sendable () async throws -> Void

    private let certificateBuilder: any SecureEnclaveCustodyCertificateBuilding
    private let handleStore: SecureEnclaveCustodyHandleStore
    private let digestSigner: any SecureEnclaveCustodyDigestSigning
    private let catalogStore: KeyCatalogStore
    private let resolver: PGPKeyCapabilityResolver
    private let invalidationGate: KeyProvisioningInvalidationGate
    private let commitCoordinator: KeyProvisioningCommitCoordinator
    private let afterIdentityCommitCheckpoint: GenerationCheckpoint?

    init(
        certificateBuilder: any SecureEnclaveCustodyCertificateBuilding,
        handleStore: SecureEnclaveCustodyHandleStore,
        digestSigner: any SecureEnclaveCustodyDigestSigning,
        catalogStore: KeyCatalogStore,
        resolver: PGPKeyCapabilityResolver,
        invalidationGate: KeyProvisioningInvalidationGate,
        commitCoordinator: KeyProvisioningCommitCoordinator,
        afterIdentityCommitCheckpoint: GenerationCheckpoint? = nil
    ) {
        self.certificateBuilder = certificateBuilder
        self.handleStore = handleStore
        self.digestSigner = digestSigner
        self.catalogStore = catalogStore
        self.resolver = resolver
        self.invalidationGate = invalidationGate
        self.commitCoordinator = commitCoordinator
        self.afterIdentityCommitCheckpoint = afterIdentityCommitCheckpoint
    }

    func generateHiddenKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        configurationIdentity: PGPKeyConfiguration.Identity,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        let configuration = configurationIdentity.configuration
        guard configuration.algorithmSuite == .p256 else {
            throw CypherAirError.invalidKeyData(
                reason: "Secure Enclave custody generation requires a P-256 configuration."
            )
        }
        let resolution = resolver.resolution(
            for: .generate,
            configuration: configuration,
            custody: .appleSecureEnclavePrivateOperations
        )
        guard resolution.support == .supported else {
            throw CypherAirError.keyGenerationFailed(
                reason: resolution.failureCategory?.rawValue
                    ?? PGPKeyOperationFailureCategory.operationUnavailableByPolicy.rawValue
            )
        }

        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let handlePair = try handleStore.createHandlePair()
        var storedFingerprint: String?
        var didRollbackGeneratedState = false
        do {
            let loadedPair = try handleStore.loadHandlePair(expected: handlePair)
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)

            let generated = try await certificateBuilder.generatePublicCertificate(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                configuration: configuration,
                handlePair: loadedPair,
                digestSigner: digestSigner
            )
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)

            return try await commitCoordinator.performCommit {
                do {
                    try Task.checkCancellation()
                    try invalidationGate.checkValid(token)
                    guard !catalogStore.containsKey(fingerprint: generated.metadata.fingerprint) else {
                        throw CypherAirError.duplicateKey
                    }

                    let identity = PGPKeyIdentity(
                        fingerprint: generated.metadata.fingerprint,
                        keyVersion: generated.metadata.keyVersion,
                        profile: configuration.keyVersion == 4 ? .universal : .advanced,
                        userId: generated.metadata.userId,
                        hasEncryptionSubkey: generated.metadata.hasEncryptionSubkey,
                        isRevoked: false,
                        isExpired: generated.metadata.isExpired,
                        isDefault: catalogStore.keys.isEmpty,
                        isBackedUp: false,
                        publicKeyData: generated.publicKeyData,
                        revocationCert: generated.revocationCert,
                        primaryAlgo: generated.metadata.primaryAlgo,
                        subkeyAlgo: generated.metadata.subkeyAlgo,
                        expiryDate: generated.metadata.expiryDate,
                        openPGPConfigurationIdentity: configuration.identity,
                        privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
                    )
                    try catalogStore.storeNewIdentity(identity)
                    storedFingerprint = identity.fingerprint
                    if let afterIdentityCommitCheckpoint {
                        try await afterIdentityCommitCheckpoint()
                    }
                    try Task.checkCancellation()
                    try invalidationGate.checkValid(token)
                    return identity
                } catch {
                    do {
                        didRollbackGeneratedState = true
                        try rollbackGeneratedState(
                            handlePair: handlePair,
                            storedFingerprint: storedFingerprint
                        )
                    } catch {
                        throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
                    }
                    throw error
                }
            }
        } catch {
            if !didRollbackGeneratedState {
                do {
                    try rollbackGeneratedState(
                        handlePair: handlePair,
                        storedFingerprint: storedFingerprint
                    )
                } catch {
                    throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
                }
            }
            throw error
        }
    }

    private func rollbackGeneratedState(
        handlePair: SecureEnclaveCustodyHandlePair,
        storedFingerprint: String?
    ) throws {
        if let storedFingerprint {
            try catalogStore.discardCommittedIdentity(fingerprint: storedFingerprint)
        }
        try handleStore.deleteHandlePair(handlePair)
    }
}
