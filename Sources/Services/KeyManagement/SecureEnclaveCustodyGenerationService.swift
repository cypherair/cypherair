import Foundation
import LocalAuthentication

/// Generation path for Secure Enclave custody public-only keys (device-bound
/// families). Exposed to the product UI since P7D; previously hidden/test-only.
final class SecureEnclaveCustodyGenerationService: @unchecked Sendable {
    typealias GenerationCheckpoint = @Sendable () async throws -> Void

    private let certificateBuilder: any SecureEnclaveCustodyCertificateBuilding
    private let handleStore: SecureEnclaveCustodyHandleStore
    private let digestSigner: any SecureEnclaveCustodyDigestSigning
    private let catalogStore: KeyCatalogStore
    private let resolver: PGPKeyCapabilityResolver
    private let invalidationGate: KeyProvisioningInvalidationGate
    private let commitCoordinator: KeyProvisioningCommitCoordinator
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator?
    private let custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator?
    private let afterIdentityCommitCheckpoint: GenerationCheckpoint?

    init(
        certificateBuilder: any SecureEnclaveCustodyCertificateBuilding,
        handleStore: SecureEnclaveCustodyHandleStore,
        digestSigner: any SecureEnclaveCustodyDigestSigning,
        catalogStore: KeyCatalogStore,
        resolver: PGPKeyCapabilityResolver,
        invalidationGate: KeyProvisioningInvalidationGate,
        commitCoordinator: KeyProvisioningCommitCoordinator,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator? = nil,
        custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator? = nil,
        afterIdentityCommitCheckpoint: GenerationCheckpoint? = nil
    ) {
        self.certificateBuilder = certificateBuilder
        self.handleStore = handleStore
        self.digestSigner = digestSigner
        self.catalogStore = catalogStore
        self.resolver = resolver
        self.invalidationGate = invalidationGate
        self.commitCoordinator = commitCoordinator
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.custodyOperationAuthenticator = custodyOperationAuthenticator
        self.afterIdentityCommitCheckpoint = afterIdentityCommitCheckpoint
    }

    /// Generation drives biometryAny digest signing, which presents auth
    /// sheets: the WHOLE action runs inside ONE operation-prompt session
    /// (SECURITY.md §4 uniform rule) when a coordinator is wired. The optional
    /// coordinator keeps test rigs (which sign with stub signers) unchanged.
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        configurationIdentity: PGPKeyConfiguration.Identity,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        guard let authenticationPromptCoordinator else {
            return try await performGenerateKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                configurationIdentity: configurationIdentity,
                invalidationToken: token
            )
        }
        return try await authenticationPromptCoordinator.withOperationPrompt(
            source: "keyProvisioning.generateSecureEnclaveCustody"
        ) {
            try await self.performGenerateKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                configurationIdentity: configurationIdentity,
                invalidationToken: token
            )
        }
    }

    private func performGenerateKey(
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
            throw CypherAirError.keyOperationUnavailable(
                category: resolution.failureCategory ?? .operationUnavailableByPolicy
            )
        }

        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        // Single prompt per generation (P7F): pre-authenticate BEFORE any
        // handle exists — a declined sheet aborts with nothing to roll back —
        // and thread the evaluated context into the biometryAny handle loads
        // below. When nil (test rigs, platforms without the production
        // wiring), the loads authenticate implicitly as before.
        var authorizedContext: LAContext?
        if let custodyOperationAuthenticator {
            do {
                authorizedContext = try await custodyOperationAuthenticator(
                    String(
                        localized: "keygen.custody.auth.reason",
                        defaultValue: "Authenticate to create your device-bound key."
                    )
                )
            } catch {
                let normalized = SecureEnclaveCustodyAuthenticationErrorNormalizer.normalize(error)
                throw CypherAirError.keyOperationUnavailable(
                    category: PGPKeyOperationFailureMapper.category(
                        for: normalized,
                        fallback: .localAuthenticationFailed
                    )
                )
            }
        }
        defer {
            authorizedContext?.invalidate()
        }

        let handlePair = try handleStore.createHandlePair()
        var storedFingerprint: String?
        var didRollbackGeneratedState = false
        do {
            let loadedPair = try handleStore.loadHandlePair(
                expected: handlePair,
                authenticationContext: authorizedContext
            )
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
