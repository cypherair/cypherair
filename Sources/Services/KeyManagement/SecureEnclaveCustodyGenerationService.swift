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

    /// Only the custody authorization and immediately authorized handle-load
    /// window is enrolled in an operation-prompt session. Certificate building
    /// and durable metadata commit stay outside that window so a genuine macOS
    /// away still locks immediately when grace period is 0.
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        configurationIdentity: PGPKeyConfiguration.Identity,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        try await performGenerateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            configurationIdentity: configurationIdentity,
            invalidationToken: token
        )
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

        let authorizedPair = try await createAuthorizedHandlePair()
        let authorizedContext = authorizedPair.authenticationContext
        defer {
            authorizedContext?.invalidate()
        }

        let handlePair = authorizedPair.handlePair
        var storedFingerprint: String?
        var didRollbackGeneratedState = false
        do {
            let loadedPair = authorizedPair.loadedPair
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

    private func createAuthorizedHandlePair() async throws -> AuthorizedCustodyGenerationHandlePair {
        try await withOperationPromptIfConfigured(
            source: "keyProvisioning.generateSecureEnclaveCustody.authorize"
        ) {
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
                    authorizedContext?.invalidate()
                    let normalized = SecureEnclaveCustodyAuthenticationErrorNormalizer.normalize(error)
                    throw CypherAirError.keyOperationUnavailable(
                        category: PGPKeyOperationFailureMapper.category(
                            for: normalized,
                            fallback: .localAuthenticationFailed
                        )
                    )
                }
            }

            do {
                let handlePair = try handleStore.createHandlePair()
                do {
                    let loadedPair = try handleStore.loadHandlePair(
                        expected: handlePair,
                        authenticationContext: authorizedContext
                    )
                    return AuthorizedCustodyGenerationHandlePair(
                        handlePair: handlePair,
                        loadedPair: loadedPair,
                        authenticationContext: authorizedContext
                    )
                } catch {
                    do {
                        try rollbackGeneratedState(
                            handlePair: handlePair,
                            storedFingerprint: nil
                        )
                    } catch {
                        throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
                    }
                    throw error
                }
            } catch {
                authorizedContext?.invalidate()
                throw error
            }
        }
    }

    private func withOperationPromptIfConfigured<T>(
        source: String,
        operation: () async throws -> T
    ) async throws -> T {
        guard let authenticationPromptCoordinator else {
            return try await operation()
        }
        return try await authenticationPromptCoordinator.withOperationPrompt(source: source) {
            try await operation()
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

private struct AuthorizedCustodyGenerationHandlePair {
    let handlePair: SecureEnclaveCustodyHandlePair
    let loadedPair: SecureEnclaveCustodyLoadedHandlePair
    let authenticationContext: LAContext?
}
