import Foundation

struct PGPSecureEnclaveCustodyGeneratedMaterial: Sendable {
    let publicKeyData: Data
    let revocationCert: Data
    let metadata: PGPKeyMetadata
    let signingKeyFingerprint: String
    let keyAgreementSubkeyFingerprint: String
}

protocol SecureEnclaveCustodyCertificateBuilding: Sendable {
    func generatePublicCertificate(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        configuration: PGPKeyConfiguration,
        handlePair: SecureEnclaveCustodyLoadedHandlePair,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) async throws -> PGPSecureEnclaveCustodyGeneratedMaterial
}

final class PGPSecureEnclaveCustodyGenerationAdapter: SecureEnclaveCustodyCertificateBuilding, @unchecked Sendable {
    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    func generatePublicCertificate(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        configuration: PGPKeyConfiguration,
        handlePair: SecureEnclaveCustodyLoadedHandlePair,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) async throws -> PGPSecureEnclaveCustodyGeneratedMaterial {
        do {
            return try await Self.performGeneratePublicCertificate(
                engine: engine,
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                configuration: configuration,
                signingPublicKeyX963: handlePair.signing.binding.publicKeyX963,
                keyAgreementPublicKeyX963: handlePair.keyAgreement.binding.publicKeyX963,
                signingProvider: PGPSecureEnclaveExternalSigningProviderBridge(
                    handle: handlePair.signing,
                    digestSigner: digestSigner
                )
            )
        } catch {
            throw PGPErrorMapper.map(error) { .keyGenerationFailed(reason: $0) }
        }
    }

    @concurrent
    private static func performGeneratePublicCertificate(
        engine: PgpEngine,
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        configuration: PGPKeyConfiguration,
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data,
        signingProvider: ExternalP256SigningProvider
    ) async throws -> PGPSecureEnclaveCustodyGeneratedMaterial {
        let version: SecureEnclaveCertificateVersion
        switch configuration.identity {
        case .compatibleP256V4:
            version = .v4
        case .modernP256V6:
            version = .v6
        case .compatibleSoftwareV4,
             .modernSoftwareV6:
            throw CypherAirError.invalidKeyData(
                reason: "Secure Enclave custody generation requires a P-256 configuration."
            )
        }

        let input = SecureEnclavePublicCertificateInput(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            version: version,
            signingPublicKeyX963: signingPublicKeyX963,
            keyAgreementPublicKeyX963: keyAgreementPublicKeyX963
        )
        let generated = try engine.generateSecureEnclavePublicCertificate(
            input: input,
            signer: signingProvider
        )
        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        let metadata = PGPKeyMetadataAdapter.metadata(
            from: keyInfo,
            profile: configuration.keyVersion == 4 ? .universal : .advanced
        )

        return PGPSecureEnclaveCustodyGeneratedMaterial(
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            metadata: metadata,
            signingKeyFingerprint: generated.signingKeyFingerprint,
            keyAgreementSubkeyFingerprint: generated.keyAgreementSubkeyFingerprint
        )
    }
}

final class PGPSecureEnclaveExternalSigningProviderBridge: ExternalP256SigningProvider, @unchecked Sendable {
    private let handle: SecureEnclaveCustodyLoadedHandle
    private let digestSigner: any SecureEnclaveCustodyDigestSigning

    init(
        handle: SecureEnclaveCustodyLoadedHandle,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) {
        self.handle = handle
        self.digestSigner = digestSigner
    }

    func signSha256Digest(digest: Data) throws -> P256EcdsaSignature {
        do {
            let signature = try digestSigner.signSHA256Digest(digest, using: handle)
            return P256EcdsaSignature(r: signature.r, s: signature.s)
        } catch is CancellationError {
            throw ExternalP256SigningError.OperationCancelled
        } catch let error as SecureEnclaveCustodyHandleError {
            throw ExternalP256SigningError.Failed(
                category: Self.callbackCategory(for: error.failureCategory)
            )
        } catch {
            throw ExternalP256SigningError.Failed(category: .externalOperationFailed)
        }
    }

    private static func callbackCategory(
        for category: PGPKeyOperationFailureCategory
    ) -> ExternalP256SigningFailureCategory {
        switch category {
        case .hardwareUnavailable:
            return .hardwareUnavailable
        case .localAuthenticationRequired:
            return .localAuthenticationRequired
        case .localAuthenticationCancelled:
            return .localAuthenticationCancelled
        case .localAuthenticationFailed:
            return .localAuthenticationFailed
        case .localAuthenticationUnavailable:
            return .localAuthenticationUnavailable
        case .localAuthenticationLockedOut:
            return .localAuthenticationLockedOut
        case .privateHandleMissing:
            return .privateHandleMissing
        case .privateHandleInaccessible:
            return .privateHandleInaccessible
        case .privateHandleUnauthorized:
            return .privateHandleUnauthorized
        case .privateOperationRoleMismatch:
            return .privateOperationRoleMismatch
        case .handlePublicKeyBindingMismatch:
            return .handlePublicKeyBindingMismatch
        case .externalOperationFailed:
            return .externalOperationFailed
        case .invalidConfigurationCustody,
             .operationUnsupportedForCustody,
             .operationNotImplementedForCustody,
             .operationUnavailableByPolicy,
             .metadataAssociationMismatch,
             .publicCertificateAssociationMismatch,
             .publicMaterialUnavailable,
             .revocationArtifactUnavailable,
             .externalOperationInvalidRequest,
             .externalOperationInvalidResponse,
             .openPGPSemanticFailure,
             .payloadAuthenticationFailure,
             .migrationOrRecoveryRequired,
             .prohibitedFallbackAttempted,
             .cleanupOrRollbackFailure:
            return .externalOperationFailed
        }
    }
}
