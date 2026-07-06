import Foundation

/// Generated Device-Bound Post-Quantum material. Unlike the P-256 result this
/// carries the freshly generated classical component secrets; the caller must
/// seal them into the classical component store and zeroize the buffers.
struct PGPSecureEnclaveCompositeGeneratedMaterial: Sendable {
    let publicKeyData: Data
    let revocationCert: Data
    let metadata: PGPKeyMetadata
    let signingKeyFingerprint: String
    let keyAgreementSubkeyFingerprint: String
    var classicalEddsaSecret: Data
    var classicalEcdhSecret: Data
}

protocol SecureEnclaveCompositeCertificateBuilding: Sendable {
    func generateCompositeCertificate(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        handlePair: SecureEnclaveCompositeLoadedHandlePair,
        compositeSigner: any SecureEnclaveCompositeSigning
    ) async throws -> PGPSecureEnclaveCompositeGeneratedMaterial
}

final class PGPSecureEnclaveCompositeGenerationAdapter: SecureEnclaveCompositeCertificateBuilding,
    @unchecked Sendable {
    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    /// Build the composite self-certificate for the tier of the supplied handle
    /// pair. The signing component public key and the external ML-DSA signer are
    /// tier-specific; the classical (Ed25519/X25519 or Ed448/X448) halves are
    /// generated inside Rust and returned for the caller to seal.
    func generateCompositeCertificate(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        handlePair: SecureEnclaveCompositeLoadedHandlePair,
        compositeSigner: any SecureEnclaveCompositeSigning
    ) async throws -> PGPSecureEnclaveCompositeGeneratedMaterial {
        do {
            switch handlePair.signing.reference.tier {
            case .postQuantum:
                return try await Self.performGenerateCompositeCertificate(
                    engine: engine,
                    name: name,
                    email: email,
                    expirySeconds: expirySeconds,
                    mldsa65SigningPublicKey: handlePair.signing.binding.publicKeyRaw,
                    mlkem768KeyAgreementPublicKey: handlePair.keyAgreement.binding.publicKeyRaw,
                    signingProvider: PGPExternalMlDsa65SigningProviderBridge(
                        handle: handlePair.signing,
                        compositeSigner: compositeSigner
                    )
                )
            case .postQuantumHigh:
                return try await Self.performGenerateCompositeHighCertificate(
                    engine: engine,
                    name: name,
                    email: email,
                    expirySeconds: expirySeconds,
                    mldsa87SigningPublicKey: handlePair.signing.binding.publicKeyRaw,
                    mlkem1024KeyAgreementPublicKey: handlePair.keyAgreement.binding.publicKeyRaw,
                    signingProvider: PGPExternalMlDsa87SigningProviderBridge(
                        handle: handlePair.signing,
                        compositeSigner: compositeSigner
                    )
                )
            }
        } catch {
            throw PGPErrorMapper.map(error) { .keyGenerationFailed(reason: $0) }
        }
    }

    @concurrent
    private static func performGenerateCompositeCertificate(
        engine: PgpEngine,
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        mldsa65SigningPublicKey: Data,
        mlkem768KeyAgreementPublicKey: Data,
        signingProvider: ExternalMlDsa65SigningProvider
    ) async throws -> PGPSecureEnclaveCompositeGeneratedMaterial {
        let input = SecureEnclaveCompositePublicCertificateInput(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            mldsa65SigningPublicKey: mldsa65SigningPublicKey,
            mlkem768KeyAgreementPublicKey: mlkem768KeyAgreementPublicKey
        )
        let generated = try engine.generateSecureEnclaveCompositePublicCertificate(
            input: input,
            signer: signingProvider
        )
        return try material(from: generated, engine: engine)
    }

    @concurrent
    private static func performGenerateCompositeHighCertificate(
        engine: PgpEngine,
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        mldsa87SigningPublicKey: Data,
        mlkem1024KeyAgreementPublicKey: Data,
        signingProvider: ExternalMlDsa87SigningProvider
    ) async throws -> PGPSecureEnclaveCompositeGeneratedMaterial {
        let input = SecureEnclaveCompositeHighPublicCertificateInput(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            mldsa87SigningPublicKey: mldsa87SigningPublicKey,
            mlkem1024KeyAgreementPublicKey: mlkem1024KeyAgreementPublicKey
        )
        let generated = try engine.generateSecureEnclaveCompositeHighPublicCertificate(
            input: input,
            signer: signingProvider
        )
        return try material(from: generated, engine: engine)
    }

    /// Both tiers return the same `SecureEnclaveCompositeGeneratedCertificate`;
    /// the engine classifies the certificate as post-quantum, so `keyInfo.profile`
    /// is authoritative and no override is needed.
    private static func material(
        from generated: SecureEnclaveCompositeGeneratedCertificate,
        engine: PgpEngine
    ) throws -> PGPSecureEnclaveCompositeGeneratedMaterial {
        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        let metadata = PGPKeyMetadataAdapter.metadata(from: keyInfo)
        return PGPSecureEnclaveCompositeGeneratedMaterial(
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            metadata: metadata,
            signingKeyFingerprint: generated.signingKeyFingerprint,
            keyAgreementSubkeyFingerprint: generated.keyAgreementSubkeyFingerprint,
            classicalEddsaSecret: generated.classicalEddsaSecret,
            classicalEcdhSecret: generated.classicalEcdhSecret
        )
    }
}
