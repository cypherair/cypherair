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

    func generateCompositeCertificate(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        handlePair: SecureEnclaveCompositeLoadedHandlePair,
        compositeSigner: any SecureEnclaveCompositeSigning
    ) async throws -> PGPSecureEnclaveCompositeGeneratedMaterial {
        do {
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
        // The engine classifies the composite certificate as post-quantum;
        // `keyInfo.profile` is authoritative, no override needed.
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
