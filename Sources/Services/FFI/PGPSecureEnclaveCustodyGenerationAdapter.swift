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
        family: PGPKeyFamily,
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
        family: PGPKeyFamily,
        handlePair: SecureEnclaveCustodyLoadedHandlePair,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) async throws -> PGPSecureEnclaveCustodyGeneratedMaterial {
        do {
            return try await Self.performGeneratePublicCertificate(
                engine: engine,
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                family: family,
                signingPublicKeyX963: handlePair.signing.binding.publicKeyRaw,
                keyAgreementPublicKeyX963: handlePair.keyAgreement.binding.publicKeyRaw,
                signingProvider: PGPExternalP256SigningProviderBridge(
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
        family: PGPKeyFamily,
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data,
        signingProvider: ExternalP256SigningProvider
    ) async throws -> PGPSecureEnclaveCustodyGeneratedMaterial {
        let version: SecureEnclaveCertificateVersion
        switch family {
        case .deviceBoundEcdsaNistP256EcdhNistP256V4:
            version = .v4
        case .deviceBoundEcdsaNistP256EcdhNistP256:
            version = .v6
        case .portableEd25519LegacyCurve25519Legacy,
             .portableEd25519X25519,
             .portableEd448X448,
             .portableMlDsa65Ed25519MlKem768X25519,
             .portableMlDsa87Ed448MlKem1024X448,
             .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            throw CypherAirError.invalidKeyData(
                reason: "Secure Enclave custody generation requires a P-256 family."
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
        // P-256 Secure Enclave certificates have no software suite classification.
        let metadata = PGPKeyMetadataAdapter.metadata(
            from: keyInfo,
            suite: nil
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
