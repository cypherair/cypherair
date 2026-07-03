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
             .modernSoftwareV6,
             .postQuantumSoftwareV6:
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
