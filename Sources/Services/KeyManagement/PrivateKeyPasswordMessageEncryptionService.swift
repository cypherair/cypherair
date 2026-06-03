import Foundation

protocol PasswordMessageEncrypting: Sendable {
    func encrypt(
        plaintext: Data,
        password: String,
        format: PasswordMessageEnvelopeFormat,
        signerFingerprint: String?,
        binary: Bool
    ) async throws -> Data
}

final class PrivateKeyPasswordMessageEncryptionService: PasswordMessageEncrypting, @unchecked Sendable {
    private let router: any PrivateKeyOperationRouting
    private let softwarePrivateKeyAccess: any SoftwareSecretCertificateUnwrapping
    private let messageAdapter: PGPMessageOperationAdapter
    private let digestSigner: any SecureEnclaveCustodyDigestSigning

    init(
        router: any PrivateKeyOperationRouting,
        softwarePrivateKeyAccess: any SoftwareSecretCertificateUnwrapping,
        messageAdapter: PGPMessageOperationAdapter,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) {
        self.router = router
        self.softwarePrivateKeyAccess = softwarePrivateKeyAccess
        self.messageAdapter = messageAdapter
        self.digestSigner = digestSigner
    }

    func encrypt(
        plaintext: Data,
        password: String,
        format: PasswordMessageEnvelopeFormat,
        signerFingerprint: String?,
        binary: Bool
    ) async throws -> Data {
        guard let signerFingerprint else {
            return try await messageAdapter.encryptWithPassword(
                plaintext: plaintext,
                password: password,
                format: format,
                signingKey: nil,
                binary: binary
            )
        }

        switch router.route(
            for: PrivateKeyOperationRequest(
                fingerprint: signerFingerprint,
                operation: .sign
            )
        ) {
        case .softwareSecretCertificate(let route):
            var secretKey: Data
            do {
                secretKey = try await softwarePrivateKeyAccess.unwrapPrivateKey(
                    fingerprint: route.identity.fingerprint
                )
            } catch {
                throw CypherAirError.from(error) { _ in .authenticationFailed }
            }
            defer {
                secretKey.resetBytes(in: 0..<secretKey.count)
            }
            return try await messageAdapter.encryptWithPassword(
                plaintext: plaintext,
                password: password,
                format: format,
                signingKey: secretKey,
                binary: binary
            )

        case .secureEnclaveSigner(let route):
            return try await messageAdapter.encryptWithPasswordAndExternalP256Signer(
                plaintext: plaintext,
                password: password,
                format: format,
                signingPublicCert: route.identity.publicKeyData,
                signingKeyFingerprint: route.publicBindingInspection.signingKeyFingerprint,
                signingProvider: PGPExternalP256SigningProviderBridge(
                    handle: route.signingHandle,
                    digestSigner: digestSigner
                ),
                binary: binary
            )

        case .secureEnclaveKeyAgreement:
            throw CypherAirError.keyOperationUnavailable(category: .privateOperationRoleMismatch)

        case .blocked(let resolution):
            throw CypherAirError.keyOperationUnavailable(
                category: resolution.failureCategory ?? .operationUnavailableByPolicy
            )
        }
    }
}
