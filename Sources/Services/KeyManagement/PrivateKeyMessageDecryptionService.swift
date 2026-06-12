import Foundation

protocol RecipientMessageDecrypting: Sendable {
    func decryptDetailed(
        ciphertext: Data,
        recipientFingerprint: String,
        verificationContext: PGPMessageVerificationContext
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification)
}

/// Routes recipient-key message decryption through the private-operation router.
///
/// Software custody keeps the existing unwrap-and-zeroize secret-certificate path.
/// Secure Enclave custody uses the external P-256 key-agreement route: Swift hands
/// only the raw shared secret to Rust/Sequoia, which owns OpenPGP ECDH KDF, AES Key
/// Wrap unwrap, session-key validation, payload authentication, and success-only
/// plaintext release. There is no software fallback for a Secure Enclave route.
final class PrivateKeyMessageDecryptionService: RecipientMessageDecrypting, @unchecked Sendable {
    private let router: any PrivateKeyOperationRouting
    private let softwarePrivateKeyAccess: any SoftwareSecretCertificateUnwrapping
    private let messageAdapter: PGPMessageOperationAdapter
    private let keyAgreement: any SecureEnclaveCustodyKeyAgreement

    init(
        router: any PrivateKeyOperationRouting,
        softwarePrivateKeyAccess: any SoftwareSecretCertificateUnwrapping,
        messageAdapter: PGPMessageOperationAdapter,
        keyAgreement: any SecureEnclaveCustodyKeyAgreement
    ) {
        self.router = router
        self.softwarePrivateKeyAccess = softwarePrivateKeyAccess
        self.messageAdapter = messageAdapter
        self.keyAgreement = keyAgreement
    }

    func decryptDetailed(
        ciphertext: Data,
        recipientFingerprint: String,
        verificationContext: PGPMessageVerificationContext
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification) {
        let operationRoute = await router.route(
            for: PrivateKeyOperationRequest(
                fingerprint: recipientFingerprint,
                operation: .decrypt
            )
        )
        defer {
            operationRoute.endAuthorizedOperation()
        }
        switch operationRoute {
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
            return try await messageAdapter.decryptDetailed(
                ciphertext: ciphertext,
                secretKeys: [secretKey],
                verificationContext: verificationContext
            )

        case .secureEnclaveKeyAgreement(let route):
            return try await messageAdapter.decryptDetailedWithExternalP256KeyAgreement(
                ciphertext: ciphertext,
                recipientPublicCert: route.identity.publicKeyData,
                keyAgreementSubkeyFingerprint: route.publicBindingInspection.keyAgreementSubkeyFingerprint,
                keyAgreementProvider: PGPExternalP256KeyAgreementProviderBridge(
                    handle: route.keyAgreementHandle,
                    keyAgreement: keyAgreement
                ),
                verificationContext: verificationContext
            )

        case .secureEnclaveSigner:
            throw CypherAirError.keyOperationUnavailable(category: .privateOperationRoleMismatch)

        case .blocked(let resolution):
            throw CypherAirError.keyOperationUnavailable(
                category: resolution.failureCategory ?? .operationUnavailableByPolicy
            )
        }
    }
}
