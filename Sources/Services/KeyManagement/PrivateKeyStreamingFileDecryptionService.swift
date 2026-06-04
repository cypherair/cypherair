import Foundation

protocol StreamingFileDecrypting: Sendable {
    func decryptFile(
        inputPath: String,
        outputPath: String,
        recipientFingerprint: String,
        verificationContext: PGPMessageVerificationContext,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification
}

/// Routes streaming recipient-key file decryption through the private-operation router.
///
/// Software custody keeps the existing unwrap-and-zeroize secret-certificate path and
/// calls the standard streaming file decrypt FFI. Secure Enclave custody loads only the
/// `.keyAgreement` handle and uses the external P-256 key-agreement route: Swift hands
/// only the raw shared secret to Rust/Sequoia, which owns OpenPGP ECDH KDF, AES Key Wrap
/// unwrap, session-key validation, payload authentication, verification folding, and the
/// success-only plaintext-to-output contract. There is no software fallback for a Secure
/// Enclave route.
final class PrivateKeyStreamingFileDecryptionService: StreamingFileDecrypting, @unchecked Sendable {
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

    func decryptFile(
        inputPath: String,
        outputPath: String,
        recipientFingerprint: String,
        verificationContext: PGPMessageVerificationContext,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification {
        switch router.route(
            for: PrivateKeyOperationRequest(
                fingerprint: recipientFingerprint,
                operation: .decrypt
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
            return try await messageAdapter.decryptFileDetailed(
                inputPath: inputPath,
                outputPath: outputPath,
                secretKeys: [secretKey],
                verificationContext: verificationContext,
                progress: progress
            )

        case .secureEnclaveKeyAgreement(let route):
            return try await messageAdapter.decryptFileWithExternalP256KeyAgreement(
                inputPath: inputPath,
                outputPath: outputPath,
                recipientPublicCert: route.identity.publicKeyData,
                keyAgreementSubkeyFingerprint: route.publicBindingInspection.keyAgreementSubkeyFingerprint,
                keyAgreementProvider: PGPExternalP256KeyAgreementProviderBridge(
                    handle: route.keyAgreementHandle,
                    keyAgreement: keyAgreement
                ),
                verificationContext: verificationContext,
                progress: progress
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
