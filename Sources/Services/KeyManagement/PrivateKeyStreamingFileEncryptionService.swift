import Foundation

protocol StreamingFileEncrypting: Sendable {
    func encryptFile(
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signerFingerprint: String?,
        selfKey: Data?,
        progress: FileProgressReporter?
    ) async throws
}

final class PrivateKeyStreamingFileEncryptionService: StreamingFileEncrypting, @unchecked Sendable {
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

    func encryptFile(
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signerFingerprint: String?,
        selfKey: Data?,
        progress: FileProgressReporter?
    ) async throws {
        guard let signerFingerprint else {
            return try await messageAdapter.encryptFile(
                inputPath: inputPath,
                outputPath: outputPath,
                recipientKeys: recipientKeys,
                signingKey: nil,
                selfKey: selfKey,
                progress: progress
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
            return try await messageAdapter.encryptFile(
                inputPath: inputPath,
                outputPath: outputPath,
                recipientKeys: recipientKeys,
                signingKey: secretKey,
                selfKey: selfKey,
                progress: progress
            )

        case .secureEnclaveSigner(let route):
            return try await messageAdapter.encryptFileWithExternalP256Signer(
                inputPath: inputPath,
                outputPath: outputPath,
                recipientKeys: recipientKeys,
                signingPublicCert: route.identity.publicKeyData,
                signingKeyFingerprint: route.publicBindingInspection.signingKeyFingerprint,
                signingProvider: PGPExternalP256SigningProviderBridge(
                    handle: route.signingHandle,
                    digestSigner: digestSigner
                ),
                selfKey: selfKey,
                progress: progress
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
