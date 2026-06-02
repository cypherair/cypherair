import Foundation

protocol TextMessageEncrypting: Sendable {
    func encryptText(
        _ plaintext: Data,
        recipientKeys: [Data],
        signerFingerprint: String?,
        selfKey: Data?
    ) async throws -> Data
}

final class PrivateKeyTextEncryptionService: TextMessageEncrypting, @unchecked Sendable {
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

    func encryptText(
        _ plaintext: Data,
        recipientKeys: [Data],
        signerFingerprint: String?,
        selfKey: Data?
    ) async throws -> Data {
        guard let signerFingerprint else {
            return try await messageAdapter.encrypt(
                plaintext: plaintext,
                recipientKeys: recipientKeys,
                signingKey: nil,
                selfKey: selfKey,
                binary: false
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
            return try await messageAdapter.encrypt(
                plaintext: plaintext,
                recipientKeys: recipientKeys,
                signingKey: secretKey,
                selfKey: selfKey,
                binary: false
            )

        case .secureEnclaveSigner(let route):
            return try await messageAdapter.encryptWithExternalP256Signer(
                plaintext: plaintext,
                recipientKeys: recipientKeys,
                signingPublicCert: route.identity.publicKeyData,
                signingKeyFingerprint: route.publicBindingInspection.signingKeyFingerprint,
                signingProvider: PGPExternalP256SigningProviderBridge(
                    handle: route.signingHandle,
                    digestSigner: digestSigner
                ),
                selfKey: selfKey
            )

        case .blocked(let resolution):
            throw CypherAirError.keyOperationUnavailable(
                category: resolution.failureCategory ?? .operationUnavailableByPolicy
            )
        }
    }
}
