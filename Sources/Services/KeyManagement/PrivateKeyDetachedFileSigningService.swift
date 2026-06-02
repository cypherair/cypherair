import Foundation

protocol DetachedFileSigning: Sendable {
    func signDetachedFile(
        inputPath: String,
        signerFingerprint: String,
        progress: FileProgressReporter?
    ) async throws -> Data
}

final class PrivateKeyDetachedFileSigningService: DetachedFileSigning, @unchecked Sendable {
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

    func signDetachedFile(
        inputPath: String,
        signerFingerprint: String,
        progress: FileProgressReporter?
    ) async throws -> Data {
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
            return try await messageAdapter.signDetachedFile(
                inputPath: inputPath,
                signerCert: secretKey,
                progress: progress
            )

        case .secureEnclaveSigner(let route):
            return try await messageAdapter.signDetachedFileWithExternalP256Signer(
                inputPath: inputPath,
                publicCert: route.identity.publicKeyData,
                signingKeyFingerprint: route.publicBindingInspection.signingKeyFingerprint,
                signingProvider: PGPExternalP256SigningProviderBridge(
                    handle: route.signingHandle,
                    digestSigner: digestSigner
                ),
                progress: progress
            )

        case .blocked(let resolution):
            throw CypherAirError.keyOperationUnavailable(
                category: resolution.failureCategory ?? .operationUnavailableByPolicy
            )
        }
    }
}
