import Foundation

protocol PrivateKeyExpiryMutationRouting: Sendable {
    func routeModifyExpiry(fingerprint: String) -> PrivateKeyOperationRoute

    func modifySecureEnclaveExpiry(
        route: SecureEnclaveSignerRoute,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial
}

final class PrivateKeyExpiryMutationService: PrivateKeyExpiryMutationRouting, @unchecked Sendable {
    private let router: any PrivateKeyOperationRouting
    private let keyAdapter: PGPKeyOperationAdapter
    private let digestSigner: any SecureEnclaveCustodyDigestSigning

    init(
        router: any PrivateKeyOperationRouting,
        keyAdapter: PGPKeyOperationAdapter,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) {
        self.router = router
        self.keyAdapter = keyAdapter
        self.digestSigner = digestSigner
    }

    func routeModifyExpiry(fingerprint: String) -> PrivateKeyOperationRoute {
        router.route(
            for: PrivateKeyOperationRequest(
                fingerprint: fingerprint,
                operation: .modifyExpiry
            )
        )
    }

    func modifySecureEnclaveExpiry(
        route: SecureEnclaveSignerRoute,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial {
        try await keyAdapter.modifyExpiryWithExternalP256Signer(
            publicCert: route.identity.publicKeyData,
            signingKeyFingerprint: route.publicBindingInspection.signingKeyFingerprint,
            signingProvider: PGPExternalP256SigningProviderBridge(
                handle: route.signingHandle,
                digestSigner: digestSigner
            ),
            newExpirySeconds: newExpirySeconds
        )
    }
}
