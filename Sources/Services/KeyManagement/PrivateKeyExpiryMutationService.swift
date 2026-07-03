import Foundation

protocol PrivateKeyExpiryMutationRouting: Sendable {
    func routeModifyExpiry(fingerprint: String) async -> PrivateKeyOperationRoute

    func modifySecureEnclaveExpiry(
        route: SecureEnclaveSignerRoute,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial

    func modifySecureEnclaveCompositeExpiry(
        route: SecureEnclaveCompositeSignerRoute,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial
}

final class PrivateKeyExpiryMutationService: PrivateKeyExpiryMutationRouting, @unchecked Sendable {
    private let router: any PrivateKeyOperationRouting
    private let keyAdapter: PGPKeyOperationAdapter
    private let digestSigner: any SecureEnclaveCustodyDigestSigning
    private let compositeSigner: any SecureEnclaveCompositeSigning

    init(
        router: any PrivateKeyOperationRouting,
        keyAdapter: PGPKeyOperationAdapter,
        digestSigner: any SecureEnclaveCustodyDigestSigning,
        compositeSigner: any SecureEnclaveCompositeSigning = SystemSecureEnclaveCompositeOperations()
    ) {
        self.router = router
        self.keyAdapter = keyAdapter
        self.digestSigner = digestSigner
        self.compositeSigner = compositeSigner
    }

    func routeModifyExpiry(fingerprint: String) async -> PrivateKeyOperationRoute {
        await router.route(
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

    func modifySecureEnclaveCompositeExpiry(
        route: SecureEnclaveCompositeSignerRoute,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial {
        try await keyAdapter.modifyExpiryWithExternalCompositeSigner(
            publicCert: route.identity.publicKeyData,
            signingKeyFingerprint: route.compositeBindingInspection.signingKeyFingerprint,
            classicalEddsaSecret: route.classicalComponent.eddsaSecret,
            signingProvider: PGPExternalMlDsa65SigningProviderBridge(
                handle: route.signingHandle,
                compositeSigner: compositeSigner
            ),
            newExpirySeconds: newExpirySeconds
        )
    }
}
