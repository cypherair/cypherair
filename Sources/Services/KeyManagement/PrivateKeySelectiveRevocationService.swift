import Foundation

protocol PrivateKeySelectiveRevocationRouting: Sendable {
    func routeRevocation(fingerprint: String) async -> PrivateKeyOperationRoute

    func generateSecureEnclaveSubkeyRevocation(
        route: SecureEnclaveSignerRoute,
        subkeyFingerprint: String
    ) async throws -> Data

    func generateSecureEnclaveUserIdRevocation(
        route: SecureEnclaveSignerRoute,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data

    func generateSecureEnclaveCompositeSubkeyRevocation(
        route: SecureEnclaveCompositeSignerRoute,
        subkeyFingerprint: String
    ) async throws -> Data

    func generateSecureEnclaveCompositeUserIdRevocation(
        route: SecureEnclaveCompositeSignerRoute,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data
}

final class PrivateKeySelectiveRevocationService: PrivateKeySelectiveRevocationRouting, @unchecked Sendable {
    private let router: any PrivateKeyOperationRouting
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let digestSigner: any SecureEnclaveCustodyDigestSigning
    private let compositeSigner: any SecureEnclaveCompositeSigning

    init(
        router: any PrivateKeyOperationRouting,
        certificateAdapter: PGPCertificateOperationAdapter,
        digestSigner: any SecureEnclaveCustodyDigestSigning,
        compositeSigner: any SecureEnclaveCompositeSigning = SystemSecureEnclaveCompositeOperations()
    ) {
        self.router = router
        self.certificateAdapter = certificateAdapter
        self.digestSigner = digestSigner
        self.compositeSigner = compositeSigner
    }

    func routeRevocation(fingerprint: String) async -> PrivateKeyOperationRoute {
        await router.route(
            for: PrivateKeyOperationRequest(
                fingerprint: fingerprint,
                operation: .revoke
            )
        )
    }

    func generateSecureEnclaveSubkeyRevocation(
        route: SecureEnclaveSignerRoute,
        subkeyFingerprint: String
    ) async throws -> Data {
        try await certificateAdapter.generateSubkeyRevocationWithExternalP256Signer(
            publicCert: route.identity.publicKeyData,
            signingKeyFingerprint: route.publicBindingInspection.signingKeyFingerprint,
            signingProvider: PGPExternalP256SigningProviderBridge(
                handle: route.signingHandle,
                digestSigner: digestSigner
            ),
            subkeyFingerprint: subkeyFingerprint
        )
    }

    func generateSecureEnclaveUserIdRevocation(
        route: SecureEnclaveSignerRoute,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data {
        try await certificateAdapter.generateUserIdRevocationWithExternalP256Signer(
            publicCert: route.identity.publicKeyData,
            signingKeyFingerprint: route.publicBindingInspection.signingKeyFingerprint,
            signingProvider: PGPExternalP256SigningProviderBridge(
                handle: route.signingHandle,
                digestSigner: digestSigner
            ),
            selectedUserId: selectedUserId
        )
    }

    func generateSecureEnclaveCompositeSubkeyRevocation(
        route: SecureEnclaveCompositeSignerRoute,
        subkeyFingerprint: String
    ) async throws -> Data {
        try await certificateAdapter.generateSubkeyRevocationWithExternalCompositeSigner(
            publicCert: route.identity.publicKeyData,
            signingKeyFingerprint: route.compositeBindingInspection.signingKeyFingerprint,
            classicalEddsaSecret: route.classicalComponent.eddsaSecret,
            signingProvider: PGPExternalMlDsa65SigningProviderBridge(
                handle: route.signingHandle,
                compositeSigner: compositeSigner
            ),
            subkeyFingerprint: subkeyFingerprint
        )
    }

    func generateSecureEnclaveCompositeUserIdRevocation(
        route: SecureEnclaveCompositeSignerRoute,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data {
        try await certificateAdapter.generateUserIdRevocationWithExternalCompositeSigner(
            publicCert: route.identity.publicKeyData,
            signingKeyFingerprint: route.compositeBindingInspection.signingKeyFingerprint,
            classicalEddsaSecret: route.classicalComponent.eddsaSecret,
            signingProvider: PGPExternalMlDsa65SigningProviderBridge(
                handle: route.signingHandle,
                compositeSigner: compositeSigner
            ),
            selectedUserId: selectedUserId
        )
    }
}
