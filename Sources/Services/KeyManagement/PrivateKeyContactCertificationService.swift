import Foundation

protocol ContactCertificationSigning: Sendable {
    func generateUserIdCertification(
        signerFingerprint: String,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: OpenPGPCertificationKind
    ) async throws -> Data
}

final class PrivateKeyContactCertificationService: ContactCertificationSigning, @unchecked Sendable {
    private let router: any PrivateKeyOperationRouting
    private let softwarePrivateKeyAccess: any SoftwareSecretCertificateUnwrapping
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let digestSigner: any SecureEnclaveCustodyDigestSigning
    private let compositeSigner: any SecureEnclaveCompositeSigning

    init(
        router: any PrivateKeyOperationRouting,
        softwarePrivateKeyAccess: any SoftwareSecretCertificateUnwrapping,
        certificateAdapter: PGPCertificateOperationAdapter,
        digestSigner: any SecureEnclaveCustodyDigestSigning,
        compositeSigner: any SecureEnclaveCompositeSigning = SystemSecureEnclaveCompositeOperations()
    ) {
        self.router = router
        self.softwarePrivateKeyAccess = softwarePrivateKeyAccess
        self.certificateAdapter = certificateAdapter
        self.digestSigner = digestSigner
        self.compositeSigner = compositeSigner
    }

    func generateUserIdCertification(
        signerFingerprint: String,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: OpenPGPCertificationKind
    ) async throws -> Data {
        let operationRoute = await router.route(
            for: PrivateKeyOperationRequest(
                fingerprint: signerFingerprint,
                operation: .certify
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
            return try await certificateAdapter.generateUserIdCertification(
                signerSecretCert: secretKey,
                targetCert: targetCert,
                selectedUserId: selectedUserId,
                certificationKind: certificationKind
            )

        case .secureEnclaveSigner(let route):
            return try await certificateAdapter.generateUserIdCertificationWithExternalP256Signer(
                publicCert: route.identity.publicKeyData,
                signingKeyFingerprint: route.publicBindingInspection.signingKeyFingerprint,
                signingProvider: PGPExternalP256SigningProviderBridge(
                    handle: route.signingHandle,
                    digestSigner: digestSigner
                ),
                targetCert: targetCert,
                selectedUserId: selectedUserId,
                certificationKind: certificationKind
            )

        case .secureEnclaveCompositeSigner(let route):
            switch route.signingHandle.reference.tier {
            case .postQuantum:
                return try await certificateAdapter.generateUserIdCertificationWithExternalCompositeSigner(
                    publicCert: route.identity.publicKeyData,
                    signingKeyFingerprint: route.compositeBindingInspection.signingKeyFingerprint,
                    classicalEddsaSecret: route.classicalComponent.eddsaSecret,
                    signingProvider: PGPExternalMlDsa65SigningProviderBridge(
                        handle: route.signingHandle,
                        compositeSigner: compositeSigner
                    ),
                    targetCert: targetCert,
                    selectedUserId: selectedUserId,
                    certificationKind: certificationKind
                )
            case .postQuantumHigh:
                return try await certificateAdapter.generateUserIdCertificationWithExternalCompositeHighSigner(
                    publicCert: route.identity.publicKeyData,
                    signingKeyFingerprint: route.compositeBindingInspection.signingKeyFingerprint,
                    classicalEddsaSecret: route.classicalComponent.eddsaSecret,
                    signingProvider: PGPExternalMlDsa87SigningProviderBridge(
                        handle: route.signingHandle,
                        compositeSigner: compositeSigner
                    ),
                    targetCert: targetCert,
                    selectedUserId: selectedUserId,
                    certificationKind: certificationKind
                )
            }

        case .secureEnclaveKeyAgreement, .secureEnclaveCompositeKeyAgreement:
            throw CypherAirError.keyOperationUnavailable(category: .privateOperationRoleMismatch)

        case .blocked(let resolution):
            throw CypherAirError.keyOperationUnavailable(
                category: resolution.failureCategory ?? .operationUnavailableByPolicy
            )
        }
    }
}
