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
    private let compositeSigner: any SecureEnclaveCompositeSigning

    init(
        router: any PrivateKeyOperationRouting,
        softwarePrivateKeyAccess: any SoftwareSecretCertificateUnwrapping,
        messageAdapter: PGPMessageOperationAdapter,
        digestSigner: any SecureEnclaveCustodyDigestSigning,
        compositeSigner: any SecureEnclaveCompositeSigning
    ) {
        self.router = router
        self.softwarePrivateKeyAccess = softwarePrivateKeyAccess
        self.messageAdapter = messageAdapter
        self.digestSigner = digestSigner
        self.compositeSigner = compositeSigner
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

        let operationRoute = await router.route(
            for: PrivateKeyOperationRequest(
                fingerprint: signerFingerprint,
                operation: .sign
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

        case .secureEnclaveCompositeSigner(let route):
            switch route.signingHandle.reference.tier {
            case .classicalP256:
                // A classical handle can never ride a composite route; the
                // router dispatches by tier before building route values.
                throw CypherAirError.keyOperationUnavailable(category: .invalidConfigurationCustody)
            case .postQuantum:
                return try await messageAdapter.encryptWithExternalCompositeSigner(
                    plaintext: plaintext,
                    recipientKeys: recipientKeys,
                    signingPublicCert: route.identity.publicKeyData,
                    signingKeyFingerprint: route.compositeBindingInspection.signingKeyFingerprint,
                    classicalEddsaSecret: route.classicalComponent.eddsaSecret,
                    signingProvider: PGPExternalMlDsa65SigningProviderBridge(
                        handle: route.signingHandle,
                        compositeSigner: compositeSigner
                    ),
                    selfKey: selfKey
                )
            case .postQuantumHigh:
                return try await messageAdapter.encryptWithExternalCompositeHighSigner(
                    plaintext: plaintext,
                    recipientKeys: recipientKeys,
                    signingPublicCert: route.identity.publicKeyData,
                    signingKeyFingerprint: route.compositeBindingInspection.signingKeyFingerprint,
                    classicalEddsaSecret: route.classicalComponent.eddsaSecret,
                    signingProvider: PGPExternalMlDsa87SigningProviderBridge(
                        handle: route.signingHandle,
                        compositeSigner: compositeSigner
                    ),
                    selfKey: selfKey
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
