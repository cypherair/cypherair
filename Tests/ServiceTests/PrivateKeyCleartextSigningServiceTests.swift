import Security
import XCTest
@testable import CypherAir

final class PrivateKeyCleartextSigningServiceTests: XCTestCase {
    private let engine = PgpEngine()

    func test_softwareRouteSignsWithUnwrappedSecretCertificate() async throws {
        let generated = try engine.generateKey(
            name: "Software Signer",
            email: "software@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let keyInfo = try engine.parseKeyInfo(keyData: generated.certData)
        let identity = PGPKeyIdentity(
            fingerprint: keyInfo.fingerprint,
            userId: keyInfo.userId,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            isRevoked: keyInfo.isRevoked,
            isExpired: keyInfo.isExpired,
            isDefault: true,
            isBackedUp: false,
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo,
            expiryDate: keyInfo.expiryTimestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) },
            keyFamily: .portableEd25519LegacyCurve25519Legacy,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
        let router = StaticPrivateKeyOperationRouter(
            route: .softwareSecretCertificate(
                SoftwareSecretCertificateRoute(
                    identity: identity,
                    operation: .sign
                )
            )
        )
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: generated.certData)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            messageAdapter: messageAdapter
        )

        let signed = try await service.signCleartext(
            Data("software cleartext".utf8),
            signerFingerprint: identity.fingerprint
        )

        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [identity.fingerprint])
        let verification = try await verificationResult(
            signed,
            verificationKey: identity.publicKeyData,
            identity: identity,
            messageAdapter: messageAdapter
        )
        XCTAssertEqual(verification.summaryState, .verified)
    }

    func test_secureEnclaveRouteSignsWithoutUnwrappingSecretCertificate() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let router = StaticPrivateKeyOperationRouter(
            route: .secureEnclaveSigner(fixture.route)
        )
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            messageAdapter: messageAdapter,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        let signed = try await service.signCleartext(
            Data("secure enclave cleartext".utf8),
            signerFingerprint: fixture.identity.fingerprint
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let verification = try await verificationResult(
            signed,
            verificationKey: fixture.identity.publicKeyData,
            identity: fixture.identity,
            messageAdapter: messageAdapter
        )
        XCTAssertEqual(verification.summaryState, .verified)
    }

    func test_secureEnclaveCleartextSigningUsesRealCatalogRouterAndSharedHandleStore() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()

        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)

        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = TestHelpers.makeCleartextSigner(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        let signed = try await service.signCleartext(
            Data("secure enclave routed cleartext".utf8),
            signerFingerprint: fixture.identity.fingerprint
        )

        XCTAssertEqual(keyManagement.keys.map(\.fingerprint), [fixture.identity.fingerprint])
        let verification = try await verificationResult(
            signed,
            verificationKey: fixture.identity.publicKeyData,
            identity: fixture.identity,
            messageAdapter: messageAdapter
        )
        XCTAssertEqual(verification.summaryState, .verified)
    }

    func test_blockedRouteThrowsUnavailableCategoryWithoutUnwrapping() async throws {
        let router = StaticPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            _ = try await service.signCleartext(
                Data("blocked".utf8),
                signerFingerprint: "blocked-fingerprint"
            )
            XCTFail("Expected blocked route to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveCallbackFailureMapsToUnavailableCategoryWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let router = StaticPrivateKeyOperationRouter(
            route: .secureEnclaveSigner(fixture.route)
        )
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: ThrowingCleartextDigestSigner(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing)
            )
        )

        do {
            _ = try await service.signCleartext(
                Data("auth failure".utf8),
                signerFingerprint: fixture.identity.fingerprint
            )
            XCTFail("Expected callback failure to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .localAuthenticationFailed)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveRouteEndsOperationAuthorizationAfterSuccessAndAdapterFailure() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()

        let successContext = RecordingLAContext()
        let successService = makeService(
            router: StaticPrivateKeyOperationRouter(
                route: .secureEnclaveSigner(makeAuthorizedRoute(fixture: fixture, context: successContext))
            ),
            unwrapper: RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        )
        _ = try await successService.signCleartext(
            Data("authorized cleartext".utf8),
            signerFingerprint: fixture.identity.fingerprint
        )
        XCTAssertEqual(successContext.invalidateCount, 1)

        let failureContext = RecordingLAContext()
        let failingService = makeService(
            router: StaticPrivateKeyOperationRouter(
                route: .secureEnclaveSigner(makeAuthorizedRoute(fixture: fixture, context: failureContext))
            ),
            unwrapper: RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00])),
            digestSigner: ThrowingCleartextDigestSigner(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing)
            )
        )
        do {
            _ = try await failingService.signCleartext(
                Data("authorized failure".utf8),
                signerFingerprint: fixture.identity.fingerprint
            )
            XCTFail("Expected adapter failure to throw")
        } catch {
        }
        XCTAssertEqual(failureContext.invalidateCount, 1)
    }

    private func makeAuthorizedRoute(
        fixture: SecureEnclaveRouteFixture,
        context: RecordingLAContext
    ) -> SecureEnclaveSignerRoute {
        SecureEnclaveSignerRoute(
            identity: fixture.identity,
            operation: .sign,
            publicBindingInspection: fixture.route.publicBindingInspection,
            signingHandle: fixture.route.signingHandle,
            operationAuthorization: SecureEnclaveCustodyOperationAuthorization(
                authenticationContext: context
            )
        )
    }

    private func makeService(
        router: StaticPrivateKeyOperationRouter,
        unwrapper: RecordingSoftwareSecretCertificateUnwrapper,
        messageAdapter: PGPMessageOperationAdapter? = nil,
        digestSigner: any SecureEnclaveCustodyDigestSigning = SoftwareP256CustodyProvider.shared.digestSigner
    ) -> PrivateKeyCleartextSigningService {
        PrivateKeyCleartextSigningService(
            router: router,
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter ?? PGPMessageOperationAdapter(engine: engine),
            digestSigner: digestSigner,
            compositeSigner: SystemSecureEnclaveCompositeOperations()
        )
    }

    private func verificationResult(
        _ signed: Data,
        verificationKey: Data,
        identity: PGPKeyIdentity,
        messageAdapter: PGPMessageOperationAdapter
    ) async throws -> DetailedSignatureVerification {
        let result = try await messageAdapter.verifyCleartextDetailed(
            signedMessage: signed,
            verificationContext: PGPMessageVerificationContext(
                verificationKeys: [verificationKey],
                contactKeys: [],
                ownKeys: [identity],
                contactsAvailability: .availableProtectedDomain
            )
        )
        return result.verification
    }

    private func makeSecureEnclaveRouteFixture() async throws -> SecureEnclaveRouteFixture {
        let custodyMaterial = SoftwareP256CustodyProvider.shared.makeMaterial()
        let handlePair = try SoftwareP256CustodyProvider.shared.loadedHandlePair(for: custodyMaterial)
        let signingHandle = handlePair.signing
        let keyAgreementHandle = handlePair.keyAgreement
        let material = try await PGPSecureEnclaveCustodyGenerationAdapter(
            engine: engine
        ).generatePublicCertificate(
            name: "Secure Enclave Cleartext",
            email: "secure-cleartext@example.invalid",
            expirySeconds: 3600,
            family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
            handlePair: handlePair,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )
        let identity = PGPKeyIdentity(
            fingerprint: material.metadata.fingerprint,
            userId: material.metadata.userId,
            hasEncryptionSubkey: material.metadata.hasEncryptionSubkey,
            isRevoked: material.metadata.isRevoked,
            isExpired: material.metadata.isExpired,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: material.publicKeyData,
            revocationCert: material.revocationCert,
            primaryAlgo: material.metadata.primaryAlgo,
            subkeyAlgo: material.metadata.subkeyAlgo,
            expiryDate: material.metadata.expiryDate,
            keyFamily: .deviceBoundEcdsaNistP256EcdhNistP256V4,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
        let inspection = try PGPSecureEnclaveCustodyPublicBindingInspector(
            engine: engine
        ).inspectPublicBindings(publicKeyData: material.publicKeyData)

        return SecureEnclaveRouteFixture(
            identity: identity,
            route: SecureEnclaveSignerRoute(
                identity: identity,
                operation: .sign,
                publicBindingInspection: inspection,
                signingHandle: signingHandle
            ),
            keyAgreementHandle: keyAgreementHandle
        )
    }

}

private struct SecureEnclaveRouteFixture {
    let identity: PGPKeyIdentity
    let route: SecureEnclaveSignerRoute
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
}

private final class StaticPrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
    private let routeResult: PrivateKeyOperationRoute
    private(set) var requests: [PrivateKeyOperationRequest] = []

    init(route: PrivateKeyOperationRoute) {
        routeResult = route
    }

    func route(for request: PrivateKeyOperationRequest) async -> PrivateKeyOperationRoute {
        requests.append(request)
        return routeResult
    }
}

private final class RecordingSoftwareSecretCertificateUnwrapper: SoftwareSecretCertificateUnwrapping {
    private let secretCert: Data
    private(set) var unwrapRequests: [String] = []

    init(secretCert: Data) {
        self.secretCert = secretCert
    }

    func unwrapPrivateKey(fingerprint: String) async throws -> Data {
        unwrapRequests.append(fingerprint)
        return secretCert
    }
}

private struct ThrowingCleartextDigestSigner: SecureEnclaveCustodyDigestSigning {
    let error: Error

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw error
    }
}
