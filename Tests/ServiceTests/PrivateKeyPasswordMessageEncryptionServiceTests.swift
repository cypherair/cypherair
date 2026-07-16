import Security
import XCTest
@testable import CypherAir

final class PrivateKeyPasswordMessageEncryptionServiceTests: XCTestCase {
    private let engine = PgpEngine()

    func test_unsignedPasswordEncryptionDoesNotRouteOrUnwrapSigner() async throws {
        let router = StaticPasswordPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        let ciphertext = try await service.encrypt(
            plaintext: Data("unsigned password message".utf8),
            password: "unsigned-password",
            format: .seipdv1,
            signerFingerprint: nil,
            binary: false
        )

        XCTAssertEqual(router.requests, [])
        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let result = try decryptPassword(
            ciphertext,
            password: "unsigned-password",
            verificationKeys: []
        )
        XCTAssertEqual(result.status, .decrypted)
        XCTAssertEqual(String(data: try XCTUnwrap(result.plaintext), encoding: .utf8), "unsigned password message")
        XCTAssertEqual(result.summaryState, .notSigned)
    }

    func test_softwareRouteSignsWithUnwrappedSecretCertificate() async throws {
        var signer = try engine.generateKey(
            name: "Password Software Signer",
            email: "password-software@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        defer { signer.certData.resetBytes(in: 0..<signer.certData.count) }
        let identity = try identity(from: signer, isDefault: true)
        let router = StaticPasswordPrivateKeyOperationRouter(
            route: .softwareSecretCertificate(
                SoftwareSecretCertificateRoute(identity: identity, operation: .sign)
            )
        )
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: signer.certData)
        let service = makeService(router: router, unwrapper: unwrapper)

        let ciphertext = try await service.encrypt(
            plaintext: Data("software signed password message".utf8),
            password: "software-password",
            format: .seipdv2,
            signerFingerprint: identity.fingerprint,
            binary: true
        )

        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: identity.fingerprint, operation: .sign)
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [identity.fingerprint])
        let result = try decryptPassword(
            ciphertext,
            password: "software-password",
            verificationKeys: [identity.publicKeyData]
        )
        XCTAssertEqual(result.status, .decrypted)
        XCTAssertEqual(String(data: try XCTUnwrap(result.plaintext), encoding: .utf8), "software signed password message")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_secureEnclaveRouteSignsWithoutUnwrappingSecretCertificate() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let router = StaticPasswordPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        let ciphertext = try await service.encrypt(
            plaintext: Data("secure enclave signed password message".utf8),
            password: "secure-enclave-password",
            format: .seipdv1,
            signerFingerprint: fixture.identity.fingerprint,
            binary: false
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let result = try decryptPassword(
            ciphertext,
            password: "secure-enclave-password",
            verificationKeys: [fixture.identity.publicKeyData]
        )
        XCTAssertEqual(result.status, .decrypted)
        XCTAssertEqual(String(data: try XCTUnwrap(result.plaintext), encoding: .utf8), "secure enclave signed password message")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_secureEnclaveV6RouteSignsPasswordMessage() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture(configurationIdentity: .modernP256V6)
        XCTAssertEqual(fixture.identity.keyVersion, 6)
        XCTAssertEqual(fixture.identity.openPGPConfigurationIdentity, .modernP256V6)
        XCTAssertEqual(fixture.identity.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)
        let router = StaticPasswordPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        let ciphertext = try await service.encrypt(
            plaintext: Data("secure enclave v6 password message".utf8),
            password: "secure-enclave-v6-password",
            format: .seipdv2,
            signerFingerprint: fixture.identity.fingerprint,
            binary: true
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let result = try decryptPassword(
            ciphertext,
            password: "secure-enclave-v6-password",
            verificationKeys: [fixture.identity.publicKeyData]
        )
        XCTAssertEqual(result.status, .decrypted)
        XCTAssertEqual(String(data: try XCTUnwrap(result.plaintext), encoding: .utf8), "secure enclave v6 password message")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_blockingPolicyBlocksSecureEnclavePasswordSigningWithoutFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = PrivateKeyPasswordMessageEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveOperationsBlocked),
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256)
            ),
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner,
            compositeSigner: SystemSecureEnclaveCompositeOperations()
        )

        do {
            _ = try await service.encrypt(
                plaintext: Data("blocked password message".utf8),
                password: "blocked-password",
                format: .seipdv1,
                signerFingerprint: fixture.identity.fingerprint,
                binary: false
            )
            XCTFail("Expected blocking policy to stop Secure Enclave password signing")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclavePasswordSigningUsesRealCatalogRouterAndSharedHandleStore() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let passwordEncryptor = PrivateKeyPasswordMessageEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
            ),
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner,
            compositeSigner: SystemSecureEnclaveCompositeOperations()
        )
        let (contactService, contactsDirectory) = await TestHelpers.makeContactService(engine: engine)
        defer { TestHelpers.cleanupTempDir(contactsDirectory) }
        let passwordService = PasswordMessageService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            passwordEncryptor: passwordEncryptor
        )

        let ciphertext = try await passwordService.encryptText(
            "secure enclave routed password message",
            password: "real-router-password",
            format: .seipdv1,
            signWithFingerprint: fixture.identity.fingerprint
        )
        let outcome = try await passwordService.decryptMessageDetailed(
            ciphertext: ciphertext,
            password: "real-router-password"
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        guard case let .decrypted(plaintext, verification) = outcome else {
            return XCTFail("Expected decrypted outcome")
        }
        XCTAssertEqual(String(data: plaintext, encoding: .utf8), "secure enclave routed password message")
        XCTAssertEqual(verification.summaryState, .verified)
        XCTAssertEqual(verification.signatures.first?.signerPrimaryFingerprint, fixture.identity.fingerprint)
    }

    func test_missingHandleSurfacesUnavailableWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = PrivateKeyPasswordMessageEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256)
            ),
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner,
            compositeSigner: SystemSecureEnclaveCompositeOperations()
        )

        do {
            _ = try await service.encrypt(
                plaintext: Data("missing handle password message".utf8),
                password: "missing-handle-password",
                format: .seipdv1,
                signerFingerprint: fixture.identity.fingerprint,
                binary: false
            )
            XCTFail("Expected missing handle to fail")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .privateHandleMissing)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveCancellationMapsToOperationCancelledWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let router = StaticPasswordPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: ThrowingPasswordDigestSigner(error: CancellationError())
        )

        do {
            _ = try await service.encrypt(
                plaintext: Data("cancel password message".utf8),
                password: "cancel-password",
                format: .seipdv1,
                signerFingerprint: fixture.identity.fingerprint,
                binary: false
            )
            XCTFail("Expected cancellation to throw")
        } catch CypherAirError.operationCancelled {
            // Expected
        } catch {
            XCTFail("Expected operationCancelled, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveAuthFailureMapsToUnavailableCategoryWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let router = StaticPasswordPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: ThrowingPasswordDigestSigner(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing)
            )
        )

        do {
            _ = try await service.encrypt(
                plaintext: Data("auth failure password message".utf8),
                password: "auth-failure-password",
                format: .seipdv1,
                signerFingerprint: fixture.identity.fingerprint,
                binary: false
            )
            XCTFail("Expected auth failure to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .localAuthenticationFailed)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveWrongRoleMapsToUnavailableCategoryWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let wrongRoleRoute = SecureEnclaveSignerRoute(
            identity: fixture.identity,
            operation: .sign,
            publicBindingInspection: fixture.route.publicBindingInspection,
            signingHandle: fixture.keyAgreementHandle
        )
        let router = StaticPasswordPrivateKeyOperationRouter(route: .secureEnclaveSigner(wrongRoleRoute))
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        do {
            _ = try await service.encrypt(
                plaintext: Data("wrong role password message".utf8),
                password: "wrong-role-password",
                format: .seipdv1,
                signerFingerprint: fixture.identity.fingerprint,
                binary: false
            )
            XCTFail("Expected wrong role to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .privateOperationRoleMismatch)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_blockedRouteDoesNotCallFFIOrUnwrap() async throws {
        let router = StaticPasswordPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            _ = try await service.encrypt(
                plaintext: Data("blocked password message".utf8),
                password: "blocked-password",
                format: .seipdv1,
                signerFingerprint: "blocked-fingerprint",
                binary: false
            )
            XCTFail("Expected blocked route to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: "blocked-fingerprint", operation: .sign)
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveRouteEndsOperationAuthorizationAfterSuccessAndAdapterFailure() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()

        let successContext = RecordingLAContext()
        let successService = makeService(
            router: StaticPasswordPrivateKeyOperationRouter(
                route: .secureEnclaveSigner(makeAuthorizedRoute(fixture: fixture, context: successContext))
            ),
            unwrapper: RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        )
        _ = try await successService.encrypt(
            plaintext: Data("authorized password message".utf8),
            password: "authorized-password",
            format: .seipdv1,
            signerFingerprint: fixture.identity.fingerprint,
            binary: false
        )
        XCTAssertEqual(successContext.invalidateCount, 1)

        let failureContext = RecordingLAContext()
        let failingService = makeService(
            router: StaticPasswordPrivateKeyOperationRouter(
                route: .secureEnclaveSigner(makeAuthorizedRoute(fixture: fixture, context: failureContext))
            ),
            unwrapper: RecordingPasswordSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00])),
            digestSigner: ThrowingPasswordDigestSigner(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing)
            )
        )
        do {
            _ = try await failingService.encrypt(
                plaintext: Data("authorized failure".utf8),
                password: "authorized-failure-password",
                format: .seipdv1,
                signerFingerprint: fixture.identity.fingerprint,
                binary: false
            )
            XCTFail("Expected adapter failure to throw")
        } catch {
        }
        XCTAssertEqual(failureContext.invalidateCount, 1)
    }

    private func makeAuthorizedRoute(
        fixture: PasswordSecureEnclaveRouteFixture,
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
        router: StaticPasswordPrivateKeyOperationRouter,
        unwrapper: RecordingPasswordSoftwareSecretCertificateUnwrapper,
        messageAdapter: PGPMessageOperationAdapter? = nil,
        digestSigner: any SecureEnclaveCustodyDigestSigning = SoftwareP256CustodyProvider.shared.digestSigner
    ) -> PrivateKeyPasswordMessageEncryptionService {
        PrivateKeyPasswordMessageEncryptionService(
            router: router,
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter ?? PGPMessageOperationAdapter(engine: engine),
            digestSigner: digestSigner,
            compositeSigner: SystemSecureEnclaveCompositeOperations()
        )
    }

    private func identity(from generated: GeneratedKey, isDefault: Bool) throws -> PGPKeyIdentity {
        let keyInfo = try engine.parseKeyInfo(keyData: generated.certData)
        return PGPKeyIdentity(
            fingerprint: keyInfo.fingerprint,
            keyVersion: UInt8(keyInfo.keyVersion),
            userId: keyInfo.userId,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            isRevoked: keyInfo.isRevoked,
            isExpired: keyInfo.isExpired,
            isDefault: isDefault,
            isBackedUp: false,
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo,
            expiryDate: keyInfo.expiryTimestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) },
            openPGPConfigurationIdentity: .modernHighSoftwareV6,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
    }

    private func decryptPassword(
        _ ciphertext: Data,
        password: String,
        verificationKeys: [Data]
    ) throws -> PasswordDecryptResult {
        try engine.decryptWithPassword(
            ciphertext: ciphertext,
            password: password,
            verificationKeys: verificationKeys
        )
    }

    private func makeSecureEnclaveRouteFixture(
        configurationIdentity: PGPKeyConfiguration.Identity = .compatibleP256V4
    ) async throws -> PasswordSecureEnclaveRouteFixture {
        let custodyMaterial = SoftwareP256CustodyProvider.shared.makeMaterial()
        let signingPublicKeyX963 = custodyMaterial.signingPublicKeyX963
        let keyAgreementPublicKeyX963 = custodyMaterial.keyAgreementPublicKeyX963
        let handleSetIdentifier = try SecureEnclaveCustodyHandleReference.generateHandleSetIdentifier()
        let signingReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .signing,
            tier: .classicalP256
        )
        let keyAgreementReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .keyAgreement,
            tier: .classicalP256
        )
        let signingHandle = SecureEnclaveCustodyLoadedHandle(
            binding: try SecureEnclaveCustodyHandlePublicBinding(
                reference: signingReference,
                publicKeyRaw: signingPublicKeyX963
            ),
            privateKey: nil
        )
        let keyAgreementHandle = SecureEnclaveCustodyLoadedHandle(
            binding: try SecureEnclaveCustodyHandlePublicBinding(
                reference: keyAgreementReference,
                publicKeyRaw: keyAgreementPublicKeyX963
            ),
            privateKey: nil
        )
        let handlePair = try SecureEnclaveCustodyLoadedHandlePair(
            signing: signingHandle,
            keyAgreement: keyAgreementHandle
        )
        let label = configurationIdentity == .modernP256V6 ? "v6" : "v4"
        let material = try await PGPSecureEnclaveCustodyGenerationAdapter(
            engine: engine
        ).generatePublicCertificate(
            name: "Secure Enclave Password \(label)",
            email: "secure-password-\(label)@example.invalid",
            expirySeconds: 3600,
            configuration: configurationIdentity.configuration,
            handlePair: handlePair,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )
        let identity = PGPKeyIdentity(
            fingerprint: material.metadata.fingerprint,
            keyVersion: material.metadata.keyVersion,
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
            openPGPConfigurationIdentity: configurationIdentity,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
        let inspection = try PGPSecureEnclaveCustodyPublicBindingInspector(
            engine: engine
        ).inspectPublicBindings(publicKeyData: material.publicKeyData)

        return PasswordSecureEnclaveRouteFixture(
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

private struct PasswordSecureEnclaveRouteFixture {
    let identity: PGPKeyIdentity
    let route: SecureEnclaveSignerRoute
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
}

private final class StaticPasswordPrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
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

private final class RecordingPasswordSoftwareSecretCertificateUnwrapper: SoftwareSecretCertificateUnwrapping {
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

private struct ThrowingPasswordDigestSigner: SecureEnclaveCustodyDigestSigning {
    let error: Error

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw error
    }
}
