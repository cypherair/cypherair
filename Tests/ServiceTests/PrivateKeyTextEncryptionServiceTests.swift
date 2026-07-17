import Security
import XCTest
@testable import CypherAir

final class PrivateKeyTextEncryptionServiceTests: XCTestCase {
    private let engine = PgpEngine()

    func test_unsignedTextEncryptionDoesNotRouteOrUnwrapSigner() async throws {
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let router = StaticTextPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        let ciphertext = try await service.encryptText(
            Data("unsigned text".utf8),
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: nil,
            selfKey: nil
        )

        XCTAssertEqual(router.requests, [])
        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let result = try decrypt(ciphertext, recipientSecret: recipient.certData, verificationKeys: [])
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "unsigned text")
        XCTAssertEqual(result.summaryState, .notSigned)
    }

    func test_softwareRouteSignsWithUnwrappedSecretCertificate() async throws {
        var signer = try engine.generateKey(
            name: "Software Signer",
            email: "software@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        defer { signer.certData.resetBytes(in: 0..<signer.certData.count) }
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let identity = try identity(from: signer, isDefault: true)
        let router = StaticTextPrivateKeyOperationRouter(
            route: .softwareSecretCertificate(
                SoftwareSecretCertificateRoute(identity: identity, operation: .sign)
            )
        )
        let unwrapper = RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: signer.certData)
        let service = makeService(router: router, unwrapper: unwrapper)

        let ciphertext = try await service.encryptText(
            Data("software signed text".utf8),
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: identity.fingerprint,
            selfKey: nil
        )

        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: identity.fingerprint, operation: .sign)
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [identity.fingerprint])
        let result = try decrypt(
            ciphertext,
            recipientSecret: recipient.certData,
            verificationKeys: [identity.publicKeyData]
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "software signed text")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_secureEnclaveRouteSignsWithoutUnwrappingSecretCertificate() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let router = StaticTextPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        let ciphertext = try await service.encryptText(
            Data("secure enclave signed text".utf8),
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: fixture.identity.fingerprint,
            selfKey: nil
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let result = try decrypt(
            ciphertext,
            recipientSecret: recipient.certData,
            verificationKeys: [fixture.identity.publicKeyData]
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "secure enclave signed text")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_secureEnclaveV6RouteSignsAndVerifies() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture(family: .deviceBoundEcdsaNistP256EcdhNistP256)
        XCTAssertEqual(fixture.identity.keyVersion, 6)
        XCTAssertEqual(fixture.identity.keyFamily, .deviceBoundEcdsaNistP256EcdhNistP256)
        XCTAssertEqual(fixture.identity.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)
        var recipient = try makeRecipient(suite: .ed448X448)
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let router = StaticTextPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        let ciphertext = try await service.encryptText(
            Data("secure enclave v6 signed text".utf8),
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: fixture.identity.fingerprint,
            selfKey: nil
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let result = try decrypt(
            ciphertext,
            recipientSecret: recipient.certData,
            verificationKeys: [fixture.identity.publicKeyData]
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "secure enclave v6 signed text")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_secureEnclaveTextSigningUsesRealCatalogRouterAndSharedHandleStore() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let textEncryptor = TestHelpers.makeTextEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )
        let (contactService, contactsDirectory) = await TestHelpers.makeContactService(engine: engine)
        defer { TestHelpers.cleanupTempDir(contactsDirectory) }
        var recipient = try makeRecipient(name: "Route Recipient")
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        try contactService.importContact(publicKeyData: recipient.publicKeyData)
        let recipientInfo = try engine.parseKeyInfo(keyData: recipient.publicKeyData)
        let recipientContactId = try XCTUnwrap(
            contactService.contactId(forFingerprint: recipientInfo.fingerprint)
        )
        let encryptionService = EncryptionService(
            keyManagement: keyManagement,
            contactService: contactService,
            textEncryptor: textEncryptor,
            fileEncryptor: TestHelpers.makeFileEncryptor(
                engine: engine,
                keyManagement: keyManagement,
                messageAdapter: messageAdapter
            )
        )

        let ciphertext = try await encryptionService.encryptText(
            "secure enclave routed text",
            recipientContactIds: [recipientContactId],
            signWithFingerprint: fixture.identity.fingerprint,
            encryptToSelf: false
        )

        XCTAssertEqual(keyManagement.keys.map(\.fingerprint), [fixture.identity.fingerprint])
        let result = try decrypt(
            ciphertext,
            recipientSecret: recipient.certData,
            verificationKeys: [fixture.identity.publicKeyData]
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "secure enclave routed text")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_secureEnclaveTextSigningWithSelfKeyUsesRealRouterAndDoesNotUnwrap() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let unwrapper = RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = PrivateKeyTextEncryptionService(
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
        var recipient = try makeRecipient(name: "Recipient With Self")
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        var selfKey = try makeRecipient(name: "Self Recipient")
        defer { selfKey.certData.resetBytes(in: 0..<selfKey.certData.count) }

        let ciphertext = try await service.encryptText(
            Data("secure enclave text with self key".utf8),
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: fixture.identity.fingerprint,
            selfKey: selfKey.publicKeyData
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        for secret in [recipient.certData, selfKey.certData] {
            let result = try decrypt(
                ciphertext,
                recipientSecret: secret,
                verificationKeys: [fixture.identity.publicKeyData]
            )
            XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "secure enclave text with self key")
            XCTAssertEqual(result.summaryState, .verified)
        }
    }

    func test_blockingPolicyBlocksSecureEnclaveTextSigning() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        let service = TestHelpers.makeTextEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: PGPMessageOperationAdapter(engine: engine),
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveOperationsBlocked),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        )
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }

        do {
            _ = try await service.encryptText(
                Data("blocked by production policy".utf8),
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: fixture.identity.fingerprint,
                selfKey: nil
            )
            XCTFail("Expected blocking policy to stop Secure Enclave signing")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }
    }

    func test_secureEnclaveMissingHandleBlocksWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let service = TestHelpers.makeTextEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: PGPMessageOperationAdapter(engine: engine),
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256)
        )
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }

        do {
            _ = try await service.encryptText(
                Data("missing handle".utf8),
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: fixture.identity.fingerprint,
                selfKey: nil
            )
            XCTFail("Expected missing handle to block")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .privateHandleMissing)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }
    }

    func test_secureEnclaveCancellationMapsToOperationCancelledWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let router = StaticTextPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: ThrowingTextDigestSigner(error: CancellationError())
        )

        do {
            _ = try await service.encryptText(
                Data("cancel text signing".utf8),
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: fixture.identity.fingerprint,
                selfKey: nil
            )
            XCTFail("Expected cancellation to throw")
        } catch CypherAirError.operationCancelled {
            XCTAssertEqual(unwrapper.unwrapRequests, [])
        } catch {
            XCTFail("Expected operationCancelled, got \(error)")
        }
    }

    func test_secureEnclaveCallbackFailuresMapToUnavailableCategoriesWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let cases: [(SecureEnclaveCustodyHandleError, PGPKeyOperationFailureCategory)] = [
            (.localAuthenticationCancelled(.signing), .localAuthenticationCancelled),
            (.localAuthenticationFailed(.signing), .localAuthenticationFailed),
            (.privateOperationRoleMismatch(expected: .signing, actual: .keyAgreement), .privateOperationRoleMismatch),
            (.handlePublicKeyBindingMismatch(.signing), .handlePublicKeyBindingMismatch),
        ]

        for (error, expectedCategory) in cases {
            let router = StaticTextPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
            let unwrapper = RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
            let service = makeService(
                router: router,
                unwrapper: unwrapper,
                digestSigner: ThrowingTextDigestSigner(error: error)
            )

            do {
                _ = try await service.encryptText(
                    Data("callback failure".utf8),
                    recipientKeys: [recipient.publicKeyData],
                    signerFingerprint: fixture.identity.fingerprint,
                    selfKey: nil
                )
                XCTFail("Expected callback failure to throw")
            } catch CypherAirError.keyOperationUnavailable(let category) {
                XCTAssertEqual(category, expectedCategory)
            } catch {
                XCTFail("Expected keyOperationUnavailable, got \(error)")
            }
            XCTAssertEqual(unwrapper.unwrapRequests, [])
        }
    }

    func test_blockedRouteThrowsUnavailableCategoryWithoutUnwrappingOrFFISigning() async throws {
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let router = StaticTextPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            _ = try await service.encryptText(
                Data("blocked".utf8),
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: "blocked-fingerprint",
                selfKey: nil
            )
            XCTFail("Expected blocked route to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveRouteEndsOperationAuthorizationAfterSuccessAndAdapterFailure() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }

        let successContext = RecordingLAContext()
        let successService = makeService(
            router: StaticTextPrivateKeyOperationRouter(
                route: .secureEnclaveSigner(makeAuthorizedRoute(fixture: fixture, context: successContext))
            ),
            unwrapper: RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        )
        _ = try await successService.encryptText(
            Data("authorized text".utf8),
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: fixture.identity.fingerprint,
            selfKey: nil
        )
        XCTAssertEqual(successContext.invalidateCount, 1)

        let failureContext = RecordingLAContext()
        let failingService = makeService(
            router: StaticTextPrivateKeyOperationRouter(
                route: .secureEnclaveSigner(makeAuthorizedRoute(fixture: fixture, context: failureContext))
            ),
            unwrapper: RecordingTextSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00])),
            digestSigner: ThrowingTextDigestSigner(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing)
            )
        )
        do {
            _ = try await failingService.encryptText(
                Data("authorized failure".utf8),
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: fixture.identity.fingerprint,
                selfKey: nil
            )
            XCTFail("Expected adapter failure to throw")
        } catch {
        }
        XCTAssertEqual(failureContext.invalidateCount, 1)
    }

    private func makeAuthorizedRoute(
        fixture: TextSecureEnclaveRouteFixture,
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
        router: StaticTextPrivateKeyOperationRouter,
        unwrapper: RecordingTextSoftwareSecretCertificateUnwrapper,
        messageAdapter: PGPMessageOperationAdapter? = nil,
        digestSigner: any SecureEnclaveCustodyDigestSigning = SoftwareP256CustodyProvider.shared.digestSigner
    ) -> PrivateKeyTextEncryptionService {
        PrivateKeyTextEncryptionService(
            router: router,
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter ?? PGPMessageOperationAdapter(engine: engine),
            digestSigner: digestSigner,
            compositeSigner: SystemSecureEnclaveCompositeOperations()
        )
    }

    private func makeRecipient(
        name: String = "Recipient",
        suite: KeySuite = .ed25519LegacyCurve25519Legacy
    ) throws -> GeneratedKey {
        try engine.generateKey(
            name: name,
            email: "\(name.lowercased().replacingOccurrences(of: " ", with: "-"))@example.invalid",
            expirySeconds: nil,
            suite: suite
        )
    }

    private func identity(from generated: GeneratedKey, isDefault: Bool) throws -> PGPKeyIdentity {
        let keyInfo = try engine.parseKeyInfo(keyData: generated.certData)
        return PGPKeyIdentity(
            fingerprint: keyInfo.fingerprint,
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
            keyFamily: .portableEd25519LegacyCurve25519Legacy,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
    }

    private func decrypt(
        _ ciphertext: Data,
        recipientSecret: Data,
        verificationKeys: [Data]
    ) throws -> DecryptDetailedResult {
        let binary = try engine.dearmor(armored: ciphertext)
        return try engine.decryptDetailed(
            ciphertext: binary,
            secretKeys: [recipientSecret],
            verificationKeys: verificationKeys
        )
    }

    private func makeSecureEnclaveRouteFixture(
        family: PGPKeyFamily = .deviceBoundEcdsaNistP256EcdhNistP256V4
    ) async throws -> TextSecureEnclaveRouteFixture {
        let custodyMaterial = SoftwareP256CustodyProvider.shared.makeMaterial()
        let handlePair = try SoftwareP256CustodyProvider.shared.loadedHandlePair(for: custodyMaterial)
        let signingHandle = handlePair.signing
        let keyAgreementHandle = handlePair.keyAgreement
        let label = family == .deviceBoundEcdsaNistP256EcdhNistP256 ? "v6" : "v4"
        let material = try await PGPSecureEnclaveCustodyGenerationAdapter(
            engine: engine
        ).generatePublicCertificate(
            name: "Secure Enclave Text Encrypt \(label)",
            email: "secure-text-encrypt-\(label)@example.invalid",
            expirySeconds: 3600,
            family: family,
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
            keyFamily: family,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
        let inspection = try PGPSecureEnclaveCustodyPublicBindingInspector(
            engine: engine
        ).inspectPublicBindings(publicKeyData: material.publicKeyData)

        return TextSecureEnclaveRouteFixture(
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

private struct TextSecureEnclaveRouteFixture {
    let identity: PGPKeyIdentity
    let route: SecureEnclaveSignerRoute
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
}

private final class StaticTextPrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
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

private final class RecordingTextSoftwareSecretCertificateUnwrapper: SoftwareSecretCertificateUnwrapping {
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

private struct ThrowingTextDigestSigner: SecureEnclaveCustodyDigestSigning {
    let error: Error

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw error
    }
}
