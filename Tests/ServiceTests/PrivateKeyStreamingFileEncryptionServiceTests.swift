import Security
import XCTest
@testable import CypherAir

final class PrivateKeyStreamingFileEncryptionServiceTests: XCTestCase {
    private let engine = PgpEngine()

    func test_unsignedFileEncryptionDoesNotRouteOrUnwrapSigner() async throws {
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let input = try makeTemporaryFile(Data("unsigned streaming file".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        try await service.encryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: nil,
            selfKey: nil,
            progress: nil
        )

        XCTAssertEqual(router.requests, [])
        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let result = try decryptFile(
            output,
            recipientSecret: recipient.certData,
            verificationKeys: []
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "unsigned streaming file")
        XCTAssertEqual(result.summaryState, .notSigned)
    }

    func test_softwareRouteSignsWithUnwrappedSecretCertificate() async throws {
        var signer = try engine.generateKey(
            name: "Software File Signer",
            email: "software-file-signer@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        defer { signer.certData.resetBytes(in: 0..<signer.certData.count) }
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let identity = try identity(from: signer, isDefault: true)
        let input = try makeTemporaryFile(Data("software signed streaming file".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(
            route: .softwareSecretCertificate(
                SoftwareSecretCertificateRoute(identity: identity, operation: .sign)
            )
        )
        let unwrapper = RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: signer.certData)
        let service = makeService(router: router, unwrapper: unwrapper)

        try await service.encryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: identity.fingerprint,
            selfKey: nil,
            progress: nil
        )

        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: identity.fingerprint, operation: .sign)
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [identity.fingerprint])
        let result = try decryptFile(
            output,
            recipientSecret: recipient.certData,
            verificationKeys: [identity.publicKeyData]
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "software signed streaming file")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_secureEnclaveRouteSignsFileWithoutUnwrappingSecretCertificate() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let input = try makeTemporaryFile(Data("secure enclave signed streaming file".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        try await service.encryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: fixture.identity.fingerprint,
            selfKey: nil,
            progress: nil
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let result = try decryptFile(
            output,
            recipientSecret: recipient.certData,
            verificationKeys: [fixture.identity.publicKeyData]
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "secure enclave signed streaming file")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_secureEnclaveV6RouteSignsFileAndVerifies() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture(family: .deviceBoundEcdsaNistP256EcdhNistP256)
        XCTAssertEqual(fixture.identity.keyVersion, 6)
        XCTAssertEqual(fixture.identity.keyFamily, .deviceBoundEcdsaNistP256EcdhNistP256)
        XCTAssertEqual(fixture.identity.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)
        var recipient = try makeRecipient(suite: .ed448X448)
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let input = try makeTemporaryFile(Data("secure enclave v6 signed streaming file".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        try await service.encryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: fixture.identity.fingerprint,
            selfKey: nil,
            progress: nil
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let result = try decryptFile(
            output,
            recipientSecret: recipient.certData,
            verificationKeys: [fixture.identity.publicKeyData]
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "secure enclave v6 signed streaming file")
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_secureEnclaveFileSigningUsesRealCatalogRouterSharedHandleStoreAndDefaultSelfKey() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        var selfSecret = try engine.generateKey(
            name: "Default Self",
            email: "default-self@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        defer { selfSecret.certData.resetBytes(in: 0..<selfSecret.certData.count) }
        let selfKey = try TestHelpers.provisionFixtureBackedIdentity(
            secretCertData: selfSecret.certData,
            engine: engine,
            service: keyManagement,
            mockSE: mockSE,
            mockKC: mockKeychain,
            metadataPersistence: metadataPersistence,
            isDefault: true
        )
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let fileEncryptor = TestHelpers.makeFileEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )
        let textEncryptor = TestHelpers.makeTextEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let (contactService, contactsDirectory) = await TestHelpers.makeContactService(engine: engine)
        defer { TestHelpers.cleanupTempDir(contactsDirectory) }
        var recipient = try makeRecipient(name: "Route File Recipient")
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        try contactService.importContact(publicKeyData: recipient.publicKeyData)
        let recipientInfo = try engine.parseKeyInfo(keyData: recipient.publicKeyData)
        let recipientContactId = try XCTUnwrap(
            contactService.contactId(forFingerprint: recipientInfo.fingerprint)
        )
        let tempRoot = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempRoot) }
        let artifactStore = AppTemporaryArtifactStore(temporaryDirectory: tempRoot)
        let encryptionService = EncryptionService(
            keyManagement: keyManagement,
            contactService: contactService,
            textEncryptor: textEncryptor,
            fileEncryptor: fileEncryptor,
            temporaryArtifactStore: artifactStore
        )
        let input = try makeTemporaryFile(Data("secure enclave routed streaming file".utf8))
        defer { try? FileManager.default.removeItem(at: input) }

        let artifact = try await encryptionService.encryptFileStreaming(
            inputURL: input,
            recipientContactIds: [recipientContactId],
            signWithFingerprint: fixture.identity.fingerprint,
            encryptToSelf: true,
            progress: nil
        )
        defer { artifact.cleanup() }

        XCTAssertEqual(keyManagement.keys.map(\.fingerprint).sorted(), [
            fixture.identity.fingerprint,
            selfKey.fingerprint,
        ].sorted())
        XCTAssertTrue(FileManager.default.fileExists(atPath: artifact.fileURL.path))
        for secret in [recipient.certData, selfSecret.certData] {
            let result = try decryptFile(
                artifact.fileURL,
                recipientSecret: secret,
                verificationKeys: [fixture.identity.publicKeyData]
            )
            XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "secure enclave routed streaming file")
            XCTAssertEqual(result.summaryState, .verified)
        }
    }

    func test_secureEnclaveFileSigningWithExplicitSelfKeyDoesNotUnwrap() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        var recipient = try makeRecipient(name: "Recipient With Explicit Self")
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        var selfKey = try makeRecipient(name: "Explicit Self")
        defer { selfKey.certData.resetBytes(in: 0..<selfKey.certData.count) }
        let input = try makeTemporaryFile(Data("secure enclave file with explicit self key".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )

        try await service.encryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: fixture.identity.fingerprint,
            selfKey: selfKey.publicKeyData,
            progress: nil
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        for secret in [recipient.certData, selfKey.certData] {
            let result = try decryptFile(
                output,
                recipientSecret: secret,
                verificationKeys: [fixture.identity.publicKeyData]
            )
            XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "secure enclave file with explicit self key")
            XCTAssertEqual(result.summaryState, .verified)
        }
    }

    func test_blockingPolicyBlocksSecureEnclaveFileSigningWithoutFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let service = TestHelpers.makeFileEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: PGPMessageOperationAdapter(engine: engine),
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveOperationsBlocked)
        )
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let input = try makeTemporaryFile(Data("blocked secure enclave streaming file".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }

        do {
            try await service.encryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: fixture.identity.fingerprint,
                selfKey: nil,
                progress: nil
            )
            XCTFail("Expected blocking policy to stop Secure Enclave file signing")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }
    }

    func test_missingHandleSurfacesUnavailableWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let service = TestHelpers.makeFileEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: PGPMessageOperationAdapter(engine: engine),
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256)
        )
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let input = try makeTemporaryFile(Data("missing handle streaming file".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }

        do {
            try await service.encryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: fixture.identity.fingerprint,
                selfKey: nil,
                progress: nil
            )
            XCTFail("Expected missing handle to fail")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .privateHandleMissing)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }
    }

    func test_progressCancellationMapsToOperationCancelledWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let input = try makeTemporaryFile(Data(repeating: 0x42, count: 128 * 1024))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: UnexpectedStreamingDigestSigner()
        )
        let progress = FileProgressReporter()
        progress.cancel()

        do {
            try await service.encryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: fixture.identity.fingerprint,
                selfKey: nil,
                progress: progress
            )
            XCTFail("Expected progress cancellation to throw")
        } catch CypherAirError.operationCancelled {
            XCTAssertEqual(unwrapper.unwrapRequests, [])
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        } catch {
            XCTFail("Expected operationCancelled, got \(error)")
        }
    }

    func test_secureEnclaveCancellationMapsToOperationCancelledWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let input = try makeTemporaryFile(Data("cancel streaming file signing".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: ThrowingStreamingDigestSigner(error: CancellationError())
        )

        do {
            try await service.encryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: fixture.identity.fingerprint,
                selfKey: nil,
                progress: nil
            )
            XCTFail("Expected cancellation to throw")
        } catch CypherAirError.operationCancelled {
            XCTAssertEqual(unwrapper.unwrapRequests, [])
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
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
            let input = try makeTemporaryFile(Data("callback streaming file failure".utf8))
            let output = makeTemporaryOutputURL()
            defer { cleanup(input, output) }
            let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
            let unwrapper = RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
            let service = makeService(
                router: router,
                unwrapper: unwrapper,
                digestSigner: ThrowingStreamingDigestSigner(error: error)
            )

            do {
                try await service.encryptFile(
                    inputPath: input.path,
                    outputPath: output.path,
                    recipientKeys: [recipient.publicKeyData],
                    signerFingerprint: fixture.identity.fingerprint,
                    selfKey: nil,
                    progress: nil
                )
                XCTFail("Expected callback failure to throw")
            } catch CypherAirError.keyOperationUnavailable(let category) {
                XCTAssertEqual(category, expectedCategory)
                XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
            } catch {
                XCTFail("Expected keyOperationUnavailable, got \(error)")
            }
            XCTAssertEqual(unwrapper.unwrapRequests, [])
        }
    }

    func test_blockedRouteThrowsUnavailableCategoryWithoutUnwrappingOrFFI() async throws {
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let input = try makeTemporaryFile(Data("blocked streaming file".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            try await service.encryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: "blocked-fingerprint",
                selfKey: nil,
                progress: nil
            )
            XCTFail("Expected blocked route to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_encryptionServiceCleansTemporaryArtifactOnSecureEnclaveSigningFailure() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let fileEncryptor = makeService(
            router: router,
            unwrapper: RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00])),
            digestSigner: ThrowingStreamingDigestSigner(error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing))
        )
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let textEncryptor = TestHelpers.makeTextEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let (contactService, contactsDirectory) = await TestHelpers.makeContactService(engine: engine)
        defer { TestHelpers.cleanupTempDir(contactsDirectory) }
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        try contactService.importContact(publicKeyData: recipient.publicKeyData)
        let recipientInfo = try engine.parseKeyInfo(keyData: recipient.publicKeyData)
        let recipientContactId = try XCTUnwrap(
            contactService.contactId(forFingerprint: recipientInfo.fingerprint)
        )
        let tempRoot = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempRoot) }
        let artifactStore = AppTemporaryArtifactStore(temporaryDirectory: tempRoot)
        let encryptionService = EncryptionService(
            keyManagement: keyManagement,
            contactService: contactService,
            textEncryptor: textEncryptor,
            fileEncryptor: fileEncryptor,
            temporaryArtifactStore: artifactStore
        )
        let input = try makeTemporaryFile(Data("cleanup failed streaming file".utf8))
        defer { try? FileManager.default.removeItem(at: input) }

        do {
            _ = try await encryptionService.encryptFileStreaming(
                inputURL: input,
                recipientContactIds: [recipientContactId],
                signWithFingerprint: fixture.identity.fingerprint,
                encryptToSelf: false,
                progress: nil
            )
            XCTFail("Expected signing failure")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .localAuthenticationFailed)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        let streamingRoot = tempRoot.appendingPathComponent("streaming", isDirectory: true)
        let streamingContents = (
            try? FileManager.default.contentsOfDirectory(
                at: streamingRoot,
                includingPropertiesForKeys: nil
            )
        ) ?? []
        XCTAssertTrue(streamingContents.isEmpty)
    }

    func test_secureEnclaveRouteEndsOperationAuthorizationAfterSuccessAndAdapterFailure() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        var recipient = try makeRecipient()
        defer { recipient.certData.resetBytes(in: 0..<recipient.certData.count) }
        let input = try makeTemporaryFile(Data("authorized streaming file".utf8))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }

        let successContext = RecordingLAContext()
        let successService = makeService(
            router: StaticStreamingPrivateKeyOperationRouter(
                route: .secureEnclaveSigner(makeAuthorizedRoute(fixture: fixture, context: successContext))
            ),
            unwrapper: RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        )
        try await successService.encryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientKeys: [recipient.publicKeyData],
            signerFingerprint: fixture.identity.fingerprint,
            selfKey: nil,
            progress: nil
        )
        XCTAssertEqual(successContext.invalidateCount, 1)

        let failureOutput = makeTemporaryOutputURL()
        defer { try? FileManager.default.removeItem(at: failureOutput) }
        let failureContext = RecordingLAContext()
        let failingService = makeService(
            router: StaticStreamingPrivateKeyOperationRouter(
                route: .secureEnclaveSigner(makeAuthorizedRoute(fixture: fixture, context: failureContext))
            ),
            unwrapper: RecordingStreamingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00])),
            digestSigner: ThrowingStreamingDigestSigner(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing)
            )
        )
        do {
            try await failingService.encryptFile(
                inputPath: input.path,
                outputPath: failureOutput.path,
                recipientKeys: [recipient.publicKeyData],
                signerFingerprint: fixture.identity.fingerprint,
                selfKey: nil,
                progress: nil
            )
            XCTFail("Expected adapter failure to throw")
        } catch {
        }
        XCTAssertEqual(failureContext.invalidateCount, 1)
    }

    private func makeAuthorizedRoute(
        fixture: StreamingSecureEnclaveRouteFixture,
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
        router: StaticStreamingPrivateKeyOperationRouter,
        unwrapper: RecordingStreamingSoftwareSecretCertificateUnwrapper,
        messageAdapter: PGPMessageOperationAdapter? = nil,
        digestSigner: any SecureEnclaveCustodyDigestSigning = SoftwareP256CustodyProvider.shared.digestSigner
    ) -> PrivateKeyStreamingFileEncryptionService {
        PrivateKeyStreamingFileEncryptionService(
            router: router,
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter ?? PGPMessageOperationAdapter(engine: engine),
            digestSigner: digestSigner,
            compositeSigner: SystemSecureEnclaveCompositeOperations()
        )
    }

    private func makeRecipient(
        name: String = "Streaming Recipient",
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
            keyFamily: keyInfo.keyVersion == 6 ? .portableEd448X448 : .portableEd25519LegacyCurve25519Legacy,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
    }

    private func decryptFile(
        _ output: URL,
        recipientSecret: Data,
        verificationKeys: [Data]
    ) throws -> DecryptDetailedResult {
        try engine.decryptDetailed(
            ciphertext: Data(contentsOf: output),
            secretKeys: [recipientSecret],
            verificationKeys: verificationKeys
        )
    }

    private func makeTemporaryFile(
        _ contents: Data,
        name: String = "streaming-encrypt-\(UUID().uuidString).bin"
    ) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try contents.write(to: url, options: .atomic)
        return url
    }

    private func makeTemporaryOutputURL(
        name: String = "streaming-encrypt-output-\(UUID().uuidString).gpg"
    ) -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(name)
    }

    private func makeTemporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(
            "streaming-file-encrypt-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func cleanup(_ urls: URL...) {
        for url in urls {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private func makeSecureEnclaveRouteFixture(
        family: PGPKeyFamily = .deviceBoundEcdsaNistP256EcdhNistP256V4
    ) async throws -> StreamingSecureEnclaveRouteFixture {
        let custodyMaterial = SoftwareP256CustodyProvider.shared.makeMaterial()
        let handlePair = try SoftwareP256CustodyProvider.shared.loadedHandlePair(for: custodyMaterial)
        let signingHandle = handlePair.signing
        let keyAgreementHandle = handlePair.keyAgreement
        let label = family == .deviceBoundEcdsaNistP256EcdhNistP256 ? "v6" : "v4"
        let material = try await PGPSecureEnclaveCustodyGenerationAdapter(
            engine: engine
        ).generatePublicCertificate(
            name: "Secure Enclave Streaming File \(label)",
            email: "secure-streaming-file-\(label)@example.invalid",
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

        return StreamingSecureEnclaveRouteFixture(
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

private struct StreamingSecureEnclaveRouteFixture {
    let identity: PGPKeyIdentity
    let route: SecureEnclaveSignerRoute
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
}

private final class StaticStreamingPrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
    private let route: PrivateKeyOperationRoute
    private(set) var requests: [PrivateKeyOperationRequest] = []

    init(route: PrivateKeyOperationRoute) {
        self.route = route
    }

    func route(for request: PrivateKeyOperationRequest) async -> PrivateKeyOperationRoute {
        requests.append(request)
        return route
    }
}

private final class RecordingStreamingSoftwareSecretCertificateUnwrapper: SoftwareSecretCertificateUnwrapping {
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

private struct UnexpectedStreamingDigestSigner: SecureEnclaveCustodyDigestSigning {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        XCTFail("Digest signer should not be called")
        throw CancellationError()
    }
}

private struct ThrowingStreamingDigestSigner: SecureEnclaveCustodyDigestSigning {
    let error: Error

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw error
    }
}
