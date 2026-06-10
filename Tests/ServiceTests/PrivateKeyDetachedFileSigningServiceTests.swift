import Security
import XCTest
@testable import CypherAir

final class PrivateKeyDetachedFileSigningServiceTests: XCTestCase {
    private let engine = PgpEngine()

    func test_softwareRouteSignsDetachedFileWithUnwrappedSecretCertificate() async throws {
        var generated = try engine.generateKey(
            name: "Software Detached Signer",
            email: "software-detached@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        defer { generated.certData.resetBytes(in: 0..<generated.certData.count) }
        let identity = try identity(from: generated, isDefault: true)
        let input = try makeTemporaryFile(Data("software detached file".utf8))
        defer { try? FileManager.default.removeItem(at: input) }
        let router = StaticDetachedPrivateKeyOperationRouter(
            route: .softwareSecretCertificate(
                SoftwareSecretCertificateRoute(identity: identity, operation: .sign)
            )
        )
        let unwrapper = RecordingDetachedSoftwareSecretCertificateUnwrapper(
            secretCert: generated.certData
        )
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            messageAdapter: messageAdapter
        )

        let signature = try await service.signDetachedFile(
            inputPath: input.path,
            signerFingerprint: identity.fingerprint,
            progress: nil
        )

        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: identity.fingerprint, operation: .sign)
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [identity.fingerprint])
        let verification = try await verifyDetached(
            input,
            signature: signature,
            verificationKey: identity.publicKeyData,
            identity: identity,
            messageAdapter: messageAdapter
        )
        XCTAssertEqual(verification.summaryState, .verified)
    }

    func test_secureEnclaveRouteSignsDetachedFileWithoutUnwrappingSecretCertificate() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let input = try makeTemporaryFile(Data("secure enclave detached file".utf8))
        defer { try? FileManager.default.removeItem(at: input) }
        let router = StaticDetachedPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingDetachedSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            messageAdapter: messageAdapter,
            digestSigner: SystemSecureEnclaveCustodyDigestSigner()
        )

        let signature = try await service.signDetachedFile(
            inputPath: input.path,
            signerFingerprint: fixture.identity.fingerprint,
            progress: nil
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let verification = try await verifyDetached(
            input,
            signature: signature,
            verificationKey: fixture.identity.publicKeyData,
            identity: fixture.identity,
            messageAdapter: messageAdapter
        )
        XCTAssertEqual(verification.summaryState, .verified)
    }

    func test_secureEnclaveV6RouteSignsDetachedFileAndVerifies() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture(configurationIdentity: .modernP256V6)
        XCTAssertEqual(fixture.identity.keyVersion, 6)
        XCTAssertEqual(fixture.identity.profile, .advanced)
        XCTAssertEqual(fixture.identity.openPGPConfigurationIdentity, .modernP256V6)
        XCTAssertEqual(fixture.identity.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)
        let input = try makeTemporaryFile(Data("secure enclave v6 detached file".utf8))
        defer { try? FileManager.default.removeItem(at: input) }
        let router = StaticDetachedPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingDetachedSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            messageAdapter: messageAdapter,
            digestSigner: SystemSecureEnclaveCustodyDigestSigner()
        )

        let signature = try await service.signDetachedFile(
            inputPath: input.path,
            signerFingerprint: fixture.identity.fingerprint,
            progress: nil
        )

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        let verification = try await verifyDetached(
            input,
            signature: signature,
            verificationKey: fixture.identity.publicKeyData,
            identity: fixture.identity,
            messageAdapter: messageAdapter
        )
        XCTAssertEqual(verification.summaryState, .verified)
    }

    func test_secureEnclaveDetachedFileSigningUsesRealCatalogRouterAndSharedHandleStore() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let detachedFileSigner = TestHelpers.makeDetachedFileSigner(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
            digestSigner: SystemSecureEnclaveCustodyDigestSigner()
        )
        let (contactService, contactsDirectory) = await TestHelpers.makeContactService(engine: engine)
        defer { TestHelpers.cleanupTempDir(contactsDirectory) }
        let signingService = SigningService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            cleartextSigner: TestHelpers.makeCleartextSigner(
                engine: engine,
                keyManagement: keyManagement,
                messageAdapter: messageAdapter
            ),
            detachedFileSigner: detachedFileSigner
        )
        let input = try makeTemporaryFile(Data("secure enclave routed detached file".utf8))
        defer { try? FileManager.default.removeItem(at: input) }

        let signature = try await signingService.signDetachedStreaming(
            fileURL: input,
            signerFingerprint: fixture.identity.fingerprint,
            progress: nil
        )

        XCTAssertEqual(keyManagement.keys.map(\.fingerprint), [fixture.identity.fingerprint])
        let verification = try await verifyDetached(
            input,
            signature: signature,
            verificationKey: fixture.identity.publicKeyData,
            identity: fixture.identity,
            messageAdapter: messageAdapter
        )
        XCTAssertEqual(verification.summaryState, .verified)
    }

    func test_productionPolicyBlocksSecureEnclaveDetachedFileSigning() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        let service = TestHelpers.makeDetachedFileSigner(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: PGPMessageOperationAdapter(engine: engine),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        )
        let input = try makeTemporaryFile(Data("blocked detached file".utf8))
        defer { try? FileManager.default.removeItem(at: input) }

        do {
            _ = try await service.signDetachedFile(
                inputPath: input.path,
                signerFingerprint: fixture.identity.fingerprint,
                progress: nil
            )
            XCTFail("Expected production policy to block Secure Enclave detached signing")
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
        let service = TestHelpers.makeDetachedFileSigner(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: PGPMessageOperationAdapter(engine: engine),
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore())
        )
        let input = try makeTemporaryFile(Data("missing handle detached file".utf8))
        defer { try? FileManager.default.removeItem(at: input) }

        do {
            _ = try await service.signDetachedFile(
                inputPath: input.path,
                signerFingerprint: fixture.identity.fingerprint,
                progress: nil
            )
            XCTFail("Expected missing handle to block")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .privateHandleMissing)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }
    }

    func test_progressCancellationMapsToOperationCancelledWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let input = try makeTemporaryFile(Data(repeating: 0x42, count: 128 * 1024))
        defer { try? FileManager.default.removeItem(at: input) }
        let router = StaticDetachedPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingDetachedSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: UnexpectedDetachedDigestSigner()
        )
        let progress = FileProgressReporter()
        progress.cancel()

        do {
            _ = try await service.signDetachedFile(
                inputPath: input.path,
                signerFingerprint: fixture.identity.fingerprint,
                progress: progress
            )
            XCTFail("Expected progress cancellation to throw")
        } catch CypherAirError.operationCancelled {
            XCTAssertEqual(unwrapper.unwrapRequests, [])
        } catch {
            XCTFail("Expected operationCancelled, got \(error)")
        }
    }

    func test_secureEnclaveCancellationMapsToOperationCancelledWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let input = try makeTemporaryFile(Data("cancel detached file signing".utf8))
        defer { try? FileManager.default.removeItem(at: input) }
        let router = StaticDetachedPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
        let unwrapper = RecordingDetachedSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            digestSigner: ThrowingDetachedDigestSigner(error: CancellationError())
        )

        do {
            _ = try await service.signDetachedFile(
                inputPath: input.path,
                signerFingerprint: fixture.identity.fingerprint,
                progress: nil
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
        let cases: [(SecureEnclaveCustodyHandleError, PGPKeyOperationFailureCategory)] = [
            (.localAuthenticationCancelled(.signing), .localAuthenticationCancelled),
            (.localAuthenticationFailed(.signing), .localAuthenticationFailed),
            (.privateOperationRoleMismatch(expected: .signing, actual: .keyAgreement), .privateOperationRoleMismatch),
            (.handlePublicKeyBindingMismatch(.signing), .handlePublicKeyBindingMismatch),
        ]

        for (error, expectedCategory) in cases {
            let input = try makeTemporaryFile(Data("callback detached file failure".utf8))
            defer { try? FileManager.default.removeItem(at: input) }
            let router = StaticDetachedPrivateKeyOperationRouter(route: .secureEnclaveSigner(fixture.route))
            let unwrapper = RecordingDetachedSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
            let service = makeService(
                router: router,
                unwrapper: unwrapper,
                digestSigner: ThrowingDetachedDigestSigner(error: error)
            )

            do {
                _ = try await service.signDetachedFile(
                    inputPath: input.path,
                    signerFingerprint: fixture.identity.fingerprint,
                    progress: nil
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
        let input = try makeTemporaryFile(Data("blocked detached file".utf8))
        defer { try? FileManager.default.removeItem(at: input) }
        let router = StaticDetachedPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingDetachedSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            _ = try await service.signDetachedFile(
                inputPath: input.path,
                signerFingerprint: "blocked-fingerprint",
                progress: nil
            )
            XCTFail("Expected blocked route to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    private func makeService(
        router: StaticDetachedPrivateKeyOperationRouter,
        unwrapper: RecordingDetachedSoftwareSecretCertificateUnwrapper,
        messageAdapter: PGPMessageOperationAdapter? = nil,
        digestSigner: any SecureEnclaveCustodyDigestSigning = SystemSecureEnclaveCustodyDigestSigner()
    ) -> PrivateKeyDetachedFileSigningService {
        PrivateKeyDetachedFileSigningService(
            router: router,
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter ?? PGPMessageOperationAdapter(engine: engine),
            digestSigner: digestSigner
        )
    }

    private func verifyDetached(
        _ input: URL,
        signature: Data,
        verificationKey: Data,
        identity: PGPKeyIdentity,
        messageAdapter: PGPMessageOperationAdapter
    ) async throws -> DetailedSignatureVerification {
        try await messageAdapter.verifyDetachedFileDetailed(
            dataPath: input.path,
            signature: signature,
            verificationContext: PGPMessageVerificationContext(
                verificationKeys: [verificationKey],
                contactKeys: [],
                ownKeys: [identity],
                contactsAvailability: .availableProtectedDomain
            ),
            progress: nil
        )
    }

    private func identity(from generated: GeneratedKey, isDefault: Bool) throws -> PGPKeyIdentity {
        let keyInfo = try engine.parseKeyInfo(keyData: generated.certData)
        return PGPKeyIdentity(
            fingerprint: keyInfo.fingerprint,
            keyVersion: UInt8(keyInfo.keyVersion),
            profile: .universal,
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
            openPGPConfigurationIdentity: .compatibleSoftwareV4,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
    }

    private func makeTemporaryFile(
        _ contents: Data,
        name: String = "detached-signing-\(UUID().uuidString).bin"
    ) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try contents.write(to: url, options: .atomic)
        return url
    }

    private func makeSecureEnclaveRouteFixture(
        configurationIdentity: PGPKeyConfiguration.Identity = .compatibleP256V4
    ) async throws -> DetachedSecureEnclaveRouteFixture {
        let signingPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let keyAgreementPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let signingPublicKeyX963 = try Self.publicKeyX963(from: signingPrivateKey)
        let keyAgreementPublicKeyX963 = try Self.publicKeyX963(from: keyAgreementPrivateKey)
        let handleSetIdentifier = "detached-file-\(UUID().uuidString.lowercased())"
        let signingReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .signing
        )
        let keyAgreementReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .keyAgreement
        )
        let signingHandle = SecureEnclaveCustodyLoadedHandle(
            binding: try SecureEnclaveCustodyHandlePublicBinding(
                reference: signingReference,
                publicKeyX963: signingPublicKeyX963
            ),
            privateKey: signingPrivateKey
        )
        let keyAgreementHandle = SecureEnclaveCustodyLoadedHandle(
            binding: try SecureEnclaveCustodyHandlePublicBinding(
                reference: keyAgreementReference,
                publicKeyX963: keyAgreementPublicKeyX963
            ),
            privateKey: keyAgreementPrivateKey
        )
        let handlePair = try SecureEnclaveCustodyLoadedHandlePair(
            signing: signingHandle,
            keyAgreement: keyAgreementHandle
        )
        let label = configurationIdentity == .modernP256V6 ? "v6" : "v4"
        let material = try await PGPSecureEnclaveCustodyGenerationAdapter(
            engine: engine
        ).generatePublicCertificate(
            name: "Secure Enclave Detached \(label)",
            email: "secure-detached-\(label)@example.invalid",
            expirySeconds: 3600,
            configuration: configurationIdentity.configuration,
            handlePair: handlePair,
            digestSigner: SystemSecureEnclaveCustodyDigestSigner()
        )
        let identity = PGPKeyIdentity(
            fingerprint: material.metadata.fingerprint,
            keyVersion: material.metadata.keyVersion,
            profile: material.metadata.profile,
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

        return DetachedSecureEnclaveRouteFixture(
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

    private static func makeEphemeralP256PrivateKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw CypherAirError.keyGenerationFailed(
                reason: error.map { CFErrorCopyDescription($0.takeRetainedValue()) as String }
                    ?? "Failed to create test P-256 key."
            )
        }
        return key
    }

    private static func publicKeyX963(from privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CypherAirError.keyGenerationFailed(reason: "Missing test public key.")
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw CypherAirError.keyGenerationFailed(
                reason: error.map { CFErrorCopyDescription($0.takeRetainedValue()) as String }
                    ?? "Failed to export test P-256 public key."
            )
        }
        return data
    }
}

private struct DetachedSecureEnclaveRouteFixture {
    let identity: PGPKeyIdentity
    let route: SecureEnclaveSignerRoute
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
}

private final class StaticDetachedPrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
    private let routeResult: PrivateKeyOperationRoute
    private(set) var requests: [PrivateKeyOperationRequest] = []

    init(route: PrivateKeyOperationRoute) {
        routeResult = route
    }

    func route(for request: PrivateKeyOperationRequest) -> PrivateKeyOperationRoute {
        requests.append(request)
        return routeResult
    }
}

private final class RecordingDetachedSoftwareSecretCertificateUnwrapper: SoftwareSecretCertificateUnwrapping {
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

private struct ThrowingDetachedDigestSigner: SecureEnclaveCustodyDigestSigning {
    let error: Error

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw error
    }
}

private struct UnexpectedDetachedDigestSigner: SecureEnclaveCustodyDigestSigning {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        XCTFail("Detached progress cancellation should happen before digest signing")
        throw CancellationError()
    }
}
