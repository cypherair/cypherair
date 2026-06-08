import Security
import XCTest
@testable import CypherAir

final class PrivateKeyMessageDecryptionServiceTests: XCTestCase {
    private let engine = PgpEngine()

    // MARK: - Software custody route

    func test_softwareRouteDecryptsWithUnwrappedSecretCertificate() async throws {
        let generated = try engine.generateKey(
            name: "Software Recipient",
            email: "software-recipient@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let identity = try softwareIdentity(from: generated, profile: .universal, isDefault: true)
        let router = StaticPrivateKeyOperationRouter(
            route: .softwareSecretCertificate(
                SoftwareSecretCertificateRoute(identity: identity, operation: .decrypt)
            )
        )
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: generated.certData)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = makeService(router: router, unwrapper: unwrapper, messageAdapter: messageAdapter)

        let plaintext = "software custody decrypt 你好"
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data(plaintext.utf8),
            recipientKeys: [identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )

        let result = try await service.decryptDetailed(
            ciphertext: ciphertext,
            recipientFingerprint: identity.fingerprint,
            verificationContext: verificationContext(for: identity)
        )

        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), plaintext)
        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: identity.fingerprint, operation: .decrypt)
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [identity.fingerprint])
    }

    // MARK: - Secure Enclave key-agreement route

    func test_secureEnclaveRouteDecryptsV4MessageWithoutUnwrappingSecretCertificate() async throws {
        try await assertSecureEnclaveRouteDecrypts(
            configurationIdentity: .compatibleP256V4,
            plaintext: "secure enclave v4 decrypt 🔐"
        )
    }

    func test_secureEnclaveRouteDecryptsV6MessageWithoutUnwrappingSecretCertificate() async throws {
        try await assertSecureEnclaveRouteDecrypts(
            configurationIdentity: .modernP256V6,
            plaintext: "secure enclave v6 decrypt 🛡️"
        )
    }

    func test_secureEnclaveSignedMessageFoldsSignatureVerification() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let signer = try engine.generateKey(
            name: "Folding Signer",
            email: "folding-signer@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let signerIdentity = try softwareIdentity(from: signer, profile: .universal)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data("signed secure enclave message".utf8),
            recipientKeys: [fixture.identity.publicKeyData],
            signingKey: signer.certData,
            selfKey: nil,
            binary: true
        )
        let router = StaticPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper, messageAdapter: messageAdapter)

        let result = try await service.decryptDetailed(
            ciphertext: ciphertext,
            recipientFingerprint: fixture.identity.fingerprint,
            verificationContext: PGPMessageVerificationContext(
                verificationKeys: [signer.publicKeyData, fixture.identity.publicKeyData],
                contactKeys: [],
                ownKeys: [signerIdentity, fixture.identity],
                contactsAvailability: .availableProtectedDomain
            )
        )

        XCTAssertEqual(result.verification.summaryState, .verified)
        XCTAssertEqual(result.verification.signatures.count, 1)
        XCTAssertEqual(result.verification.signatures.first?.signerPrimaryFingerprint, signerIdentity.fingerprint)
        XCTAssertEqual(result.verification.signatures.first?.signerIdentity?.source, .ownKey)
        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveMessageDecryptUsesRealCatalogRouterAndSharedHandleStore() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let (keyManagement, _, mockKeychain, _) = TestHelpers.makeKeyManagement(engine: engine)
        try KeyMetadataStore(keychain: mockKeychain).save(fixture.identity)
        try keyManagement.loadKeys()

        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.signingHandle)
        keyStore.insert(fixture.route.keyAgreementHandle)

        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = TestHelpers.makeMessageDecryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveKeyAgreementRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        )

        let plaintext = "secure enclave routed decrypt"
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data(plaintext.utf8),
            recipientKeys: [fixture.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )

        let result = try await service.decryptDetailed(
            ciphertext: ciphertext,
            recipientFingerprint: fixture.identity.fingerprint,
            verificationContext: verificationContext(for: fixture.identity)
        )

        XCTAssertEqual(keyManagement.keys.map(\.fingerprint), [fixture.identity.fingerprint])
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), plaintext)
    }

    func test_productionPolicyBlocksSecureEnclaveDecryptWithoutUnwrap() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let (keyManagement, _, mockKeychain, _) = TestHelpers.makeKeyManagement(engine: engine)
        try KeyMetadataStore(keychain: mockKeychain).save(fixture.identity)
        try keyManagement.loadKeys()

        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.signingHandle)
        keyStore.insert(fixture.route.keyAgreementHandle)

        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = TestHelpers.makeMessageDecryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter,
            resolver: PGPKeyCapabilityResolver(),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        )

        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data("blocked by policy".utf8),
            recipientKeys: [fixture.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )

        do {
            _ = try await service.decryptDetailed(
                ciphertext: ciphertext,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity)
            )
            XCTFail("Expected production policy to block Secure Enclave decrypt")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }
    }

    // MARK: - Failure and fail-closed coverage

    func test_blockedRouteThrowsUnavailableCategoryWithoutUnwrapping() async throws {
        let router = StaticPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            _ = try await service.decryptDetailed(
                ciphertext: Data([0x01, 0x02]),
                recipientFingerprint: "blocked-fingerprint",
                verificationContext: emptyVerificationContext()
            )
            XCTFail("Expected blocked route to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_signerRouteThrowsRoleMismatchWithoutUnwrapping() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let router = StaticPrivateKeyOperationRouter(
            route: .secureEnclaveSigner(
                SecureEnclaveSignerRoute(
                    identity: fixture.identity,
                    operation: .decrypt,
                    publicBindingInspection: fixture.route.publicBindingInspection,
                    signingHandle: fixture.signingHandle
                )
            )
        )
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            _ = try await service.decryptDetailed(
                ciphertext: Data([0x01]),
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity)
            )
            XCTFail("Expected signer route to be rejected for decrypt")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .privateOperationRoleMismatch)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveCallbackFailureMapsToUnavailableCategoryWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data("callback failure".utf8),
            recipientKeys: [fixture.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )
        let router = StaticPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            messageAdapter: messageAdapter,
            keyAgreement: ThrowingKeyAgreement(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.keyAgreement)
            )
        )

        do {
            _ = try await service.decryptDetailed(
                ciphertext: ciphertext,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity)
            )
            XCTFail("Expected callback failure to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .localAuthenticationFailed)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveRecipientMismatchFailsClosedWithoutUnwrapping() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let otherFixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        // Encrypt to a DIFFERENT Secure Enclave-shaped recipient than the route binds.
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data("recipient mismatch".utf8),
            recipientKeys: [otherFixture.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )
        let router = StaticPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper, messageAdapter: messageAdapter)

        do {
            _ = try await service.decryptDetailed(
                ciphertext: ciphertext,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity)
            )
            XCTFail("Expected recipient mismatch to fail closed")
        } catch let error as CypherAirError {
            switch error {
            case .noMatchingKey, .keyOperationUnavailable:
                break
            default:
                XCTFail("Expected fail-closed recipient mismatch, got \(error)")
            }
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveTamperedV4CiphertextHardFailsWithoutPlaintext() async throws {
        try await assertSecureEnclaveTamperHardFails(configurationIdentity: .compatibleP256V4)
    }

    func test_secureEnclaveTamperedV6CiphertextHardFailsWithoutPlaintext() async throws {
        try await assertSecureEnclaveTamperHardFails(configurationIdentity: .modernP256V6)
    }

    // MARK: - Phase 6D closure (mixed recipients, repeated operations)

    func test_secureEnclaveRouteDecryptsMixedRecipientMessageWithoutUnwrap() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let otherRecipient = try engine.generateKey(
            name: "Other Recipient",
            email: "other-recipient@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let plaintext = "secure enclave mixed-recipient decrypt 🔐"
        // Two named recipients; the Secure Enclave key-agreement recipient is second so
        // the matching PKESK is selected past a non-matching recipient's packet.
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data(plaintext.utf8),
            recipientKeys: [otherRecipient.publicKeyData, fixture.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )
        let router = StaticPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper, messageAdapter: messageAdapter)

        let result = try await service.decryptDetailed(
            ciphertext: ciphertext,
            recipientFingerprint: fixture.identity.fingerprint,
            verificationContext: verificationContext(for: fixture.identity)
        )

        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), plaintext)
        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: fixture.identity.fingerprint, operation: .decrypt)
        ])
        XCTAssertEqual(
            unwrapper.unwrapRequests, [],
            "Mixed-recipient Secure Enclave decrypt must not unwrap a secret certificate"
        )
    }

    func test_secureEnclaveRepeatedMessageDecryptsStayConsistentWithoutUnwrap() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let plaintext = "secure enclave repeated decrypt"
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data(plaintext.utf8),
            recipientKeys: [fixture.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )
        let router = StaticPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper, messageAdapter: messageAdapter)

        for iteration in 0..<3 {
            let result = try await service.decryptDetailed(
                ciphertext: ciphertext,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity)
            )
            XCTAssertEqual(
                String(data: result.plaintext, encoding: .utf8), plaintext,
                "Repeated Secure Enclave decrypt \(iteration) must return identical plaintext"
            )
        }

        XCTAssertEqual(
            unwrapper.unwrapRequests, [],
            "Repeated Secure Enclave decrypt must not unwrap a secret certificate"
        )
    }

    // MARK: - Shared assertions

    private func assertSecureEnclaveRouteDecrypts(
        configurationIdentity: PGPKeyConfiguration.Identity,
        plaintext: String
    ) async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: configurationIdentity)
        let router = StaticPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = makeService(router: router, unwrapper: unwrapper, messageAdapter: messageAdapter)

        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data(plaintext.utf8),
            recipientKeys: [fixture.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )

        let result = try await service.decryptDetailed(
            ciphertext: ciphertext,
            recipientFingerprint: fixture.identity.fingerprint,
            verificationContext: verificationContext(for: fixture.identity)
        )

        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), plaintext)
        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: fixture.identity.fingerprint, operation: .decrypt)
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [], "Secure Enclave decrypt must not unwrap a secret certificate")
    }

    private func assertSecureEnclaveTamperHardFails(
        configurationIdentity: PGPKeyConfiguration.Identity
    ) async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: configurationIdentity)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data("tamper target plaintext".utf8),
            recipientKeys: [fixture.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )
        var tampered = ciphertext
        tampered[tampered.count / 2] ^= 0x01

        let router = StaticPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper, messageAdapter: messageAdapter)

        do {
            _ = try await service.decryptDetailed(
                ciphertext: tampered,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity)
            )
            XCTFail("Expected tampered ciphertext to hard-fail without releasing plaintext")
        } catch let error as CypherAirError {
            switch error {
            case .aeadAuthenticationFailed,
                 .integrityCheckFailed,
                 .corruptData,
                 .noMatchingKey,
                 .keyOperationUnavailable:
                break
            default:
                XCTFail("Expected payload/session hard-fail, got \(error)")
            }
        } catch let error as PgpError {
            switch error {
            case .AeadAuthenticationFailed, .IntegrityCheckFailed, .CorruptData, .NoMatchingKey:
                break
            default:
                XCTFail("Expected payload/session hard-fail, got \(error)")
            }
        }
    }

    // MARK: - Helpers

    private func makeService(
        router: StaticPrivateKeyOperationRouter,
        unwrapper: RecordingSoftwareSecretCertificateUnwrapper,
        messageAdapter: PGPMessageOperationAdapter? = nil,
        keyAgreement: any SecureEnclaveCustodyKeyAgreement = SystemSecureEnclaveCustodyKeyAgreement()
    ) -> PrivateKeyMessageDecryptionService {
        PrivateKeyMessageDecryptionService(
            router: router,
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter ?? PGPMessageOperationAdapter(engine: engine),
            keyAgreement: keyAgreement
        )
    }

    private func verificationContext(for identity: PGPKeyIdentity) -> PGPMessageVerificationContext {
        PGPMessageVerificationContext(
            verificationKeys: [identity.publicKeyData],
            contactKeys: [],
            ownKeys: [identity],
            contactsAvailability: .availableProtectedDomain
        )
    }

    private func emptyVerificationContext() -> PGPMessageVerificationContext {
        PGPMessageVerificationContext(
            verificationKeys: [],
            contactKeys: [],
            ownKeys: [],
            contactsAvailability: .availableProtectedDomain
        )
    }

    private func softwareIdentity(
        from generated: GeneratedKey,
        profile: PGPKeyProfile,
        isDefault: Bool = false
    ) throws -> PGPKeyIdentity {
        let keyInfo = try engine.parseKeyInfo(keyData: generated.certData)
        return PGPKeyIdentity(
            fingerprint: keyInfo.fingerprint,
            keyVersion: UInt8(keyInfo.keyVersion),
            profile: profile,
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
            expiryDate: keyInfo.expiryTimestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        )
    }

    private func makeSecureEnclaveDecryptFixture(
        configurationIdentity: PGPKeyConfiguration.Identity
    ) async throws -> SecureEnclaveDecryptFixture {
        let signingPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let keyAgreementPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let signingPublicKeyX963 = try Self.publicKeyX963(from: signingPrivateKey)
        let keyAgreementPublicKeyX963 = try Self.publicKeyX963(from: keyAgreementPrivateKey)
        let handleSetIdentifier = "decrypt-\(UUID().uuidString.lowercased())"
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
        let material = try await PGPSecureEnclaveCustodyGenerationAdapter(
            engine: engine
        ).generatePublicCertificate(
            name: "Secure Enclave Decrypt",
            email: "secure-decrypt@example.invalid",
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

        return SecureEnclaveDecryptFixture(
            identity: identity,
            signingHandle: signingHandle,
            route: SecureEnclaveKeyAgreementRoute(
                identity: identity,
                operation: .decrypt,
                publicBindingInspection: inspection,
                keyAgreementHandle: keyAgreementHandle
            )
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

private struct SecureEnclaveDecryptFixture {
    let identity: PGPKeyIdentity
    let signingHandle: SecureEnclaveCustodyLoadedHandle
    let route: SecureEnclaveKeyAgreementRoute
}

private final class StaticPrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
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

private struct ThrowingKeyAgreement: SecureEnclaveCustodyKeyAgreement {
    let error: Error

    func deriveSharedSecret(
        request: ExternalP256KeyAgreementRequest,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSharedSecret {
        throw error
    }
}
