import Security
import XCTest
@testable import CypherAir

final class PrivateKeyStreamingFileDecryptionServiceTests: XCTestCase {
    private let engine = PgpEngine()

    // MARK: - Software custody route

    func test_softwareRouteDecryptsFileWithUnwrappedSecretCertificate() async throws {
        let generated = try engine.generateKey(
            name: "Software File Recipient",
            email: "software-file-recipient@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let identity = try softwareIdentity(from: generated, profile: .universal, isDefault: true)
        let router = StaticStreamingPrivateKeyOperationRouter(
            route: .softwareSecretCertificate(
                SoftwareSecretCertificateRoute(identity: identity, operation: .decrypt)
            )
        )
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: generated.certData)
        let service = makeService(router: router, unwrapper: unwrapper)

        let plaintext = "software custody file decrypt 你好"
        let input = try await writeEncryptedInputFile(
            plaintext: plaintext,
            recipientPublicKey: identity.publicKeyData
        )
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }

        let verification = try await service.decryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientFingerprint: identity.fingerprint,
            verificationContext: verificationContext(for: identity),
            progress: nil
        )

        XCTAssertEqual(try readOutput(output), plaintext)
        XCTAssertEqual(verification.legacyStatus, .notSigned)
        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: identity.fingerprint, operation: .decrypt)
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [identity.fingerprint])
    }

    // MARK: - Secure Enclave key-agreement route

    func test_secureEnclaveRouteDecryptsV4FileWithoutUnwrappingSecretCertificate() async throws {
        try await assertSecureEnclaveRouteDecryptsFile(
            configurationIdentity: .compatibleP256V4,
            plaintext: "secure enclave v4 file decrypt 🔐"
        )
    }

    func test_secureEnclaveRouteDecryptsV6FileWithoutUnwrappingSecretCertificate() async throws {
        try await assertSecureEnclaveRouteDecryptsFile(
            configurationIdentity: .modernP256V6,
            plaintext: "secure enclave v6 file decrypt 🛡️"
        )
    }

    func test_secureEnclaveSignedFileFoldsSignatureVerification() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let signer = try engine.generateKey(
            name: "Folding File Signer",
            email: "folding-file-signer@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let signerIdentity = try softwareIdentity(from: signer, profile: .universal)
        let input = try await writeEncryptedInputFile(
            plaintext: "signed secure enclave file",
            recipientPublicKey: fixture.identity.publicKeyData,
            signingKey: signer.certData
        )
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        let verification = try await service.decryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientFingerprint: fixture.identity.fingerprint,
            verificationContext: PGPMessageVerificationContext(
                verificationKeys: [signer.publicKeyData, fixture.identity.publicKeyData],
                contactKeys: [],
                ownKeys: [signerIdentity, fixture.identity],
                contactsAvailability: .availableProtectedDomain
            ),
            progress: nil
        )

        XCTAssertEqual(verification.legacyStatus, .valid)
        XCTAssertEqual(verification.signatures.count, 1)
        XCTAssertEqual(verification.signatures.first?.signerPrimaryFingerprint, signerIdentity.fingerprint)
        XCTAssertEqual(verification.signatures.first?.signerIdentity?.source, .ownKey)
        XCTAssertEqual(unwrapper.unwrapRequests, [])
    }

    func test_secureEnclaveFileDecryptUsesRealCatalogRouterAndSharedHandleStore() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let (keyManagement, _, mockKeychain, _) = TestHelpers.makeKeyManagement(engine: engine)
        try KeyMetadataStore(keychain: mockKeychain).save(fixture.identity)
        try keyManagement.loadKeys()

        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.signingHandle)
        keyStore.insert(fixture.route.keyAgreementHandle)

        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = TestHelpers.makeFileDecryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveKeyAgreementRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        )

        let plaintext = "secure enclave routed file decrypt"
        let input = try await writeEncryptedInputFile(
            plaintext: plaintext,
            recipientPublicKey: fixture.identity.publicKeyData
        )
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }

        let verification = try await service.decryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientFingerprint: fixture.identity.fingerprint,
            verificationContext: verificationContext(for: fixture.identity),
            progress: nil
        )

        XCTAssertEqual(keyManagement.keys.map(\.fingerprint), [fixture.identity.fingerprint])
        XCTAssertEqual(try readOutput(output), plaintext)
        XCTAssertEqual(verification.legacyStatus, .notSigned)
    }

    func test_productionPolicyBlocksSecureEnclaveFileDecryptWithoutUnwrap() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let (keyManagement, _, mockKeychain, _) = TestHelpers.makeKeyManagement(engine: engine)
        try KeyMetadataStore(keychain: mockKeychain).save(fixture.identity)
        try keyManagement.loadKeys()

        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.signingHandle)
        keyStore.insert(fixture.route.keyAgreementHandle)

        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let service = TestHelpers.makeFileDecryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter,
            resolver: PGPKeyCapabilityResolver(),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        )

        let input = try await writeEncryptedInputFile(
            plaintext: "blocked by policy",
            recipientPublicKey: fixture.identity.publicKeyData
        )
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }

        do {
            _ = try await service.decryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity),
                progress: nil
            )
            XCTFail("Expected production policy to block Secure Enclave file decrypt")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    // MARK: - Failure and fail-closed coverage

    func test_blockedRouteThrowsUnavailableCategoryWithoutUnwrappingOrOutput() async throws {
        let input = try makeTemporaryFile(Data([0x01, 0x02]))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(
            route: .blocked(.unavailable(.operationUnavailableByPolicy))
        )
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            _ = try await service.decryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientFingerprint: "blocked-fingerprint",
                verificationContext: emptyVerificationContext(),
                progress: nil
            )
            XCTFail("Expected blocked route to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func test_signerRouteThrowsRoleMismatchWithoutUnwrappingOrOutput() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let input = try makeTemporaryFile(Data([0x01]))
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(
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
            _ = try await service.decryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity),
                progress: nil
            )
            XCTFail("Expected signer route to be rejected for decrypt")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .privateOperationRoleMismatch)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func test_secureEnclaveCallbackFailureMapsToUnavailableCategoryWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let input = try await writeEncryptedInputFile(
            plaintext: "callback failure file",
            recipientPublicKey: fixture.identity.publicKeyData
        )
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(
            router: router,
            unwrapper: unwrapper,
            keyAgreement: ThrowingKeyAgreement(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.keyAgreement)
            )
        )

        do {
            _ = try await service.decryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity),
                progress: nil
            )
            XCTFail("Expected callback failure to throw")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .localAuthenticationFailed)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func test_secureEnclaveRecipientMismatchFailsClosedWithoutUnwrappingOrOutput() async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        let otherFixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: .compatibleP256V4)
        // Encrypt to a DIFFERENT Secure Enclave-shaped recipient than the route binds.
        let input = try await writeEncryptedInputFile(
            plaintext: "recipient mismatch file",
            recipientPublicKey: otherFixture.identity.publicKeyData
        )
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            _ = try await service.decryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity),
                progress: nil
            )
            XCTFail("Expected recipient mismatch to fail closed")
        } catch let error as CypherAirError {
            switch error {
            case .noMatchingKey, .keyOperationUnavailable, .corruptData:
                break
            default:
                XCTFail("Expected fail-closed recipient mismatch, got \(error)")
            }
        }

        XCTAssertEqual(unwrapper.unwrapRequests, [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func test_secureEnclaveTamperedV4FileHardFailsWithoutPlaintext() async throws {
        try await assertSecureEnclaveTamperHardFails(configurationIdentity: .compatibleP256V4)
    }

    func test_secureEnclaveTamperedV6FileHardFailsWithoutPlaintext() async throws {
        try await assertSecureEnclaveTamperHardFails(configurationIdentity: .modernP256V6)
    }

    // MARK: - Shared assertions

    private func assertSecureEnclaveRouteDecryptsFile(
        configurationIdentity: PGPKeyConfiguration.Identity,
        plaintext: String
    ) async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: configurationIdentity)
        let input = try await writeEncryptedInputFile(
            plaintext: plaintext,
            recipientPublicKey: fixture.identity.publicKeyData
        )
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }
        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        let verification = try await service.decryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientFingerprint: fixture.identity.fingerprint,
            verificationContext: verificationContext(for: fixture.identity),
            progress: nil
        )

        XCTAssertEqual(try readOutput(output), plaintext)
        XCTAssertEqual(verification.legacyStatus, .notSigned)
        XCTAssertEqual(router.requests, [
            PrivateKeyOperationRequest(fingerprint: fixture.identity.fingerprint, operation: .decrypt)
        ])
        XCTAssertEqual(unwrapper.unwrapRequests, [], "Secure Enclave decrypt must not unwrap a secret certificate")
    }

    private func assertSecureEnclaveTamperHardFails(
        configurationIdentity: PGPKeyConfiguration.Identity
    ) async throws {
        let fixture = try await makeSecureEnclaveDecryptFixture(configurationIdentity: configurationIdentity)
        let adapter = PGPMessageOperationAdapter(engine: engine)
        let ciphertext = try await adapter.encrypt(
            plaintext: Data("tamper target file plaintext".utf8),
            recipientKeys: [fixture.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )
        var tampered = ciphertext
        tampered[tampered.count / 2] ^= 0x01
        let input = try makeTemporaryFile(tampered)
        let output = makeTemporaryOutputURL()
        defer { cleanup(input, output) }

        let router = StaticStreamingPrivateKeyOperationRouter(route: .secureEnclaveKeyAgreement(fixture.route))
        let unwrapper = RecordingSoftwareSecretCertificateUnwrapper(secretCert: Data([0x00]))
        let service = makeService(router: router, unwrapper: unwrapper)

        do {
            _ = try await service.decryptFile(
                inputPath: input.path,
                outputPath: output.path,
                recipientFingerprint: fixture.identity.fingerprint,
                verificationContext: verificationContext(for: fixture.identity),
                progress: nil
            )
            XCTFail("Expected tampered file to hard-fail without releasing plaintext")
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
        }

        XCTAssertFalse(
            FileManager.default.fileExists(atPath: output.path),
            "No plaintext output file may exist after a payload hard-fail"
        )
    }

    // MARK: - Helpers

    private func makeService(
        router: StaticStreamingPrivateKeyOperationRouter,
        unwrapper: RecordingSoftwareSecretCertificateUnwrapper,
        messageAdapter: PGPMessageOperationAdapter? = nil,
        keyAgreement: any SecureEnclaveCustodyKeyAgreement = SystemSecureEnclaveCustodyKeyAgreement()
    ) -> PrivateKeyStreamingFileDecryptionService {
        PrivateKeyStreamingFileDecryptionService(
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

    private func writeEncryptedInputFile(
        plaintext: String,
        recipientPublicKey: Data,
        signingKey: Data? = nil
    ) async throws -> URL {
        let adapter = PGPMessageOperationAdapter(engine: engine)
        let ciphertext = try await adapter.encrypt(
            plaintext: Data(plaintext.utf8),
            recipientKeys: [recipientPublicKey],
            signingKey: signingKey,
            selfKey: nil,
            binary: true
        )
        return try makeTemporaryFile(ciphertext)
    }

    private func readOutput(_ url: URL) throws -> String? {
        String(data: try Data(contentsOf: url), encoding: .utf8)
    }

    private func makeTemporaryFile(
        _ contents: Data,
        name: String = "streaming-file-decrypt-input-\(UUID().uuidString).gpg"
    ) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try contents.write(to: url, options: .atomic)
        return url
    }

    private func makeTemporaryOutputURL(
        name: String = "streaming-file-decrypt-output-\(UUID().uuidString).bin"
    ) -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(name)
    }

    private func cleanup(_ urls: URL...) {
        for url in urls {
            try? FileManager.default.removeItem(at: url)
        }
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
    ) async throws -> SecureEnclaveFileDecryptFixture {
        let signingPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let keyAgreementPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let signingPublicKeyX963 = try Self.publicKeyX963(from: signingPrivateKey)
        let keyAgreementPublicKeyX963 = try Self.publicKeyX963(from: keyAgreementPrivateKey)
        let handleSetIdentifier = "file-decrypt-\(UUID().uuidString.lowercased())"
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
            name: "Secure Enclave File Decrypt",
            email: "secure-file-decrypt@example.invalid",
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

        return SecureEnclaveFileDecryptFixture(
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

private struct SecureEnclaveFileDecryptFixture {
    let identity: PGPKeyIdentity
    let signingHandle: SecureEnclaveCustodyLoadedHandle
    let route: SecureEnclaveKeyAgreementRoute
}

private final class StaticStreamingPrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
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
