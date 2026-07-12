import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

final class PrivateKeySelectiveRevocationServiceTests: XCTestCase {
    private let engine = PgpEngine()

    func test_blockingPolicyBlocksSecureEnclaveSelectiveRevocationBeforeHandleLookup() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        keyManagement.configurePrivateKeySelectiveRevocationService(
            TestHelpers.makeSelectiveRevocationService(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveOperationsBlocked),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: UnexpectedSelectiveRevocationDigestSigner()
            )
        )
        let catalog = try keyManagement.selectionCatalog(fingerprint: fixture.identity.fingerprint)
        let subkey = try XCTUnwrap(catalog.subkeys.first)

        do {
            _ = try await keyManagement.exportSubkeyRevocationCertificate(
                fingerprint: fixture.identity.fingerprint,
                subkeySelection: subkey
            )
            XCTFail("Expected blocking policy to stop Secure Enclave selective revocation")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, 0)
    }

    func test_secureEnclaveSelectiveRevocationUsesRealCatalogRouterAndSharedHandleStoreForV4AndV6() async throws {
        for configurationIdentity in [
            PGPKeyConfiguration.Identity.compatibleP256V4,
            .modernP256V6,
        ] {
            let fixture = try await makeSecureEnclaveRouteFixture(
                configurationIdentity: configurationIdentity
            )
            let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
            try metadataPersistence.save(fixture.identity)
            try keyManagement.loadKeys()
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            keyStore.insert(fixture.route.signingHandle)
            keyStore.insert(fixture.keyAgreementHandle)
            keyManagement.configurePrivateKeySelectiveRevocationService(
                TestHelpers.makeSelectiveRevocationService(
                    engine: engine,
                    keyManagement: keyManagement,
                    resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                    handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                    digestSigner: SystemSecureEnclaveCustodyDigestSigner()
                )
            )
            let catalog = try keyManagement.selectionCatalog(fingerprint: fixture.identity.fingerprint)
            let subkey = try XCTUnwrap(catalog.subkeys.first)
            let userId = try XCTUnwrap(catalog.userIds.first)
            let snapshot = catalogSnapshot(
                keyManagement: keyManagement,
                keychain: mockKeychain
            )

            let subkeyRevocation = try await keyManagement.exportSubkeyRevocationCertificate(
                fingerprint: fixture.identity.fingerprint,
                subkeySelection: subkey
            )
            let userIdRevocation = try await keyManagement.exportUserIdRevocationCertificate(
                fingerprint: fixture.identity.fingerprint,
                userIdSelection: userId
            )

            try assertArmoredSignature(subkeyRevocation)
            try assertArmoredSignature(userIdRevocation)
            XCTAssertEqual(fixture.identity.keyVersion, configurationIdentity.configuration.keyVersion)
            XCTAssertEqual(fixture.identity.openPGPConfigurationIdentity, configurationIdentity)
            XCTAssertEqual(fixture.identity.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)
            XCTAssertEqual(keyManagement.keys.map(\.fingerprint), [fixture.identity.fingerprint])
            XCTAssertEqual(mockSE.unwrapCallCount, 0)
            assertNoCatalogOrKeychainMutation(
                keyManagement: keyManagement,
                keychain: mockKeychain,
                before: snapshot
            )
        }
    }

    func test_secureEnclaveSelectorMismatchFailsBeforeHandleLookupOrUnwrap() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        keyManagement.configurePrivateKeySelectiveRevocationService(
            TestHelpers.makeSelectiveRevocationService(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: UnexpectedSelectiveRevocationDigestSigner()
            )
        )
        let bogusSelection = SubkeySelectionOption(
            fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            algorithmDisplay: "ECDH P-256",
            isCurrentlyTransportEncryptionCapable: true,
            isCurrentlyRevoked: false,
            isCurrentlyExpired: false
        )

        do {
            _ = try await keyManagement.exportSubkeyRevocationCertificate(
                fingerprint: fixture.identity.fingerprint,
                subkeySelection: bogusSelection
            )
            XCTFail("Expected selector mismatch to fail before routing")
        } catch CypherAirError.invalidKeyData {
            // Expected.
        } catch {
            XCTFail("Expected invalidKeyData, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, 0)
    }

    func test_secureEnclaveSelectiveRevocationHandleFailuresDoNotFallback() async throws {
        let cases: [(SecureEnclaveCustodyHandleError?, PGPKeyOperationFailureCategory)] = [
            (nil, .privateHandleMissing),
            (
                .privateOperationRoleMismatch(expected: .signing, actual: .keyAgreement),
                .privateOperationRoleMismatch
            ),
            (
                .handlePublicKeyBindingMismatch(.signing),
                .handlePublicKeyBindingMismatch
            ),
        ]

        for (loadError, expectedCategory) in cases {
            let fixture = try await makeSecureEnclaveRouteFixture()
            let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
            try metadataPersistence.save(fixture.identity)
            try keyManagement.loadKeys()
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            if let loadError {
                keyStore.insert(fixture.route.signingHandle)
                keyStore.insert(fixture.keyAgreementHandle)
                keyStore.failLoadError = loadError
            }
            keyManagement.configurePrivateKeySelectiveRevocationService(
                TestHelpers.makeSelectiveRevocationService(
                    engine: engine,
                    keyManagement: keyManagement,
                    resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                    handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                    digestSigner: UnexpectedSelectiveRevocationDigestSigner()
                )
            )
            let catalog = try keyManagement.selectionCatalog(fingerprint: fixture.identity.fingerprint)
            let subkey = try XCTUnwrap(catalog.subkeys.first)

            do {
                _ = try await keyManagement.exportSubkeyRevocationCertificate(
                    fingerprint: fixture.identity.fingerprint,
                    subkeySelection: subkey
                )
                XCTFail("Expected Secure Enclave handle failure")
            } catch CypherAirError.keyOperationUnavailable(let category) {
                XCTAssertEqual(category, expectedCategory)
            } catch {
                XCTFail("Expected keyOperationUnavailable, got \(error)")
            }

            XCTAssertEqual(mockSE.unwrapCallCount, 0)
        }
    }

    func test_secureEnclaveSelectiveRevocationCancellationAndCallbackFailuresDoNotFallback() async throws {
        let cases: [(Error, ExpectedSelectiveRevocationError)] = [
            (CancellationError(), .operationCancelled),
            (
                SecureEnclaveCustodyHandleError.localAuthenticationCancelled(.signing),
                .keyOperationUnavailable(.localAuthenticationCancelled)
            ),
            (
                SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing),
                .keyOperationUnavailable(.localAuthenticationFailed)
            ),
        ]

        for (signingError, expectedError) in cases {
            let fixture = try await makeSecureEnclaveRouteFixture()
            let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(engine: engine)
            try metadataPersistence.save(fixture.identity)
            try keyManagement.loadKeys()
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            keyStore.insert(fixture.route.signingHandle)
            keyStore.insert(fixture.keyAgreementHandle)
            keyManagement.configurePrivateKeySelectiveRevocationService(
                TestHelpers.makeSelectiveRevocationService(
                    engine: engine,
                    keyManagement: keyManagement,
                    resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                    handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                    digestSigner: ThrowingSelectiveRevocationDigestSigner(error: signingError)
                )
            )
            let catalog = try keyManagement.selectionCatalog(fingerprint: fixture.identity.fingerprint)
            let userId = try XCTUnwrap(catalog.userIds.first)

            do {
                _ = try await keyManagement.exportUserIdRevocationCertificate(
                    fingerprint: fixture.identity.fingerprint,
                    userIdSelection: userId
                )
                XCTFail("Expected Secure Enclave signing failure")
            } catch let error as CypherAirError {
                assert(error, matches: expectedError)
            } catch {
                XCTFail("Expected CypherAirError, got \(error)")
            }

            XCTAssertEqual(mockSE.unwrapCallCount, 0)
        }
    }

    func test_secureEnclaveSelectiveRevocationAuthenticatesOncePerExportAndEndsAuthorization() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let stub = StubSelectiveRevocationCustodyOperationAuthenticator()
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            secureEnclaveCustodyOperationAuthenticator: stub.authenticate
        )
        _ = mockKeychain
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        keyManagement.configurePrivateKeySelectiveRevocationService(
            TestHelpers.makeSelectiveRevocationService(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: SystemSecureEnclaveCustodyDigestSigner()
            )
        )
        let catalog = try keyManagement.selectionCatalog(fingerprint: fixture.identity.fingerprint)
        let subkey = try XCTUnwrap(catalog.subkeys.first)
        let userId = try XCTUnwrap(catalog.userIds.first)

        _ = try await keyManagement.exportSubkeyRevocationCertificate(
            fingerprint: fixture.identity.fingerprint,
            subkeySelection: subkey
        )
        XCTAssertEqual(stub.calls, 1, "Exactly one custody authentication per export.")
        XCTAssertEqual(stub.context.invalidateCount, 1)

        _ = try await keyManagement.exportUserIdRevocationCertificate(
            fingerprint: fixture.identity.fingerprint,
            userIdSelection: userId
        )
        XCTAssertEqual(stub.calls, 2)
        XCTAssertEqual(stub.context.invalidateCount, 2)
        XCTAssertEqual(mockSE.unwrapCallCount, 0)
    }

    func test_secureEnclaveSelectiveRevocationCancelledAuthenticationBlocksBothExportsWithoutSigning() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let stub = StubSelectiveRevocationCustodyOperationAuthenticator()
        stub.errorToThrow = CypherAirError.operationCancelled
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            secureEnclaveCustodyOperationAuthenticator: stub.authenticate
        )
        _ = mockKeychain
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        keyManagement.configurePrivateKeySelectiveRevocationService(
            TestHelpers.makeSelectiveRevocationService(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: UnexpectedSelectiveRevocationDigestSigner()
            )
        )
        let catalog = try keyManagement.selectionCatalog(fingerprint: fixture.identity.fingerprint)
        let subkey = try XCTUnwrap(catalog.subkeys.first)
        let userId = try XCTUnwrap(catalog.userIds.first)

        do {
            _ = try await keyManagement.exportSubkeyRevocationCertificate(
                fingerprint: fixture.identity.fingerprint,
                subkeySelection: subkey
            )
            XCTFail("Expected cancelled custody authentication to block subkey export")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .localAuthenticationCancelled)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        do {
            _ = try await keyManagement.exportUserIdRevocationCertificate(
                fingerprint: fixture.identity.fingerprint,
                userIdSelection: userId
            )
            XCTFail("Expected cancelled custody authentication to block User ID export")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .localAuthenticationCancelled)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(stub.calls, 2)
        XCTAssertTrue(keyStore.loadRequests.allSatisfy { $0.authenticationContext == nil })
        XCTAssertEqual(mockSE.unwrapCallCount, 0)
    }

    func test_secureEnclaveSelectiveRevocationEndsAuthorizationAfterSigningFailureInBothExports() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let stub = StubSelectiveRevocationCustodyOperationAuthenticator()
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            secureEnclaveCustodyOperationAuthenticator: stub.authenticate
        )
        _ = mockKeychain
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        keyManagement.configurePrivateKeySelectiveRevocationService(
            TestHelpers.makeSelectiveRevocationService(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: ThrowingSelectiveRevocationDigestSigner(
                    error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing)
                )
            )
        )
        let catalog = try keyManagement.selectionCatalog(fingerprint: fixture.identity.fingerprint)
        let subkey = try XCTUnwrap(catalog.subkeys.first)
        let userId = try XCTUnwrap(catalog.userIds.first)

        do {
            _ = try await keyManagement.exportSubkeyRevocationCertificate(
                fingerprint: fixture.identity.fingerprint,
                subkeySelection: subkey
            )
            XCTFail("Expected signing failure to throw")
        } catch {
        }
        XCTAssertEqual(stub.context.invalidateCount, 1)

        do {
            _ = try await keyManagement.exportUserIdRevocationCertificate(
                fingerprint: fixture.identity.fingerprint,
                userIdSelection: userId
            )
            XCTFail("Expected signing failure to throw")
        } catch {
        }
        XCTAssertEqual(stub.context.invalidateCount, 2)
    }

    private func assertArmoredSignature(
        _ armored: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let header = "-----BEGIN PGP SIGNATURE-----"
        let prefix = String(data: armored.prefix(header.utf8.count), encoding: .utf8)
        XCTAssertEqual(prefix, header, file: file, line: line)
        XCTAssertFalse(try engine.dearmor(armored: armored).isEmpty, file: file, line: line)
    }

    private func assert(
        _ error: CypherAirError,
        matches expected: ExpectedSelectiveRevocationError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        switch (error, expected) {
        case (.operationCancelled, .operationCancelled):
            break
        case (.keyOperationUnavailable(let actualCategory), .keyOperationUnavailable(let expectedCategory)):
            XCTAssertEqual(actualCategory, expectedCategory, file: file, line: line)
        default:
            XCTFail("Expected \(expected), got \(error)", file: file, line: line)
        }
    }

    private func catalogSnapshot(
        keyManagement: KeyManagementService,
        keychain: MockKeychain
    ) -> (keys: [PGPKeyIdentity], saveCount: Int, deleteCount: Int) {
        (keyManagement.keys, keychain.saveCallCount, keychain.deleteCallCount)
    }

    private func assertNoCatalogOrKeychainMutation(
        keyManagement: KeyManagementService,
        keychain: MockKeychain,
        before: (keys: [PGPKeyIdentity], saveCount: Int, deleteCount: Int),
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(keyManagement.keys, before.keys, file: file, line: line)
        XCTAssertEqual(keychain.saveCallCount, before.saveCount, file: file, line: line)
        XCTAssertEqual(keychain.deleteCallCount, before.deleteCount, file: file, line: line)
    }

    private func makeSecureEnclaveRouteFixture(
        configurationIdentity: PGPKeyConfiguration.Identity = .compatibleP256V4
    ) async throws -> SelectiveRevocationSecureEnclaveRouteFixture {
        let signingPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let keyAgreementPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let signingPublicKeyX963 = try Self.publicKeyX963(from: signingPrivateKey)
        let keyAgreementPublicKeyX963 = try Self.publicKeyX963(from: keyAgreementPrivateKey)
        let handleSetIdentifier = "selective-revocation-\(UUID().uuidString.lowercased())"
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
            name: "Secure Enclave Selective Revocation",
            email: "secure-selective-revocation@example.invalid",
            expirySeconds: 3600,
            configuration: configurationIdentity.configuration,
            handlePair: handlePair,
            digestSigner: SystemSecureEnclaveCustodyDigestSigner()
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

        return SelectiveRevocationSecureEnclaveRouteFixture(
            identity: identity,
            route: SecureEnclaveSignerRoute(
                identity: identity,
                operation: .revoke,
                publicBindingInspection: inspection,
                signingHandle: signingHandle
            ),
            keyAgreementHandle: keyAgreementHandle
        )
    }

    private static func makeEphemeralP256PrivateKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
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

private struct SelectiveRevocationSecureEnclaveRouteFixture {
    let identity: PGPKeyIdentity
    let route: SecureEnclaveSignerRoute
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
}

private enum ExpectedSelectiveRevocationError {
    case operationCancelled
    case keyOperationUnavailable(PGPKeyOperationFailureCategory)
}

private final class StubSelectiveRevocationCustodyOperationAuthenticator: @unchecked Sendable {
    private(set) var calls = 0
    var errorToThrow: Error?
    let context = RecordingLAContext()

    func authenticate(_ reason: String) async throws -> LAContext {
        calls += 1
        if let errorToThrow {
            throw errorToThrow
        }
        return context
    }
}

private struct UnexpectedSelectiveRevocationDigestSigner: SecureEnclaveCustodyDigestSigning {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        XCTFail("Digest signer should not be called")
        throw CancellationError()
    }
}

private struct ThrowingSelectiveRevocationDigestSigner: SecureEnclaveCustodyDigestSigning {
    let error: Error

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw error
    }
}
