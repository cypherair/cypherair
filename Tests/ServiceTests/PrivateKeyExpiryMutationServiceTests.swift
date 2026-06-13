import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

final class PrivateKeyExpiryMutationServiceTests: XCTestCase {
    private let engine = PgpEngine()

    func test_blockingPolicyBlocksSecureEnclaveModifyExpiryWithoutFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: privateKeyControlStore
        )
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        keyManagement.configurePrivateKeyExpiryMutationService(
            TestHelpers.makeExpiryMutator(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveOperationsBlocked),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: UnexpectedExpiryDigestSigner()
            )
        )

        do {
            _ = try await keyManagement.modifyExpiry(
                fingerprint: fixture.identity.fingerprint,
                newExpirySeconds: 31_536_000
            )
            XCTFail("Expected blocking policy to stop Secure Enclave modify-expiry")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, 0)
        XCTAssertEqual(privateKeyControlStore.beginModifyExpiryRequests, [])
        XCTAssertEqual(privateKeyControlStore.clearModifyExpiryCallCount, 0)
    }

    func test_secureEnclaveModifyExpiryUsesRealCatalogRouterAndSharedHandleStoreForV4AndV6() async throws {
        for configurationIdentity in [
            PGPKeyConfiguration.Identity.compatibleP256V4,
            .modernP256V6
        ] {
            let fixture = try await makeSecureEnclaveRouteFixture(configurationIdentity: configurationIdentity)
            let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
            let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
                engine: engine,
                privateKeyControlStore: privateKeyControlStore
            )
            try metadataPersistence.save(fixture.identity)
            try keyManagement.loadKeys()
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            keyStore.insert(fixture.route.signingHandle)
            keyStore.insert(fixture.keyAgreementHandle)
            keyManagement.configurePrivateKeyExpiryMutationService(
                TestHelpers.makeExpiryMutator(
                    engine: engine,
                    keyManagement: keyManagement,
                    resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                    handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                    digestSigner: SystemSecureEnclaveCustodyDigestSigner()
                )
            )

            let updated = try await keyManagement.modifyExpiry(
                fingerprint: fixture.identity.fingerprint,
                newExpirySeconds: 31_536_000
            )

            XCTAssertEqual(updated.fingerprint, fixture.identity.fingerprint)
            XCTAssertEqual(updated.keyVersion, configurationIdentity.configuration.keyVersion)
            XCTAssertEqual(updated.openPGPConfigurationIdentity, configurationIdentity)
            XCTAssertEqual(updated.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)
            XCTAssertFalse(updated.isExpired)
            XCTAssertNotNil(updated.expiryDate)
            XCTAssertNotEqual(updated.publicKeyData, fixture.identity.publicKeyData)
            let updatedInfo = try engine.parseKeyInfo(keyData: updated.publicKeyData)
            XCTAssertEqual(updatedInfo.fingerprint, fixture.identity.fingerprint)
            XCTAssertEqual(updatedInfo.keyVersion, configurationIdentity.configuration.keyVersion)
            XCTAssertNotNil(updatedInfo.expiryTimestamp)
            let updatedInspection = try PGPSecureEnclaveCustodyPublicBindingInspector(
                engine: engine
            ).inspectPublicBindings(publicKeyData: updated.publicKeyData)
            XCTAssertEqual(updatedInspection.fingerprint, fixture.identity.fingerprint)
            XCTAssertEqual(
                updatedInspection.signingPublicKeyX963,
                fixture.route.publicBindingInspection.signingPublicKeyX963
            )
            XCTAssertEqual(
                updatedInspection.keyAgreementPublicKeyX963,
                fixture.route.publicBindingInspection.keyAgreementPublicKeyX963
            )
            XCTAssertEqual(keyManagement.keys.map(\.fingerprint), [fixture.identity.fingerprint])
            XCTAssertEqual(keyManagement.keys.first?.publicKeyData, updated.publicKeyData)
            XCTAssertEqual(mockSE.generateCallCount, 0)
            XCTAssertEqual(mockSE.wrapCallCount, 0)
            XCTAssertEqual(mockSE.unwrapCallCount, 0)
            XCTAssertEqual(privateKeyControlStore.beginModifyExpiryRequests, [])
            XCTAssertEqual(privateKeyControlStore.clearModifyExpiryCallCount, 0)
            XCTAssertNil(try privateKeyControlStore.recoveryJournal().modifyExpiry)
        }
    }

    func test_secureEnclaveModifyExpiryCanRemoveExpiryWithoutSoftwareFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: privateKeyControlStore
        )
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        keyManagement.configurePrivateKeyExpiryMutationService(
            TestHelpers.makeExpiryMutator(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: SystemSecureEnclaveCustodyDigestSigner()
            )
        )

        let updated = try await keyManagement.modifyExpiry(
            fingerprint: fixture.identity.fingerprint,
            newExpirySeconds: nil
        )

        XCTAssertNil(updated.expiryDate)
        XCTAssertNil(try engine.parseKeyInfo(keyData: updated.publicKeyData).expiryTimestamp)
        XCTAssertEqual(mockSE.unwrapCallCount, 0)
        XCTAssertEqual(privateKeyControlStore.beginModifyExpiryRequests, [])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().modifyExpiry)
    }

    func test_secureEnclaveModifyExpiryRefreshesTransportSubkeyBindingPastOriginalExpiry() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture(expirySeconds: 2)
        let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: privateKeyControlStore
        )
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        keyManagement.configurePrivateKeyExpiryMutationService(
            TestHelpers.makeExpiryMutator(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: SystemSecureEnclaveCustodyDigestSigner()
            )
        )

        let updated = try await keyManagement.modifyExpiry(
            fingerprint: fixture.identity.fingerprint,
            newExpirySeconds: 31_536_000
        )
        XCTAssertTrue(updated.hasEncryptionSubkey)

        try await Task.sleep(for: .seconds(3))

        let reparsedInfo = try engine.parseKeyInfo(keyData: updated.publicKeyData)
        XCTAssertTrue(
            reparsedInfo.hasEncryptionSubkey,
            "Updated Secure Enclave public cert should keep the transport subkey valid after the old expiry."
        )
        XCTAssertFalse(reparsedInfo.isExpired)
        XCTAssertEqual(mockSE.unwrapCallCount, 0)
        XCTAssertEqual(privateKeyControlStore.beginModifyExpiryRequests, [])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().modifyExpiry)
    }

    func test_secureEnclaveModifyExpiryRecoversAfterKeyAlreadyExpired() async throws {
        for configurationIdentity in [
            PGPKeyConfiguration.Identity.compatibleP256V4,
            .modernP256V6
        ] {
            let fixture = try await makeSecureEnclaveRouteFixture(
                configurationIdentity: configurationIdentity,
                expirySeconds: 1
            )
            let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
            let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
                engine: engine,
                privateKeyControlStore: privateKeyControlStore
            )
            try metadataPersistence.save(fixture.identity)
            try keyManagement.loadKeys()
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            keyStore.insert(fixture.route.signingHandle)
            keyStore.insert(fixture.keyAgreementHandle)
            keyManagement.configurePrivateKeyExpiryMutationService(
                TestHelpers.makeExpiryMutator(
                    engine: engine,
                    keyManagement: keyManagement,
                    resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                    handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                    digestSigner: SystemSecureEnclaveCustodyDigestSigner()
                )
            )

            try await Task.sleep(for: .seconds(2))
            XCTAssertTrue(try engine.parseKeyInfo(keyData: fixture.identity.publicKeyData).isExpired)

            let extended = try await keyManagement.modifyExpiry(
                fingerprint: fixture.identity.fingerprint,
                newExpirySeconds: 31_536_000
            )
            let extendedInfo = try engine.parseKeyInfo(keyData: extended.publicKeyData)
            XCTAssertFalse(extendedInfo.isExpired)
            XCTAssertTrue(extendedInfo.hasEncryptionSubkey)

            let removed = try await keyManagement.modifyExpiry(
                fingerprint: fixture.identity.fingerprint,
                newExpirySeconds: nil
            )
            let removedInfo = try engine.parseKeyInfo(keyData: removed.publicKeyData)
            XCTAssertFalse(removedInfo.isExpired)
            XCTAssertTrue(removedInfo.hasEncryptionSubkey)
            XCTAssertNil(removedInfo.expiryTimestamp)
            XCTAssertEqual(mockSE.unwrapCallCount, 0)
            XCTAssertEqual(privateKeyControlStore.beginModifyExpiryRequests, [])
            XCTAssertNil(try privateKeyControlStore.recoveryJournal().modifyExpiry)
        }
    }

    func test_secureEnclaveModifyExpiryMergesCurrentCatalogFlagsAfterAsyncSigning() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: privateKeyControlStore
        )
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let gate = ExpiryMutationSuspensionGate()
        keyManagement.configurePrivateKeyExpiryMutationService(
            SuspendedExpiryMutationService(
                route: fixture.route,
                material: Self.publicModifiedMaterial(from: fixture.identity, expiryTimestamp: nil),
                gate: gate
            )
        )

        let fingerprint = fixture.identity.fingerprint
        let task = Task { [keyManagement, fingerprint] in
            try await keyManagement.modifyExpiry(
                fingerprint: fingerprint,
                newExpirySeconds: nil
            )
        }
        await gate.waitUntilSuspended()
        try keyManagement.setDefaultKey(fingerprint: fingerprint)
        keyManagement.confirmKeyBackupExported(fingerprint: fingerprint)
        await gate.resume()

        let updated = try await task.value
        XCTAssertTrue(updated.isDefault)
        XCTAssertTrue(updated.isBackedUp)
        XCTAssertTrue(keyManagement.keys.first?.isDefault == true)
        XCTAssertTrue(keyManagement.keys.first?.isBackedUp == true)
        let reloaded = try metadataPersistence.loadAll()
        XCTAssertEqual(reloaded.count, 1)
        XCTAssertTrue(reloaded[0].isDefault)
        XCTAssertTrue(reloaded[0].isBackedUp)
    }

    func test_secureEnclaveModifyExpiryDoesNotResurrectDeletedCatalogIdentity() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
        let (keyManagement, _, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: privateKeyControlStore
        )
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let gate = ExpiryMutationSuspensionGate()
        keyManagement.configurePrivateKeyExpiryMutationService(
            SuspendedExpiryMutationService(
                route: fixture.route,
                material: Self.publicModifiedMaterial(from: fixture.identity, expiryTimestamp: nil),
                gate: gate
            )
        )

        let fingerprint = fixture.identity.fingerprint
        let task = Task { [keyManagement, fingerprint] in
            try await keyManagement.modifyExpiry(
                fingerprint: fingerprint,
                newExpirySeconds: nil
            )
        }
        await gate.waitUntilSuspended()
        try keyManagement.deleteKey(fingerprint: fingerprint)
        await gate.resume()

        do {
            _ = try await task.value
            XCTFail("Expected deleted identity to block late Secure Enclave expiry writeback")
        } catch CypherAirError.keyMetadataUnavailable {
            // Expected: the late SE expiry writeback hits the catalog miss and now
            // surfaces the honest key-metadata-unavailable error (matching the
            // software path), not the decrypt-flavored noMatchingKey.
        } catch {
            XCTFail("Expected keyMetadataUnavailable, got \(error)")
        }
        XCTAssertTrue(keyManagement.keys.isEmpty)
        XCTAssertTrue(try metadataPersistence.loadAll().isEmpty)
    }

    func test_secureEnclaveModifyExpiryMissingHandleSurfacesUnavailableWithoutFallback() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: privateKeyControlStore
        )
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        keyManagement.configurePrivateKeyExpiryMutationService(
            TestHelpers.makeExpiryMutator(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore())
            )
        )

        do {
            _ = try await keyManagement.modifyExpiry(
                fingerprint: fixture.identity.fingerprint,
                newExpirySeconds: 31_536_000
            )
            XCTFail("Expected missing Secure Enclave handle to fail")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .privateHandleMissing)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, 0)
        XCTAssertEqual(privateKeyControlStore.beginModifyExpiryRequests, [])
    }

    func test_secureEnclaveModifyExpiryCancellationAndCallbackFailuresDoNotFallback() async throws {
        let cases: [(Error, ExpectedExpiryError)] = [
            (CancellationError(), .operationCancelled),
            (
                SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing),
                .keyOperationUnavailable(.localAuthenticationFailed)
            ),
        ]

        for (signingError, expectedError) in cases {
            let fixture = try await makeSecureEnclaveRouteFixture()
            let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
            let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
                engine: engine,
                privateKeyControlStore: privateKeyControlStore
            )
            try metadataPersistence.save(fixture.identity)
            try keyManagement.loadKeys()
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            keyStore.insert(fixture.route.signingHandle)
            keyStore.insert(fixture.keyAgreementHandle)
            keyManagement.configurePrivateKeyExpiryMutationService(
                TestHelpers.makeExpiryMutator(
                    engine: engine,
                    keyManagement: keyManagement,
                    resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                    handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                    digestSigner: ThrowingExpiryDigestSigner(error: signingError)
                )
            )

            do {
                _ = try await keyManagement.modifyExpiry(
                    fingerprint: fixture.identity.fingerprint,
                    newExpirySeconds: 31_536_000
                )
                XCTFail("Expected Secure Enclave signing failure")
            } catch let error as CypherAirError {
                assert(error, matches: expectedError)
            } catch {
                XCTFail("Expected CypherAirError, got \(error)")
            }

            XCTAssertEqual(mockSE.unwrapCallCount, 0)
            XCTAssertEqual(privateKeyControlStore.beginModifyExpiryRequests, [])
        }
    }

    func test_secureEnclaveModifyExpiryAuthenticatesOnceAndEndsAuthorizationOnSuccess() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let stub = StubExpiryCustodyOperationAuthenticator()
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
        keyManagement.configurePrivateKeyExpiryMutationService(
            TestHelpers.makeExpiryMutator(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: SystemSecureEnclaveCustodyDigestSigner()
            )
        )

        let updated = try await keyManagement.modifyExpiry(
            fingerprint: fixture.identity.fingerprint,
            newExpirySeconds: 31_536_000
        )

        XCTAssertEqual(updated.fingerprint, fixture.identity.fingerprint)
        XCTAssertEqual(stub.calls, 1, "Exactly one custody authentication for the whole operation.")
        XCTAssertEqual(
            stub.context.invalidateCount,
            1,
            "The dispatcher's defer ends the operation authorization exactly once."
        )
        let contextBearingLoads = keyStore.loadRequests.filter { $0.authenticationContext != nil }
        XCTAssertEqual(contextBearingLoads.count, 1)
        XCTAssertTrue(contextBearingLoads.first?.authenticationContext === stub.context)
        XCTAssertEqual(mockSE.unwrapCallCount, 0)
    }

    func test_secureEnclaveModifyExpiryCancelledAuthenticationBlocksBeforeAnyMutation() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let stub = StubExpiryCustodyOperationAuthenticator()
        stub.errorToThrow = CypherAirError.operationCancelled
        let privateKeyControlStore = RecordingExpiryPrivateKeyControlStore(mode: .standard)
        let (keyManagement, mockSE, mockKeychain, _, metadataPersistence) = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: privateKeyControlStore,
            secureEnclaveCustodyOperationAuthenticator: stub.authenticate
        )
        _ = mockKeychain
        try metadataPersistence.save(fixture.identity)
        try keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.insert(fixture.route.signingHandle)
        keyStore.insert(fixture.keyAgreementHandle)
        keyManagement.configurePrivateKeyExpiryMutationService(
            TestHelpers.makeExpiryMutator(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: UnexpectedExpiryDigestSigner()
            )
        )

        do {
            _ = try await keyManagement.modifyExpiry(
                fingerprint: fixture.identity.fingerprint,
                newExpirySeconds: 31_536_000
            )
            XCTFail("Expected cancelled custody authentication to block")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .localAuthenticationCancelled)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(stub.calls, 1)
        XCTAssertTrue(keyStore.loadRequests.allSatisfy { $0.authenticationContext == nil })
        XCTAssertEqual(mockSE.unwrapCallCount, 0)
        XCTAssertEqual(privateKeyControlStore.beginModifyExpiryRequests, [])
    }

    func test_secureEnclaveModifyExpiryEndsAuthorizationAfterSigningFailure() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let stub = StubExpiryCustodyOperationAuthenticator()
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
        keyManagement.configurePrivateKeyExpiryMutationService(
            TestHelpers.makeExpiryMutator(
                engine: engine,
                keyManagement: keyManagement,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
                digestSigner: ThrowingExpiryDigestSigner(
                    error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing)
                )
            )
        )

        do {
            _ = try await keyManagement.modifyExpiry(
                fingerprint: fixture.identity.fingerprint,
                newExpirySeconds: 31_536_000
            )
            XCTFail("Expected signing failure to throw")
        } catch {
        }

        XCTAssertEqual(stub.calls, 1)
        XCTAssertEqual(
            stub.context.invalidateCount,
            1,
            "The dispatcher's defer ends the authorization on the failure path too."
        )
    }

    func test_softwareModifyExpiryNeverInvokesCustodyOperationAuthenticator() async throws {
        let stub = StubExpiryCustodyOperationAuthenticator()
        let (keyManagement, _, mockKeychain, _, _) = TestHelpers.makeKeyManagement(
            engine: engine,
            secureEnclaveCustodyOperationAuthenticator: stub.authenticate
        )
        _ = mockKeychain
        let identity = try await keyManagement.generateKey(
            name: "Software Expiry",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        keyManagement.configurePrivateKeyExpiryMutationService(
            TestHelpers.makeExpiryMutator(
                engine: engine,
                keyManagement: keyManagement,
                digestSigner: UnexpectedExpiryDigestSigner()
            )
        )

        let updated = try await keyManagement.modifyExpiry(
            fingerprint: identity.fingerprint,
            newExpirySeconds: 60 * 60 * 24
        )

        XCTAssertEqual(updated.fingerprint, identity.fingerprint)
        XCTAssertEqual(stub.calls, 0, "Software custody never consults the custody pre-authenticator.")
    }

    private func assert(
        _ error: CypherAirError,
        matches expected: ExpectedExpiryError,
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

    private func makeSecureEnclaveRouteFixture(
        configurationIdentity: PGPKeyConfiguration.Identity = .compatibleP256V4,
        expirySeconds: UInt64? = 3600
    ) async throws -> ExpirySecureEnclaveRouteFixture {
        let signingPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let keyAgreementPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let signingPublicKeyX963 = try Self.publicKeyX963(from: signingPrivateKey)
        let keyAgreementPublicKeyX963 = try Self.publicKeyX963(from: keyAgreementPrivateKey)
        let handleSetIdentifier = "expiry-\(UUID().uuidString.lowercased())"
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
            name: "Secure Enclave Expiry",
            email: "secure-expiry@example.invalid",
            expirySeconds: expirySeconds,
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

        return ExpirySecureEnclaveRouteFixture(
            identity: identity,
            route: SecureEnclaveSignerRoute(
                identity: identity,
                operation: .modifyExpiry,
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

    private static func publicModifiedMaterial(
        from identity: PGPKeyIdentity,
        expiryTimestamp: UInt64?
    ) -> PGPPublicModifiedExpiryKeyMaterial {
        PGPPublicModifiedExpiryKeyMaterial(
            publicKeyData: identity.publicKeyData,
            metadata: PGPKeyMetadata(
                fingerprint: identity.fingerprint,
                keyVersion: identity.keyVersion,
                userId: identity.userId,
                hasEncryptionSubkey: identity.hasEncryptionSubkey,
                isRevoked: identity.isRevoked,
                isExpired: false,
                profile: identity.profile,
                primaryAlgo: identity.primaryAlgo,
                subkeyAlgo: identity.subkeyAlgo,
                expiryTimestamp: expiryTimestamp
            )
        )
    }
}

private struct ExpirySecureEnclaveRouteFixture {
    let identity: PGPKeyIdentity
    let route: SecureEnclaveSignerRoute
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
}

private actor ExpiryMutationSuspensionGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var suspended = false

    func suspend() async {
        suspended = true
        waiters.forEach { $0.resume() }
        waiters.removeAll()
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }

    func waitUntilSuspended() async {
        if suspended {
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func resume() {
        continuation?.resume()
        continuation = nil
    }
}

private final class SuspendedExpiryMutationService: PrivateKeyExpiryMutationRouting, @unchecked Sendable {
    private let route: SecureEnclaveSignerRoute
    private let material: PGPPublicModifiedExpiryKeyMaterial
    private let gate: ExpiryMutationSuspensionGate

    init(
        route: SecureEnclaveSignerRoute,
        material: PGPPublicModifiedExpiryKeyMaterial,
        gate: ExpiryMutationSuspensionGate
    ) {
        self.route = route
        self.material = material
        self.gate = gate
    }

    func routeModifyExpiry(fingerprint: String) async -> PrivateKeyOperationRoute {
        guard route.identity.fingerprint == fingerprint else {
            return .blocked(.unavailable(.metadataAssociationMismatch))
        }
        return .secureEnclaveSigner(route)
    }

    func modifySecureEnclaveExpiry(
        route: SecureEnclaveSignerRoute,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial {
        await gate.suspend()
        return material
    }
}

private enum ExpectedExpiryError {
    case operationCancelled
    case keyOperationUnavailable(PGPKeyOperationFailureCategory)
}

private final class StubExpiryCustodyOperationAuthenticator: @unchecked Sendable {
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

private final class RecordingExpiryPrivateKeyControlStore: PrivateKeyControlStoreProtocol, @unchecked Sendable {
    private var mode: AuthenticationMode?
    private var journal = PrivateKeyControlRecoveryJournal.empty
    private(set) var beginModifyExpiryRequests: [String] = []
    private(set) var clearModifyExpiryCallCount = 0

    init(mode: AuthenticationMode?) {
        self.mode = mode
    }

    var privateKeyControlState: PrivateKeyControlState {
        guard let mode else {
            return .locked
        }
        return .unlocked(mode)
    }

    func requireUnlockedAuthMode() throws -> AuthenticationMode {
        guard let mode else {
            throw PrivateKeyControlError.locked
        }
        return mode
    }

    func recoveryJournal() throws -> PrivateKeyControlRecoveryJournal {
        _ = try requireUnlockedAuthMode()
        return journal
    }

    func beginRewrap(targetMode: AuthenticationMode) throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapTargetMode = targetMode
        journal.rewrapPhase = .preparing
    }

    func markRewrapCommitRequired() throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapPhase = .commitRequired
    }

    func completeRewrap(targetMode: AuthenticationMode) throws {
        _ = try requireUnlockedAuthMode()
        mode = targetMode
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func clearRewrapJournal() throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func beginModifyExpiry(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        beginModifyExpiryRequests.append(fingerprint)
        journal.modifyExpiry = ModifyExpiryRecoveryEntry(fingerprint: fingerprint)
    }

    func clearModifyExpiryJournal() throws {
        _ = try requireUnlockedAuthMode()
        clearModifyExpiryCallCount += 1
        journal.modifyExpiry = nil
    }

    func clearModifyExpiryJournalIfMatches(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        guard journal.modifyExpiry?.fingerprint == fingerprint else {
            return
        }
        clearModifyExpiryCallCount += 1
        journal.modifyExpiry = nil
    }
}

private struct UnexpectedExpiryDigestSigner: SecureEnclaveCustodyDigestSigning {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        XCTFail("Digest signer should not be called")
        throw CancellationError()
    }
}

private struct ThrowingExpiryDigestSigner: SecureEnclaveCustodyDigestSigning {
    let error: Error

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw error
    }
}
