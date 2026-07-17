import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

final class PrivateKeyContactCertificationServiceTests: XCTestCase {
    private let engine = PgpEngine()

    func test_softwareUserIdCertificationRemainsBehaviorCompatibleAndZeroizes() async throws {
        let stack = await TestHelpers.makeServiceStack(engine: engine)
        defer { stack.cleanup() }
        let signer = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Software Certification Signer",
            email: "software-certification-signer@example.invalid"
        )
        let target = try generatedTarget(profile: .universal)
        let selectedUserId = try selectedUserId(
            service: stack.certificateSignatureService,
            targetCert: target.publicKeyData
        )
        let unwrapCountBefore = stack.mockSE.unwrapCallCount

        let signature = try await stack.certificateSignatureService.generateUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId,
            certificationKind: .positive
        )
        let verification = try await stack.certificateSignatureService.verifyUserIdBindingSignature(
            signature: signature,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId
        )

        XCTAssertEqual(verification.status, .valid)
        XCTAssertEqual(verification.signerPrimaryFingerprint, signer.fingerprint)
        XCTAssertEqual(verification.signerIdentity?.source, .ownKey)
        XCTAssertEqual(stack.mockSE.unwrapCallCount, unwrapCountBefore + 1)
    }

    func test_blockingPolicyBlocksSecureEnclaveCertificationBeforeHandleLookup() async throws {
        let stack = await TestHelpers.makeServiceStack(engine: engine)
        defer { stack.cleanup() }
        let fixture = try await makeSecureEnclaveRouteFixture()
        try stack.metadataPersistence.save(fixture.identity)
        try stack.keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        let service = makeCertificateSignatureService(
            stack: stack,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveOperationsBlocked),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
            digestSigner: UnexpectedCertificationDigestSigner()
        )
        let target = try generatedTarget(profile: .universal)
        let selectedUserId = try selectedUserId(service: service, targetCert: target.publicKeyData)

        do {
            _ = try await service.generateUserIdCertification(
                signerFingerprint: fixture.identity.fingerprint,
                targetCert: target.publicKeyData,
                selectedUserId: selectedUserId,
                certificationKind: .positive
            )
            XCTFail("Expected blocking policy to stop Secure Enclave certification")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(stack.mockSE.unwrapCallCount, 0)
    }

    func test_secureEnclaveCertificationUsesRealCatalogRouterAndSharedHandleStoreForV4AndV6()
        async throws
    {
        for configurationIdentity in [
            PGPKeyConfiguration.Identity.compatibleP256V4,
            .modernP256V6,
        ] {
            let stack = await TestHelpers.makeServiceStack(engine: engine)
            defer { stack.cleanup() }
            let fixture = try await makeSecureEnclaveRouteFixture(
                configurationIdentity: configurationIdentity
            )
            try stack.metadataPersistence.save(fixture.identity)
            try stack.keyManagement.loadKeys()
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            keyStore.insert(fixture.route.signingHandle)
            keyStore.insert(fixture.keyAgreementHandle)
            let service = makeCertificateSignatureService(
                stack: stack,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
                digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
            )
            let target = try generatedTarget(profile: .universal)
            let contactKey = try importedContactKey(
                publicKeyData: target.publicKeyData,
                contactService: stack.contactService
            )
            let selectedUserId = try selectedUserId(service: service, targetCert: target.publicKeyData)
            let snapshot = catalogSnapshot(stack: stack)

            let signature = try await service.generateUserIdCertification(
                signerFingerprint: fixture.identity.fingerprint,
                targetCert: target.publicKeyData,
                selectedUserId: selectedUserId,
                certificationKind: .positive
            )
            let verification = try await service.verifyUserIdBindingSignature(
                signature: signature,
                targetCert: target.publicKeyData,
                selectedUserId: selectedUserId
            )
            let validation = try await service.validateUserIdCertificationArtifact(
                signature: signature,
                targetKey: contactKey,
                targetCert: target.publicKeyData,
                selectedUserId: selectedUserId,
                source: .generated
            )

            XCTAssertEqual(verification.status, .valid)
            XCTAssertEqual(verification.signerPrimaryFingerprint, fixture.identity.fingerprint)
            XCTAssertEqual(verification.signingKeyFingerprint, nil)
            XCTAssertEqual(verification.signerIdentity?.source, .ownKey)
            XCTAssertEqual(validation.verification.status, .valid)
            XCTAssertEqual(fixture.identity.keyVersion, configurationIdentity.configuration.keyVersion)
            XCTAssertEqual(fixture.identity.openPGPConfigurationIdentity, configurationIdentity)
            XCTAssertEqual(fixture.identity.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)
            XCTAssertEqual(stack.mockSE.unwrapCallCount, 0)
            assertNoCatalogOrKeychainMutation(stack: stack, before: snapshot)
        }
    }

    func test_secureEnclaveCertificationSelectorMismatchFailsBeforeHandleLookupOrUnwrap()
        async throws
    {
        let stack = await TestHelpers.makeServiceStack(engine: engine)
        defer { stack.cleanup() }
        let fixture = try await makeSecureEnclaveRouteFixture()
        try stack.metadataPersistence.save(fixture.identity)
        try stack.keyManagement.loadKeys()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        let service = makeCertificateSignatureService(
            stack: stack,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
            digestSigner: UnexpectedCertificationDigestSigner()
        )
        let target = try generatedTarget(profile: .universal)
        let selectedUserId = try selectedUserId(service: service, targetCert: target.publicKeyData)
        let mismatchedSelector = UserIdSelectionOption(
            occurrenceIndex: selectedUserId.occurrenceIndex,
            userIdData: selectedUserId.userIdData + Data("-mismatch".utf8),
            displayText: selectedUserId.displayText,
            isCurrentlyPrimary: selectedUserId.isCurrentlyPrimary,
            isCurrentlyRevoked: selectedUserId.isCurrentlyRevoked,
            isSelfCertified: selectedUserId.isSelfCertified
        )

        do {
            _ = try await service.generateUserIdCertification(
                signerFingerprint: fixture.identity.fingerprint,
                targetCert: target.publicKeyData,
                selectedUserId: mismatchedSelector,
                certificationKind: .positive
            )
            XCTFail("Expected selector mismatch to fail before routing")
        } catch CypherAirError.invalidKeyData {
            // Expected.
        } catch {
            XCTFail("Expected invalidKeyData, got \(error)")
        }

        XCTAssertEqual(stack.mockSE.unwrapCallCount, 0)
    }

    func test_secureEnclaveCertificationHandleFailuresDoNotFallback() async throws {
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
            let stack = await TestHelpers.makeServiceStack(engine: engine)
            defer { stack.cleanup() }
            let fixture = try await makeSecureEnclaveRouteFixture()
            try stack.metadataPersistence.save(fixture.identity)
            try stack.keyManagement.loadKeys()
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            if let loadError {
                keyStore.insert(fixture.route.signingHandle)
                keyStore.insert(fixture.keyAgreementHandle)
                keyStore.failLoadError = loadError
            }
            let service = makeCertificateSignatureService(
                stack: stack,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
                digestSigner: UnexpectedCertificationDigestSigner()
            )
            let target = try generatedTarget(profile: .universal)
            let selectedUserId = try selectedUserId(service: service, targetCert: target.publicKeyData)

            do {
                _ = try await service.generateUserIdCertification(
                    signerFingerprint: fixture.identity.fingerprint,
                    targetCert: target.publicKeyData,
                    selectedUserId: selectedUserId,
                    certificationKind: .positive
                )
                XCTFail("Expected Secure Enclave handle failure")
            } catch CypherAirError.keyOperationUnavailable(let category) {
                XCTAssertEqual(category, expectedCategory)
            } catch {
                XCTFail("Expected keyOperationUnavailable, got \(error)")
            }

            XCTAssertEqual(stack.mockSE.unwrapCallCount, 0)
        }
    }

    func test_secureEnclaveCertificationCancellationAndCallbackFailuresDoNotFallback()
        async throws
    {
        let cases: [(Error, ExpectedCertificationError)] = [
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
            let stack = await TestHelpers.makeServiceStack(engine: engine)
            defer { stack.cleanup() }
            let fixture = try await makeSecureEnclaveRouteFixture()
            try stack.metadataPersistence.save(fixture.identity)
            try stack.keyManagement.loadKeys()
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            keyStore.insert(fixture.route.signingHandle)
            keyStore.insert(fixture.keyAgreementHandle)
            let service = makeCertificateSignatureService(
                stack: stack,
                resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
                digestSigner: ThrowingCertificationDigestSigner(error: signingError)
            )
            let target = try generatedTarget(profile: .universal)
            let selectedUserId = try selectedUserId(service: service, targetCert: target.publicKeyData)

            do {
                _ = try await service.generateUserIdCertification(
                    signerFingerprint: fixture.identity.fingerprint,
                    targetCert: target.publicKeyData,
                    selectedUserId: selectedUserId,
                    certificationKind: .positive
                )
                XCTFail("Expected Secure Enclave signing failure")
            } catch let error as CypherAirError {
                assert(error, matches: expectedError)
            } catch {
                XCTFail("Expected CypherAirError, got \(error)")
            }

            XCTAssertEqual(stack.mockSE.unwrapCallCount, 0)
        }
    }

    func test_secureEnclaveCertificationEndsAuthorizationAfterSuccessAndSigningFailure() async throws {
        let fixture = try await makeSecureEnclaveRouteFixture()
        let stub = StubCertificationCustodyOperationAuthenticator()
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
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let target = try generatedTarget(profile: .universal)
        let targetInfo = try engine.parseKeyInfo(keyData: target.publicKeyData)
        let selectedUserId = try XCTUnwrap(
            certificateAdapter.validatedCatalog(
                certData: target.publicKeyData,
                expectedFingerprint: targetInfo.fingerprint
            ).userIds.first
        )

        let service = TestHelpers.makeContactCertificationSigner(
            engine: engine,
            keyManagement: keyManagement,
            certificateAdapter: certificateAdapter,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
            digestSigner: SoftwareP256CustodyProvider.shared.digestSigner
        )
        _ = try await service.generateUserIdCertification(
            signerFingerprint: fixture.identity.fingerprint,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId,
            certificationKind: .positive
        )
        XCTAssertEqual(stub.calls, 1, "Exactly one custody authentication per certification.")
        XCTAssertEqual(stub.context.invalidateCount, 1)
        XCTAssertEqual(mockSE.unwrapCallCount, 0)

        let failingService = TestHelpers.makeContactCertificationSigner(
            engine: engine,
            keyManagement: keyManagement,
            certificateAdapter: certificateAdapter,
            resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256),
            digestSigner: ThrowingCertificationDigestSigner(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.signing)
            )
        )
        do {
            _ = try await failingService.generateUserIdCertification(
                signerFingerprint: fixture.identity.fingerprint,
                targetCert: target.publicKeyData,
                selectedUserId: selectedUserId,
                certificationKind: .positive
            )
            XCTFail("Expected signing failure to throw")
        } catch {
        }
        XCTAssertEqual(stub.calls, 2)
        XCTAssertEqual(stub.context.invalidateCount, 2)
    }

    private func generatedTarget(profile: KeyProfile) throws -> GeneratedKey {
        try engine.generateKey(
            name: "Certification Target",
            email: "certification-target@example.invalid",
            expirySeconds: nil,
            profile: profile
        )
    }

    private func selectedUserId(
        service: CertificateSignatureService,
        targetCert: Data
    ) throws -> UserIdSelectionOption {
        try XCTUnwrap(service.selectionCatalog(targetCert: targetCert).userIds.first)
    }

    private func importedContactKey(
        publicKeyData: Data,
        contactService: ContactService
    ) throws -> ContactKeySummary {
        let result = try contactService.importContact(publicKeyData: publicKeyData)
        guard case .added(_, let key) = result else {
            throw XCTSkip("Expected contact to import for certification validation")
        }
        return key
    }

    private func makeCertificateSignatureService(
        stack: TestHelpers.ServiceStack,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> CertificateSignatureService {
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        return CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: stack.keyManagement,
            contactService: stack.contactService,
            certificationSigner: TestHelpers.makeContactCertificationSigner(
                engine: engine,
                keyManagement: stack.keyManagement,
                certificateAdapter: certificateAdapter,
                resolver: resolver,
                handleStore: handleStore,
                digestSigner: digestSigner
            )
        )
    }

    private func catalogSnapshot(
        stack: TestHelpers.ServiceStack
    ) -> (keys: [PGPKeyIdentity], saveCount: Int, deleteCount: Int) {
        (stack.keyManagement.keys, stack.mockKC.saveCallCount, stack.mockKC.deleteCallCount)
    }

    private func assertNoCatalogOrKeychainMutation(
        stack: TestHelpers.ServiceStack,
        before: (keys: [PGPKeyIdentity], saveCount: Int, deleteCount: Int),
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(stack.keyManagement.keys, before.keys, file: file, line: line)
        XCTAssertEqual(stack.mockKC.saveCallCount, before.saveCount, file: file, line: line)
        XCTAssertEqual(stack.mockKC.deleteCallCount, before.deleteCount, file: file, line: line)
    }

    private func assert(
        _ error: CypherAirError,
        matches expected: ExpectedCertificationError,
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
        configurationIdentity: PGPKeyConfiguration.Identity = .compatibleP256V4
    ) async throws -> ContactCertificationSecureEnclaveRouteFixture {
        let custodyMaterial = SoftwareP256CustodyProvider.shared.makeMaterial()
        let handlePair = try SoftwareP256CustodyProvider.shared.loadedHandlePair(for: custodyMaterial)
        let signingHandle = handlePair.signing
        let keyAgreementHandle = handlePair.keyAgreement
        let material = try await PGPSecureEnclaveCustodyGenerationAdapter(
            engine: engine
        ).generatePublicCertificate(
            name: "Secure Enclave Contact Certification",
            email: "secure-contact-certification@example.invalid",
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

        return ContactCertificationSecureEnclaveRouteFixture(
            identity: identity,
            route: SecureEnclaveSignerRoute(
                identity: identity,
                operation: .certify,
                publicBindingInspection: inspection,
                signingHandle: signingHandle
            ),
            keyAgreementHandle: keyAgreementHandle
        )
    }

}

private struct ContactCertificationSecureEnclaveRouteFixture {
    let identity: PGPKeyIdentity
    let route: SecureEnclaveSignerRoute
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
}

private enum ExpectedCertificationError {
    case operationCancelled
    case keyOperationUnavailable(PGPKeyOperationFailureCategory)
}

private struct UnexpectedCertificationDigestSigner: SecureEnclaveCustodyDigestSigning {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        XCTFail("Digest signer should not be called")
        throw CancellationError()
    }
}

private final class StubCertificationCustodyOperationAuthenticator: @unchecked Sendable {
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

private struct ThrowingCertificationDigestSigner: SecureEnclaveCustodyDigestSigning {
    let error: Error

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw error
    }
}
