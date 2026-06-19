import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

final class PrivateKeyOperationRouterTests: XCTestCase {
    func test_softwareCustodyRoutesWithoutInspectingSecureEnclaveHandles() async throws {
        let identity = makeSoftwareIdentity()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        let inspector = RecordingPublicBindingInspector()
        inspector.error = CypherAirError.invalidKeyData(reason: "Unexpected public binding inspection")
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore
        )

        let route = await router.route(for: PrivateKeyOperationRequest(
            fingerprint: identity.fingerprint,
            operation: .sign
        ))

        guard case .softwareSecretCertificate(let softwareRoute) = route else {
            return XCTFail("Expected software custody route")
        }
        XCTAssertEqual(softwareRoute.identity.fingerprint, identity.fingerprint)
        XCTAssertEqual(softwareRoute.operation, .sign)
        XCTAssertEqual(inspector.inspectCallCount, 0)
    }

    func test_blockingPolicyBlocksSecureEnclavePrivateOperationBeforeHandleLookup() async throws {
        let identity = makeSecureEnclaveIdentity()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        let inspector = RecordingPublicBindingInspector()
        inspector.error = CypherAirError.invalidKeyData(reason: "Unexpected public binding inspection")
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveOperationsBlocked,
            inspector: inspector,
            keyStore: keyStore
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.operationUnavailableByPolicy)
        )
        XCTAssertEqual(inspector.inspectCallCount, 0)
    }

    func test_signingPolicyRoutesSecureEnclaveSigningClassOperations() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-signing" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore
        )

        let signingOperations: [PGPPrivateOperationKind] = [
            .sign,
            .certify,
            .revoke,
            .modifyExpiry
        ]
        for operation in signingOperations {
            let route = await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: operation
            ))
            guard case .secureEnclaveSigner(let signerRoute) = route else {
                return XCTFail("Expected Secure Enclave signer route for \(operation)")
            }
            XCTAssertEqual(signerRoute.identity.fingerprint, identity.fingerprint)
            XCTAssertEqual(signerRoute.operation, operation)
            XCTAssertEqual(signerRoute.signingHandle.binding, pair.signing)
            XCTAssertEqual(
                signerRoute.publicBindingInspection.signingPublicKeyX963,
                pair.signing.publicKeyX963
            )
        }
    }

    func test_refreshBindingRemainsExplicitlyNotImplementedUnderSigningRoutePolicy() async throws {
        let identity = makeSecureEnclaveIdentity()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        let inspector = RecordingPublicBindingInspector()
        inspector.error = CypherAirError.invalidKeyData(reason: "Unexpected public binding inspection")
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .refreshBinding
            )),
            .notImplemented(.operationNotImplementedForCustody)
        )
        XCTAssertEqual(inspector.inspectCallCount, 0)
    }

    func test_decryptRemainsBlockedForPhase5ASigningRouter() async throws {
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: MockSecureEnclaveCustodyKeyStore()
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .decrypt
            )),
            .notImplemented(.operationNotImplementedForCustody)
        )
        XCTAssertEqual(inspector.inspectCallCount, 0)
    }

    func test_keyAgreementPolicyRoutesSecureEnclaveDecryptOperation() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-agreement" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveKeyAgreementRoutes,
            inspector: inspector,
            keyStore: keyStore
        )

        let route = await router.route(for: PrivateKeyOperationRequest(
            fingerprint: identity.fingerprint,
            operation: .decrypt
        ))

        guard case .secureEnclaveKeyAgreement(let keyAgreementRoute) = route else {
            return XCTFail("Expected Secure Enclave key-agreement route")
        }
        XCTAssertEqual(keyAgreementRoute.identity.fingerprint, identity.fingerprint)
        XCTAssertEqual(keyAgreementRoute.operation, .decrypt)
        XCTAssertEqual(keyAgreementRoute.keyAgreementHandle.binding, pair.keyAgreement)
        XCTAssertEqual(
            keyAgreementRoute.publicBindingInspection.keyAgreementPublicKeyX963,
            pair.keyAgreement.publicKeyX963
        )
    }

    func test_keyAgreementPolicyBlocksSigningClassOperationsBeforeInspection() async throws {
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.error = CypherAirError.invalidKeyData(reason: "Unexpected public binding inspection")
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveKeyAgreementRoutes,
            inspector: inspector,
            keyStore: MockSecureEnclaveCustodyKeyStore()
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .notImplemented(.operationNotImplementedForCustody)
        )
        XCTAssertEqual(inspector.inspectCallCount, 0)
    }

    func test_missingIdentityReturnsSanitizedBlockedRoute() async throws {
        let router = try makeRouter(
            identities: [],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: RecordingPublicBindingInspector(),
            keyStore: MockSecureEnclaveCustodyKeyStore()
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: "missing",
                operation: .sign
            )),
            .unavailable(.metadataAssociationMismatch)
        )
    }

    func test_invalidConfigurationCustodyPairBlocksBeforeInspection() async throws {
        let identity = PGPKeyIdentity(
            fingerprint: "3333333333333333333333333333333333333333",
            keyVersion: 4,
            profile: .universal,
            userId: "Invalid <invalid@example.invalid>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data([0x33]),
            revocationCert: Data([0x34]),
            primaryAlgo: "ECDSA P-256",
            subkeyAlgo: "ECDH P-256",
            expiryDate: nil,
            openPGPConfigurationIdentity: .compatibleP256V4,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
        let inspector = RecordingPublicBindingInspector()
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: MockSecureEnclaveCustodyKeyStore()
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unsupported(.invalidConfigurationCustody)
        )
        XCTAssertEqual(inspector.inspectCallCount, 0)
    }

    func test_publicCertificateInspectionFailureMapsToSanitizedCategory() async throws {
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.error = CypherAirError.invalidKeyData(reason: "Malformed certificate")
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: MockSecureEnclaveCustodyKeyStore()
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.publicCertificateAssociationMismatch)
        )
    }

    func test_publicCertificateFingerprintMismatchBlocksAsMetadataMismatch() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-fpmismatch" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(
            identity: identity,
            pair: pair,
            fingerprint: "ffffffffffffffffffffffffffffffffffffffff"
        )
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.metadataAssociationMismatch)
        )
    }

    func test_missingHandleBlocksWithoutSoftwareFallback() async throws {
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(
            identity: identity,
            signingPublicKeyX963: makePublicKey(byte: 0x41),
            keyAgreementPublicKeyX963: makePublicKey(byte: 0x42)
        )
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: MockSecureEnclaveCustodyKeyStore()
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.privateHandleMissing)
        )
    }

    func test_missingKeyAgreementHandleBlocksWithoutSoftwareFallback() async throws {
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(
            identity: identity,
            signingPublicKeyX963: makePublicKey(byte: 0x71),
            keyAgreementPublicKeyX963: makePublicKey(byte: 0x72)
        )
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveKeyAgreementRoutes,
            inspector: inspector,
            keyStore: MockSecureEnclaveCustodyKeyStore()
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .decrypt
            )),
            .unavailable(.privateHandleMissing)
        )
    }

    func test_wrongHandleRoleMapsToRoleMismatch() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let signingReference = try reference("router-wrong-role", .signing)
        let keyAgreementReference = try reference("router-wrong-role", .keyAgreement)
        let wrongSigningHandle = SecureEnclaveCustodyLoadedHandle(
            binding: try binding(keyAgreementReference, byte: 0x51),
            privateKey: nil
        )
        let keyAgreementHandle = SecureEnclaveCustodyLoadedHandle(
            binding: try binding(keyAgreementReference, byte: 0x52),
            privateKey: nil
        )
        keyStore.insert(wrongSigningHandle, for: signingReference)
        keyStore.insert(keyAgreementHandle)

        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(
            identity: identity,
            signingPublicKeyX963: wrongSigningHandle.binding.publicKeyX963,
            keyAgreementPublicKeyX963: keyAgreementHandle.binding.publicKeyX963
        )
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.privateOperationRoleMismatch)
        )
    }

    func test_wrongPublicBindingMapsToBindingMismatch() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-wrong-binding" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(
            identity: identity,
            signingPublicKeyX963: makePublicKey(byte: 0x61),
            keyAgreementPublicKeyX963: pair.keyAgreement.publicKeyX963
        )
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.handlePublicKeyBindingMismatch)
        )
    }

    func test_authenticationHandleFailuresMapToStableCategories() async throws {
        let failureCases: [(SecureEnclaveCustodyHandleError, PGPKeyOperationFailureCategory)] = [
            (.localAuthenticationCancelled(.signing), .localAuthenticationCancelled),
            (.localAuthenticationFailed(.signing), .localAuthenticationFailed)
        ]

        for (index, failureCase) in failureCases.enumerated() {
            let (loadError, expectedCategory) = failureCase
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            let setupStore = SecureEnclaveCustodyHandleStore(
                keyStore: keyStore,
                handleSetIdentifierGenerator: { "router-auth-\(index)" }
            )
            let pair = try setupStore.createHandlePair()
            keyStore.failLoadError = loadError

            let identity = makeSecureEnclaveIdentity()
            let inspector = RecordingPublicBindingInspector()
            inspector.inspection = makeInspection(identity: identity, pair: pair)
            let router = try makeRouter(
                identities: [identity],
                policy: .testSecureEnclaveSigningRoutes,
                inspector: inspector,
                keyStore: keyStore
            )

            assertBlocked(
                await router.route(for: PrivateKeyOperationRequest(
                    fingerprint: identity.fingerprint,
                    operation: .sign
                )),
                .unavailable(expectedCategory)
            )
        }
    }

    func test_secureEnclaveSignerRouteAuthenticatesOnceAndThreadsContextIntoHandleLoad() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-p7f-signer" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let stub = StubCustodyOperationAuthenticator()
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore,
            custodyOperationAuthenticator: stub.authenticate
        )
        keyStore.resetCallHistory()

        let route = await router.route(for: PrivateKeyOperationRequest(
            fingerprint: identity.fingerprint,
            operation: .sign
        ))

        guard case .secureEnclaveSigner(let signerRoute) = route else {
            return XCTFail("Expected Secure Enclave signer route")
        }
        XCTAssertEqual(stub.calls, 1)
        XCTAssertFalse(stub.reasons[0].isEmpty)
        XCTAssertTrue(signerRoute.operationAuthorization?.authenticationContext === stub.context)
        let contextBearingLoads = keyStore.loadRequests.filter { $0.authenticationContext != nil }
        XCTAssertEqual(contextBearingLoads.count, 1)
        XCTAssertEqual(contextBearingLoads.first?.reference.role, .signing)
        XCTAssertTrue(contextBearingLoads.first?.authenticationContext === stub.context)
        XCTAssertEqual(stub.context.invalidateCount, 0)
        route.endAuthorizedOperation()
        XCTAssertEqual(stub.context.invalidateCount, 1)
    }

    func test_secureEnclaveKeyAgreementRouteAuthenticatesOnceAndThreadsContextIntoHandleLoad() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-p7f-agreement" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let stub = StubCustodyOperationAuthenticator()
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveKeyAgreementRoutes,
            inspector: inspector,
            keyStore: keyStore,
            custodyOperationAuthenticator: stub.authenticate
        )
        keyStore.resetCallHistory()

        let route = await router.route(for: PrivateKeyOperationRequest(
            fingerprint: identity.fingerprint,
            operation: .decrypt
        ))

        guard case .secureEnclaveKeyAgreement(let keyAgreementRoute) = route else {
            return XCTFail("Expected Secure Enclave key-agreement route")
        }
        XCTAssertEqual(stub.calls, 1)
        XCTAssertTrue(keyAgreementRoute.operationAuthorization?.authenticationContext === stub.context)
        let contextBearingLoads = keyStore.loadRequests.filter { $0.authenticationContext != nil }
        XCTAssertEqual(contextBearingLoads.count, 1)
        XCTAssertEqual(contextBearingLoads.first?.reference.role, .keyAgreement)
        XCTAssertTrue(contextBearingLoads.first?.authenticationContext === stub.context)
        route.endAuthorizedOperation()
        XCTAssertEqual(stub.context.invalidateCount, 1)
    }

    func test_cancelledCustodyAuthenticationBlocksWithoutContextBearingLoad() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-p7f-cancel" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let stub = StubCustodyOperationAuthenticator()
        stub.errorToThrow = CypherAirError.operationCancelled
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore,
            custodyOperationAuthenticator: stub.authenticate
        )
        keyStore.resetCallHistory()

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.localAuthenticationCancelled)
        )
        XCTAssertEqual(stub.calls, 1)
        XCTAssertTrue(keyStore.loadRequests.allSatisfy { $0.authenticationContext == nil })
    }

    func test_failedCustodyAuthenticationBlocksAsLocalAuthenticationFailed() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-p7f-fail" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let stub = StubCustodyOperationAuthenticator()
        stub.errorToThrow = CypherAirError.authenticationFailed
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore,
            custodyOperationAuthenticator: stub.authenticate
        )
        keyStore.resetCallHistory()

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.localAuthenticationFailed)
        )
        XCTAssertTrue(keyStore.loadRequests.allSatisfy { $0.authenticationContext == nil })
    }

    func test_biometryLockoutCustodyAuthenticationBlocksAsLocalAuthenticationLockedOut() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-p7f-lockout" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let stub = StubCustodyOperationAuthenticator()
        stub.errorToThrow = LAError(.biometryLockout)
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore,
            custodyOperationAuthenticator: stub.authenticate
        )
        keyStore.resetCallHistory()

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.localAuthenticationLockedOut)
        )
        XCTAssertEqual(stub.calls, 1)
        XCTAssertTrue(keyStore.loadRequests.allSatisfy { $0.authenticationContext == nil })
    }

    func test_nilCustodyAuthenticatorKeepsContextFreeLoadsAndNilAuthorization() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-p7f-nil" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore
        )
        keyStore.resetCallHistory()

        let route = await router.route(for: PrivateKeyOperationRequest(
            fingerprint: identity.fingerprint,
            operation: .sign
        ))

        guard case .secureEnclaveSigner(let signerRoute) = route else {
            return XCTFail("Expected Secure Enclave signer route")
        }
        XCTAssertNil(signerRoute.operationAuthorization)
        XCTAssertFalse(keyStore.loadRequests.isEmpty)
        XCTAssertTrue(keyStore.loadRequests.allSatisfy { $0.authenticationContext == nil })
    }

    func test_softwareAndBlockedRoutesNeverInvokeCustodyAuthenticator() async throws {
        let stub = StubCustodyOperationAuthenticator()
        let softwareIdentity = makeSoftwareIdentity()
        let softwareRouter = try makeRouter(
            identities: [softwareIdentity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: RecordingPublicBindingInspector(),
            keyStore: MockSecureEnclaveCustodyKeyStore(),
            custodyOperationAuthenticator: stub.authenticate
        )
        guard case .softwareSecretCertificate = await softwareRouter.route(for: PrivateKeyOperationRequest(
            fingerprint: softwareIdentity.fingerprint,
            operation: .sign
        )) else {
            return XCTFail("Expected software custody route")
        }

        let secureEnclaveIdentity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(
            identity: secureEnclaveIdentity,
            signingPublicKeyX963: makePublicKey(byte: 0x91),
            keyAgreementPublicKeyX963: makePublicKey(byte: 0x92)
        )
        let blockedRouter = try makeRouter(
            identities: [secureEnclaveIdentity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: MockSecureEnclaveCustodyKeyStore(),
            custodyOperationAuthenticator: stub.authenticate
        )
        assertBlocked(
            await blockedRouter.route(for: PrivateKeyOperationRequest(
                fingerprint: secureEnclaveIdentity.fingerprint,
                operation: .sign
            )),
            .unavailable(.privateHandleMissing)
        )

        XCTAssertEqual(stub.calls, 0)
    }

    func test_postAuthenticationLoadFailureBlocksAndEndsNeverReturnedAuthorization() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-p7f-loadfail" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let stub = StubCustodyOperationAuthenticator()
        stub.failLoadAfterAuthentication = { keyStore.failLoadError = .privateHandleInaccessible(.signing) }
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: keyStore,
            custodyOperationAuthenticator: stub.authenticate
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.privateHandleInaccessible)
        )
        XCTAssertEqual(stub.calls, 1)
        XCTAssertEqual(
            stub.context.invalidateCount,
            1,
            "The router ends a never-returned authorization itself."
        )
    }

    #if os(macOS)
    @MainActor
    func test_secureEnclaveSignerAuthorizationWindowRunsInsideOperationPromptSession() async throws {
        try await assertCustodyAuthorizationWindowRunsInsideOperationPromptSession(
            policy: .testSecureEnclaveSigningRoutes,
            operation: .sign,
            expectedRole: .signing
        )
    }

    @MainActor
    func test_secureEnclaveKeyAgreementAuthorizationWindowRunsInsideOperationPromptSession() async throws {
        try await assertCustodyAuthorizationWindowRunsInsideOperationPromptSession(
            policy: .testSecureEnclaveKeyAgreementRoutes,
            operation: .decrypt,
            expectedRole: .keyAgreement
        )
    }

    @MainActor
    func test_missingHandleWithPromptCoordinatorBlocksBeforeCustodyAuthentication() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(
            identity: identity,
            signingPublicKeyX963: makePublicKey(byte: 0xA1),
            keyAgreementPublicKeyX963: makePublicKey(byte: 0xA2)
        )
        let stub = StubCustodyOperationAuthenticator()
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: MockSecureEnclaveCustodyKeyStore(),
            custodyOperationAuthenticator: stub.authenticate,
            authenticationPromptCoordinator: harness.coordinator
        )

        assertBlocked(
            await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.privateHandleMissing)
        )
        XCTAssertEqual(stub.calls, 0)
        XCTAssertFalse(harness.coordinator.isOperationPromptInProgress)
    }

    @MainActor
    private func assertCustodyAuthorizationWindowRunsInsideOperationPromptSession(
        policy: PGPKeyCapabilityResolver.Policy,
        operation: PGPPrivateOperationKind,
        expectedRole: PGPPrivateOperationRole
    ) async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let setupStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "router-composition" }
        )
        let pair = try setupStore.createHandlePair()
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        inspector.inspection = makeInspection(identity: identity, pair: pair)
        let loadObservation = LockedBool()
        keyStore.onLoadKeys = {
            loadObservation.set(harness.coordinator.isOperationPromptInProgress)
        }
        let gate = GatedRouterCustodyAuthenticator(coordinator: harness.coordinator)
        let router = try makeRouter(
            identities: [identity],
            policy: policy,
            inspector: inspector,
            keyStore: keyStore,
            custodyOperationAuthenticator: gate.authenticate,
            authenticationPromptCoordinator: harness.coordinator
        )
        keyStore.resetCallHistory()

        var routed: PrivateKeyOperationRoute?
        let routeFinished = expectation(description: "router route finished")
        Task { @MainActor in
            routed = await router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: operation
            ))
            routeFinished.fulfill()
        }
        await fulfillment(of: [gate.suspendedExpectation], timeout: 10)
        await harness.settle()

        XCTAssertEqual(gate.wasInOperationPromptSession, true)
        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(harness.lockState, .unlocked)
        XCTAssertEqual(harness.relockCount, relocksBefore)

        gate.resume()
        await fulfillment(of: [routeFinished], timeout: 10)
        guard let route = routed else {
            return XCTFail("Expected route result")
        }
        switch (expectedRole, route) {
        case (.signing, .secureEnclaveSigner(let signerRoute)):
            XCTAssertEqual(signerRoute.signingHandle.binding, pair.signing)
        case (.keyAgreement, .secureEnclaveKeyAgreement(let keyAgreementRoute)):
            XCTAssertEqual(keyAgreementRoute.keyAgreementHandle.binding, pair.keyAgreement)
        default:
            XCTFail("Expected Secure Enclave \(expectedRole) route")
        }
        XCTAssertTrue(loadObservation.value, "The authorized handle load must stay inside the prompt session.")

        await harness.settle()
        XCTAssertEqual(harness.lockState, .locked)
        XCTAssertGreaterThan(harness.relockCount, relocksBefore)
        route.endAuthorizedOperation()
    }
    #endif

    private func makeRouter(
        identities: [PGPKeyIdentity],
        policy: PGPKeyCapabilityResolver.Policy,
        inspector: RecordingPublicBindingInspector,
        keyStore: MockSecureEnclaveCustodyKeyStore,
        custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator? = nil,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator? = nil
    ) throws -> PrivateKeyOperationRouter {
        let metadata = RouterMemoryKeyMetadataPersistence()
        metadata.seed(identities)
        let catalogStore = KeyCatalogStore(metadataStore: metadata)
        try catalogStore.loadAll()
        return PrivateKeyOperationRouter(
            catalogStore: catalogStore,
            resolver: PGPKeyCapabilityResolver(policy: policy),
            publicBindingInspector: inspector,
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore),
            custodyOperationAuthenticator: custodyOperationAuthenticator,
            authenticationPromptCoordinator: authenticationPromptCoordinator
        )
    }

    private func makeSoftwareIdentity() -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: "1111111111111111111111111111111111111111",
            keyVersion: 4,
            profile: .universal,
            userId: "Software <software@example.invalid>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data([0x11]),
            revocationCert: Data([0x12]),
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519",
            expiryDate: nil,
            openPGPConfigurationIdentity: .compatibleSoftwareV4,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
    }

    private func makeSecureEnclaveIdentity() -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: "2222222222222222222222222222222222222222",
            keyVersion: 4,
            profile: .universal,
            userId: "Secure Enclave <secure@example.invalid>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data([0x21]),
            revocationCert: Data([0x22]),
            primaryAlgo: "ECDSA P-256",
            subkeyAlgo: "ECDH P-256",
            expiryDate: nil,
            openPGPConfigurationIdentity: .compatibleP256V4,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
    }

    private func makeInspection(
        identity: PGPKeyIdentity,
        pair: SecureEnclaveCustodyHandlePair,
        fingerprint: String? = nil
    ) -> PGPSecureEnclaveCustodyPublicBindingInspection {
        makeInspection(
            identity: identity,
            fingerprint: fingerprint,
            signingPublicKeyX963: pair.signing.publicKeyX963,
            keyAgreementPublicKeyX963: pair.keyAgreement.publicKeyX963
        )
    }

    private func makeInspection(
        identity: PGPKeyIdentity,
        fingerprint: String? = nil,
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data
    ) -> PGPSecureEnclaveCustodyPublicBindingInspection {
        PGPSecureEnclaveCustodyPublicBindingInspection(
            fingerprint: fingerprint ?? identity.fingerprint,
            keyVersion: identity.keyVersion,
            signingKeyFingerprint: "signing-subkey",
            keyAgreementSubkeyFingerprint: "agreement-subkey",
            signingPublicKeyX963: signingPublicKeyX963,
            keyAgreementPublicKeyX963: keyAgreementPublicKeyX963
        )
    }

    private func assertBlocked(
        _ route: PrivateKeyOperationRoute,
        _ expectedResolution: PGPKeyOperationResolution,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .blocked(let resolution) = route else {
            return XCTFail("Expected blocked route", file: file, line: line)
        }
        XCTAssertEqual(resolution, expectedResolution, file: file, line: line)
    }

    private func reference(
        _ handleSetIdentifier: String,
        _ role: PGPPrivateOperationRole
    ) throws -> SecureEnclaveCustodyHandleReference {
        try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: role
        )
    }

    private func binding(
        _ reference: SecureEnclaveCustodyHandleReference,
        byte: UInt8
    ) throws -> SecureEnclaveCustodyHandlePublicBinding {
        try SecureEnclaveCustodyHandlePublicBinding(
            reference: reference,
            publicKeyX963: makePublicKey(byte: byte)
        )
    }

    private func makePublicKey(byte: UInt8) -> Data {
        var data = Data([0x04])
        data.append(Data(repeating: byte, count: 64))
        return data
    }
}

private final class StubCustodyOperationAuthenticator: @unchecked Sendable {
    private(set) var calls = 0
    private(set) var reasons: [String] = []
    var errorToThrow: Error?
    var failLoadAfterAuthentication: (() -> Void)?
    let context = RecordingLAContext()

    func authenticate(_ reason: String) async throws -> LAContext {
        calls += 1
        reasons.append(reason)
        if let errorToThrow {
            throw errorToThrow
        }
        failLoadAfterAuthentication?()
        return context
    }
}

#if os(macOS)
private final class GatedRouterCustodyAuthenticator: @unchecked Sendable {
    private let coordinator: AuthenticationPromptCoordinator
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    private var observedInSession: Bool?
    let context = RecordingLAContext()
    let suspendedExpectation = XCTestExpectation(description: "router custody authorization suspended")

    init(coordinator: AuthenticationPromptCoordinator) {
        self.coordinator = coordinator
    }

    var wasInOperationPromptSession: Bool? {
        lock.withLock { observedInSession }
    }

    func authenticate(_ reason: String) async throws -> LAContext {
        lock.withLock {
            observedInSession = coordinator.isOperationPromptInProgress
        }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            lock.withLock { continuation = cont }
            suspendedExpectation.fulfill()
        }
        return context
    }

    func resume() {
        let cont = lock.withLock {
            let value = continuation
            continuation = nil
            return value
        }
        cont?.resume()
    }
}

private final class LockedBool: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = false

    var value: Bool {
        lock.withLock { storage }
    }

    func set(_ value: Bool) {
        lock.withLock { storage = value }
    }
}
#endif

private final class RecordingPublicBindingInspector: SecureEnclaveCustodyPublicBindingInspecting, @unchecked Sendable {
    var inspection: PGPSecureEnclaveCustodyPublicBindingInspection?
    var error: Error?
    private(set) var inspectCallCount = 0

    func inspectPublicBindings(
        publicKeyData: Data
    ) throws -> PGPSecureEnclaveCustodyPublicBindingInspection {
        inspectCallCount += 1
        if let error {
            throw error
        }
        guard let inspection else {
            throw CypherAirError.invalidKeyData(reason: "Missing test inspection")
        }
        return inspection
    }
}

private final class RouterMemoryKeyMetadataPersistence: KeyMetadataPersistence {
    private var identities: [PGPKeyIdentity] = []

    func seed(_ identities: [PGPKeyIdentity]) {
        self.identities = identities
    }

    func loadAll() throws -> [PGPKeyIdentity] {
        identities
    }

    func save(_ identity: PGPKeyIdentity) throws {
        identities.append(identity)
    }

    func update(_ identity: PGPKeyIdentity) throws {
        if let index = identities.firstIndex(where: { $0.fingerprint == identity.fingerprint }) {
            identities[index] = identity
        } else {
            identities.append(identity)
        }
    }

    func delete(fingerprint: String) throws {
        identities.removeAll { $0.fingerprint == fingerprint }
    }
}
