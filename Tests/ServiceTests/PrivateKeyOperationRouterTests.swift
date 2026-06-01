import Foundation
import XCTest
@testable import CypherAir

final class PrivateKeyOperationRouterTests: XCTestCase {
    func test_softwareCustodyRoutesWithoutInspectingSecureEnclaveHandles() throws {
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

        let route = router.route(for: PrivateKeyOperationRequest(
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

    func test_productionPolicyBlocksSecureEnclavePrivateOperationBeforeHandleLookup() throws {
        let identity = makeSecureEnclaveIdentity()
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        let inspector = RecordingPublicBindingInspector()
        inspector.error = CypherAirError.invalidKeyData(reason: "Unexpected public binding inspection")
        let router = try makeRouter(
            identities: [identity],
            policy: .production,
            inspector: inspector,
            keyStore: keyStore
        )

        assertBlocked(
            router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.operationUnavailableByPolicy)
        )
        XCTAssertEqual(inspector.inspectCallCount, 0)
    }

    func test_signingPolicyRoutesSecureEnclaveSigningClassOperations() throws {
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
            .modifyExpiry,
            .refreshBinding
        ]
        for operation in signingOperations {
            let route = router.route(for: PrivateKeyOperationRequest(
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

    func test_decryptRemainsBlockedForPhase5ASigningRouter() throws {
        let identity = makeSecureEnclaveIdentity()
        let inspector = RecordingPublicBindingInspector()
        let router = try makeRouter(
            identities: [identity],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: inspector,
            keyStore: MockSecureEnclaveCustodyKeyStore()
        )

        assertBlocked(
            router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .decrypt
            )),
            .notImplemented(.operationNotImplementedForCustody)
        )
        XCTAssertEqual(inspector.inspectCallCount, 0)
    }

    func test_missingIdentityReturnsSanitizedBlockedRoute() throws {
        let router = try makeRouter(
            identities: [],
            policy: .testSecureEnclaveSigningRoutes,
            inspector: RecordingPublicBindingInspector(),
            keyStore: MockSecureEnclaveCustodyKeyStore()
        )

        assertBlocked(
            router.route(for: PrivateKeyOperationRequest(
                fingerprint: "missing",
                operation: .sign
            )),
            .unavailable(.metadataAssociationMismatch)
        )
    }

    func test_invalidConfigurationCustodyPairBlocksBeforeInspection() throws {
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
            router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unsupported(.invalidConfigurationCustody)
        )
        XCTAssertEqual(inspector.inspectCallCount, 0)
    }

    func test_publicCertificateInspectionFailureMapsToSanitizedCategory() throws {
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
            router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.publicCertificateAssociationMismatch)
        )
    }

    func test_publicCertificateFingerprintMismatchBlocksAsMetadataMismatch() throws {
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
            router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.metadataAssociationMismatch)
        )
    }

    func test_missingHandleBlocksWithoutSoftwareFallback() throws {
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
            router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.privateHandleMissing)
        )
    }

    func test_wrongHandleRoleMapsToRoleMismatch() throws {
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
            router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.privateOperationRoleMismatch)
        )
    }

    func test_wrongPublicBindingMapsToBindingMismatch() throws {
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
            router.route(for: PrivateKeyOperationRequest(
                fingerprint: identity.fingerprint,
                operation: .sign
            )),
            .unavailable(.handlePublicKeyBindingMismatch)
        )
    }

    func test_authenticationHandleFailuresMapToStableCategories() throws {
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
                router.route(for: PrivateKeyOperationRequest(
                    fingerprint: identity.fingerprint,
                    operation: .sign
                )),
                .unavailable(expectedCategory)
            )
        }
    }

    private func makeRouter(
        identities: [PGPKeyIdentity],
        policy: PGPKeyCapabilityResolver.Policy,
        inspector: RecordingPublicBindingInspector,
        keyStore: MockSecureEnclaveCustodyKeyStore
    ) throws -> PrivateKeyOperationRouter {
        let metadata = RouterMemoryKeyMetadataPersistence()
        metadata.seed(identities)
        let catalogStore = KeyCatalogStore(metadataStore: metadata)
        try catalogStore.loadAll()
        return PrivateKeyOperationRouter(
            catalogStore: catalogStore,
            resolver: PGPKeyCapabilityResolver(policy: policy),
            publicBindingInspector: inspector,
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore)
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
            expiryDate: nil
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
