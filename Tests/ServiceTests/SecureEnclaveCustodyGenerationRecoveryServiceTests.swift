import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

final class SecureEnclaveCustodyGenerationRecoveryServiceTests: XCTestCase {
    // Device-Bound Post-Quantum (composite split custody) shares the
    // `.appleSecureEnclavePrivateOperations` custody kind with P-256 but carries
    // an ML-DSA/ML-KEM suite. Before the composite-aware recovery branch, every
    // healthy composite key was misclassified `.invalidConfigurationCustody`
    // (audit #661 C5). These two tests lock the correct routing.
    fileprivate static let compositeSigningPublicKey = Data(repeating: 0xA1, count: 1952)
    fileprivate static let compositeKeyAgreementPublicKey = Data(repeating: 0xB2, count: 1184)
    // PQ-High tier component lengths (ML-DSA-87 / ML-KEM-1024).
    fileprivate static let compositeHighSigningPublicKey = Data(repeating: 0xC3, count: 2592)
    fileprivate static let compositeHighKeyAgreementPublicKey = Data(repeating: 0xD4, count: 1568)

    func test_recoveryReportMarksHealthyDeviceBoundPostQuantumIdentityAvailable() throws {
        let keyStore = InMemoryCompositeKeyStore()
        try keyStore.seed(handleSetIdentifier: "abcdef01")
        let identity = Self.identity(
            fingerprint: "device-bound-pq",
            keyVersion: 6,
            family: .deviceBoundMlDsa65Ed25519MlKem768X25519,
            publicKeyData: Data("device-bound-pq-cert".utf8),
            revocationCert: Data("device-bound-pq-revocation".utf8)
        )
        let service = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: MockSecureEnclaveCustodyPublicBindingInspector(
                error: CypherAirError.invalidKeyData(reason: "p256 inspector must not be called")
            ),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256),
            compositeBindingInspector: MockSecureEnclaveCompositeBindingInspector(
                inspection: Self.compositeInspection(identity: identity)
            ),
            compositeHandleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .postQuantum)
        )

        let report = service.classify(identities: [identity])

        XCTAssertEqual(report.assessments.count, 1)
        XCTAssertEqual(report.assessments[0].publicMaterialAvailability, .available)
        XCTAssertEqual(report.assessments[0].revocationArtifactAvailability, .available)
        XCTAssertEqual(report.assessments[0].handleAvailability, .available)
    }

    func test_recoveryReportMarksHealthyDeviceBoundPostQuantumHighIdentityAvailable() throws {
        // Locks the PQ-High tier arm so a future swap of the tier→store switch
        // cannot silently recur C5 on the High tier: the base-tier store would
        // shape-reject 2592/1568-byte components and mis-grade the key.
        let keyStore = InMemoryCompositeKeyStore(tier: .postQuantumHigh)
        try keyStore.seed(
            handleSetIdentifier: "beef1234",
            signing: Self.compositeHighSigningPublicKey,
            keyAgreement: Self.compositeHighKeyAgreementPublicKey
        )
        let identity = Self.identity(
            fingerprint: "device-bound-pq-high",
            keyVersion: 6,
            family: .deviceBoundMlDsa87Ed448MlKem1024X448,
            publicKeyData: Data("device-bound-pq-high-cert".utf8),
            revocationCert: Data("device-bound-pq-high-revocation".utf8)
        )
        let service = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: MockSecureEnclaveCustodyPublicBindingInspector(
                error: CypherAirError.invalidKeyData(reason: "p256 inspector must not be called")
            ),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256),
            compositeBindingInspector: MockSecureEnclaveCompositeBindingInspector(
                inspection: Self.compositeInspection(
                    identity: identity,
                    signingComponentPublicKey: Self.compositeHighSigningPublicKey,
                    keyAgreementComponentPublicKey: Self.compositeHighKeyAgreementPublicKey
                )
            ),
            compositeHighHandleStore: SecureEnclaveCustodyHandleStore(
                keyStore: keyStore,
                tier: .postQuantumHigh
            )
        )

        let report = service.classify(identities: [identity])

        XCTAssertEqual(report.assessments[0].publicMaterialAvailability, .available)
        XCTAssertEqual(report.assessments[0].handleAvailability, .available)
    }

    func test_recoveryReportClassifiesDeviceBoundPostQuantumWithMissingHandlesAsMissing() throws {
        let identity = Self.identity(
            fingerprint: "device-bound-pq-orphan",
            keyVersion: 6,
            family: .deviceBoundMlDsa65Ed25519MlKem768X25519,
            publicKeyData: Data("device-bound-pq-orphan-cert".utf8),
            revocationCert: Data("device-bound-pq-orphan-revocation".utf8)
        )
        let service = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: MockSecureEnclaveCustodyPublicBindingInspector(
                error: CypherAirError.invalidKeyData(reason: "p256 inspector must not be called")
            ),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256),
            compositeBindingInspector: MockSecureEnclaveCompositeBindingInspector(
                inspection: Self.compositeInspection(identity: identity)
            ),
            compositeHandleStore: SecureEnclaveCustodyHandleStore(keyStore: InMemoryCompositeKeyStore(), tier: .postQuantum)
        )

        let report = service.classify(identities: [identity])

        // The key material is valid and associated; only the enclave handles are
        // gone — a precise "missing handles" state, never the false invalid-custody.
        XCTAssertEqual(report.assessments[0].publicMaterialAvailability, .available)
        XCTAssertEqual(report.assessments[0].handleAvailability, .unavailable(.privateHandleMissing))
    }

    func test_recoveryReportMarksCompleteMetadataAndHandlesAvailable() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let handleStore = makeHandleStore(keyStore: keyStore, handleSetIdentifier: "a1a11ab1e0")
        let pairLoaded = try handleStore.createLoadedHandlePair(authenticationContext: nil)
        let pair = try SecureEnclaveCustodyHandlePair(
            signing: pairLoaded.signing.binding,
            keyAgreement: pairLoaded.keyAgreement.binding
        )
        let identity = Self.identity(
            fingerprint: "available",
            publicKeyData: Data("available-cert".utf8),
            revocationCert: Data("available-revocation".utf8)
        )
        let inspector = MockSecureEnclaveCustodyPublicBindingInspector(
            inspection: Self.inspection(
                identity: identity,
                signingPublicKeyX963: pair.signing.publicKeyRaw,
                keyAgreementPublicKeyX963: pair.keyAgreement.publicKeyRaw
            )
        )
        let service = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: inspector,
            handleStore: handleStore
        )

        let report = service.classify(identities: [identity])

        XCTAssertNil(report.inventoryFailureCategory)
        XCTAssertEqual(report.inventorySummary.completeSetCount, 1)
        XCTAssertEqual(report.assessments.count, 1)
        XCTAssertEqual(report.assessments[0].publicMaterialAvailability, .available)
        XCTAssertEqual(report.assessments[0].revocationArtifactAvailability, .available)
        XCTAssertEqual(report.assessments[0].handleAvailability, .available)
    }

    func test_recoveryReportClassifiesMetadataOnlyIdentityAsMissingHandles() throws {
        let identity = Self.identity(
            fingerprint: "metadata-only",
            publicKeyData: Data("metadata-only-cert".utf8),
            revocationCert: Data("metadata-only-revocation".utf8)
        )
        let inspector = MockSecureEnclaveCustodyPublicBindingInspector(
            inspection: Self.inspection(identity: identity)
        )
        let service = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: inspector,
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256)
        )

        let report = service.classify(identities: [identity])

        XCTAssertEqual(report.assessments[0].publicMaterialAvailability, .available)
        XCTAssertEqual(report.assessments[0].revocationArtifactAvailability, .available)
        XCTAssertEqual(report.assessments[0].handleAvailability, .unavailable(.privateHandleMissing))
    }

    func test_recoveryReportClassifiesPartialAmbiguousAndWrongPublicHandles() throws {
        let identity = Self.identity(
            fingerprint: "disagreement",
            publicKeyData: Data("disagreement-cert".utf8),
            revocationCert: Data("disagreement-revocation".utf8)
        )

        let partialKeyStore = MockSecureEnclaveCustodyKeyStore()
        let partialReference = try Self.reference("9a57fa10", .signing)
        let partialSigning = try Self.binding(partialReference, byte: 0x31)
        partialKeyStore.insert(
            SecureEnclaveCustodyLoadedHandle(binding: partialSigning, privateKey: nil)
        )
        var partialReport = makeService(
            keyStore: partialKeyStore,
            inspection: Self.inspection(
                identity: identity,
                signingPublicKeyX963: partialSigning.publicKeyRaw,
                keyAgreementPublicKeyX963: Self.publicKey(byte: 0x32)
            )
        )
        .classify(identities: [identity])
        XCTAssertEqual(
            partialReport.assessments[0].handleAvailability,
            .unavailable(.recoveryRequired)
        )

        let wrongPublicKeyStore = MockSecureEnclaveCustodyKeyStore()
        let wrongPublicStore = makeHandleStore(keyStore: wrongPublicKeyStore, handleSetIdentifier: "b0b2c0de99")
        let wrongPublicPairLoaded = try wrongPublicStore.createLoadedHandlePair(authenticationContext: nil)
        let wrongPublicPair = try SecureEnclaveCustodyHandlePair(
            signing: wrongPublicPairLoaded.signing.binding,
            keyAgreement: wrongPublicPairLoaded.keyAgreement.binding
        )
        let wrongPublicReport = makeService(
            keyStore: wrongPublicKeyStore,
            inspection: Self.inspection(
                identity: identity,
                signingPublicKeyX963: wrongPublicPair.signing.publicKeyRaw,
                keyAgreementPublicKeyX963: Self.publicKey(byte: 0x34)
            )
        )
        .classify(identities: [identity])
        XCTAssertEqual(
            wrongPublicReport.assessments[0].handleAvailability,
            .unavailable(.handlePublicKeyBindingMismatch)
        )
    }

    func test_recoveryReportClassifiesPublicCertificateAndMetadataMismatch() throws {
        let identity = Self.identity(
            fingerprint: "expected",
            publicKeyData: Data("expected-cert".utf8),
            revocationCert: Data("expected-revocation".utf8)
        )
        let mismatchedInspector = MockSecureEnclaveCustodyPublicBindingInspector(
            inspection: Self.inspection(
                identity: Self.identity(fingerprint: "other"),
                signingPublicKeyX963: Self.publicKey(byte: 0x41),
                keyAgreementPublicKeyX963: Self.publicKey(byte: 0x42)
            )
        )
        let metadataMismatchReport = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: mismatchedInspector,
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256)
        )
        .classify(identities: [identity])
        XCTAssertEqual(
            metadataMismatchReport.assessments[0].publicMaterialAvailability,
            .unavailable(.metadataAssociationMismatch)
        )
        XCTAssertEqual(
            metadataMismatchReport.assessments[0].handleAvailability,
            .unavailable(.metadataAssociationMismatch)
        )

        let corruptInspector = MockSecureEnclaveCustodyPublicBindingInspector(
            error: CypherAirError.invalidKeyData(reason: "corrupt")
        )
        let corruptReport = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: corruptInspector,
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore(), tier: .classicalP256)
        )
        .classify(identities: [identity])
        XCTAssertEqual(
            corruptReport.assessments[0].publicMaterialAvailability,
            .unavailable(.publicCertificateAssociationMismatch)
        )
        XCTAssertEqual(
            corruptReport.assessments[0].handleAvailability,
            .unavailable(.publicCertificateAssociationMismatch)
        )
    }

    func test_recoveryReportClassifiesMissingRevocationAndInventoryFailure() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        let identity = Self.identity(
            fingerprint: "inventory-failure",
            publicKeyData: Data("inventory-failure-cert".utf8),
            revocationCert: Data()
        )
        let service = makeService(
            keyStore: keyStore,
            inspection: Self.inspection(identity: identity)
        )

        let report = service.classify(identities: [identity])

        XCTAssertEqual(report.inventoryFailureCategory, .privateHandleInaccessible)
        XCTAssertEqual(
            report.assessments[0].revocationArtifactAvailability,
            .unavailable(.revocationArtifactUnavailable)
        )
        XCTAssertEqual(
            report.assessments[0].handleAvailability,
            .unavailable(.privateHandleInaccessible)
        )
    }

    private func makeService(
        keyStore: MockSecureEnclaveCustodyKeyStore,
        inspection: PGPSecureEnclaveCustodyPublicBindingInspection
    ) -> SecureEnclaveCustodyGenerationRecoveryService {
        SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: MockSecureEnclaveCustodyPublicBindingInspector(
                inspection: inspection
            ),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        )
    }

    private func makeHandleStore(
        keyStore: MockSecureEnclaveCustodyKeyStore,
        handleSetIdentifier: String
    ) -> SecureEnclaveCustodyHandleStore {
        SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            tier: .classicalP256,
            handleSetIdentifierGenerator: { handleSetIdentifier }
        )
    }

    private static func identity(
        fingerprint: String,
        keyVersion: UInt8 = 4,
        family: PGPKeyFamily = .deviceBoundEcdsaNistP256EcdhNistP256V4,
        publicKeyData: Data = Data("public".utf8),
        revocationCert: Data = Data("revocation".utf8)
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            userId: "Secure Enclave <se@example.test>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: true,
            isBackedUp: false,
            publicKeyData: publicKeyData,
            revocationCert: revocationCert,
            primaryAlgo: "ECDSA P-256",
            subkeyAlgo: "ECDH P-256",
            expiryDate: nil,
            keyFamily: family,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
    }

    private static func inspection(
        identity: PGPKeyIdentity,
        signingPublicKeyX963: Data = publicKey(byte: 0x21),
        keyAgreementPublicKeyX963: Data = publicKey(byte: 0x22)
    ) -> PGPSecureEnclaveCustodyPublicBindingInspection {
        PGPSecureEnclaveCustodyPublicBindingInspection(
            fingerprint: identity.fingerprint,
            keyVersion: identity.keyVersion,
            signingKeyFingerprint: "\(identity.fingerprint)-signing",
            keyAgreementSubkeyFingerprint: "\(identity.fingerprint)-agreement",
            signingPublicKeyX963: signingPublicKeyX963,
            keyAgreementPublicKeyX963: keyAgreementPublicKeyX963
        )
    }

    private static func reference(
        _ handleSetIdentifier: String,
        _ role: PGPPrivateOperationRole
    ) throws -> SecureEnclaveCustodyHandleReference {
        try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: role,
            tier: .classicalP256
        )
    }

    private static func binding(
        _ reference: SecureEnclaveCustodyHandleReference,
        byte: UInt8
    ) throws -> SecureEnclaveCustodyHandlePublicBinding {
        try SecureEnclaveCustodyHandlePublicBinding(
            reference: reference,
            publicKeyRaw: publicKey(byte: byte)
        )
    }

    private static func publicKey(byte: UInt8) -> Data {
        var data = Data([0x04])
        data.append(Data(repeating: byte, count: 64))
        return data
    }

    private static func compositeInspection(
        identity: PGPKeyIdentity,
        signingComponentPublicKey: Data = compositeSigningPublicKey,
        keyAgreementComponentPublicKey: Data = compositeKeyAgreementPublicKey
    ) -> PGPSecureEnclaveCompositeBindingInspection {
        PGPSecureEnclaveCompositeBindingInspection(
            fingerprint: identity.fingerprint,
            keyVersion: identity.keyVersion,
            signingKeyFingerprint: "\(identity.fingerprint)-signing",
            keyAgreementSubkeyFingerprint: "\(identity.fingerprint)-agreement",
            signingComponentPublicKey: signingComponentPublicKey,
            keyAgreementComponentPublicKey: keyAgreementComponentPublicKey
        )
    }
}

private final class MockSecureEnclaveCompositeBindingInspector: SecureEnclaveCompositeBindingInspecting, @unchecked Sendable {
    private let inspection: PGPSecureEnclaveCompositeBindingInspection?
    private let error: Error?

    init(
        inspection: PGPSecureEnclaveCompositeBindingInspection? = nil,
        error: Error? = nil
    ) {
        self.inspection = inspection
        self.error = error
    }

    func inspectCompositeBindings(
        publicKeyData: Data,
        tier: SecureEnclaveCustodyTier
    ) throws -> PGPSecureEnclaveCompositeBindingInspection {
        if let error {
            throw error
        }
        return try XCTUnwrap(inspection)
    }
}

/// Minimal in-memory `SecureEnclaveCustodyKeyStoring` for the `.postQuantum`
/// tier: only `inventoryBindings()` is exercised by handle location.
private final class InMemoryCompositeKeyStore: SecureEnclaveCustodyKeyStoring, @unchecked Sendable {
    private let tier: SecureEnclaveCustodyTier
    private var rows: [String: Data] = [:]

    init(tier: SecureEnclaveCustodyTier = .postQuantum) {
        self.tier = tier
    }

    private func key(_ reference: SecureEnclaveCustodyHandleReference) -> String {
        "\(reference.handleSetIdentifier).\(reference.role.rawValue)"
    }

    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        throw SecureEnclaveCustodyHandleError.hardwareUnavailable
    }

    func loadKey(
        reference: SecureEnclaveCustodyHandleReference,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle? {
        nil
    }

    func inventory() throws -> SecureEnclaveCustodyHandleInventory {
        let bindings = try rows.compactMap { entry -> SecureEnclaveCustodyHandlePublicBinding? in
            let parts = entry.key.split(separator: ".")
            guard parts.count == 2,
                  let role = PGPPrivateOperationRole(rawValue: String(parts[1])) else {
                return nil
            }
            let reference = try SecureEnclaveCustodyHandleReference(
                handleSetIdentifier: String(parts[0]),
                role: role,
                tier: tier
            )
            return try SecureEnclaveCustodyHandlePublicBinding(
                reference: reference,
                publicKeyRaw: entry.value
            )
        }
        return SecureEnclaveCustodyHandleInventory(bindings: bindings, malformedRowCount: 0)
    }

    func deleteAllKeys(tier: SecureEnclaveCustodyTier, role: PGPPrivateOperationRole) throws {
        guard tier == self.tier else {
            return
        }
        rows = rows.filter { !$0.key.hasSuffix(".\(role.rawValue)") }
    }

    func deleteKey(reference: SecureEnclaveCustodyHandleReference) throws {
        guard rows.removeValue(forKey: key(reference)) != nil else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(reference.role)
        }
    }

    func seed(
        handleSetIdentifier: String,
        signing: Data = SecureEnclaveCustodyGenerationRecoveryServiceTests.compositeSigningPublicKey,
        keyAgreement: Data = SecureEnclaveCustodyGenerationRecoveryServiceTests.compositeKeyAgreementPublicKey
    ) throws {
        let signingReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .signing,
            tier: tier
        )
        let keyAgreementReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .keyAgreement,
            tier: tier
        )
        rows[key(signingReference)] = signing
        rows[key(keyAgreementReference)] = keyAgreement
    }
}

private final class MockSecureEnclaveCustodyPublicBindingInspector: SecureEnclaveCustodyPublicBindingInspecting, @unchecked Sendable {
    private let inspection: PGPSecureEnclaveCustodyPublicBindingInspection?
    private let error: Error?

    init(
        inspection: PGPSecureEnclaveCustodyPublicBindingInspection? = nil,
        error: Error? = nil
    ) {
        self.inspection = inspection
        self.error = error
    }

    func inspectPublicBindings(
        publicKeyData: Data
    ) throws -> PGPSecureEnclaveCustodyPublicBindingInspection {
        if let error {
            throw error
        }
        return try XCTUnwrap(inspection)
    }
}
