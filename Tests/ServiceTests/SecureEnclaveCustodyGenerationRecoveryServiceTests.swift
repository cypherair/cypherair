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

    func test_recoveryReportMarksHealthyDeviceBoundPostQuantumIdentityAvailable() throws {
        let keyStore = InMemoryCompositeKeyStore()
        try keyStore.seed(handleSetIdentifier: "abcdef01")
        let identity = Self.identity(
            fingerprint: "device-bound-pq",
            keyVersion: 6,
            configurationIdentity: .deviceBoundPostQuantumV6,
            publicKeyData: Data("device-bound-pq-cert".utf8),
            revocationCert: Data("device-bound-pq-revocation".utf8)
        )
        let service = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: MockSecureEnclaveCustodyPublicBindingInspector(
                error: CypherAirError.invalidKeyData(reason: "p256 inspector must not be called")
            ),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore()),
            compositeBindingInspector: MockSecureEnclaveCompositeBindingInspector(
                inspection: Self.compositeInspection(identity: identity)
            ),
            compositeHandleStore: SecureEnclaveCompositeHandleStore(keyStore: keyStore)
        )

        let report = service.classify(identities: [identity])

        XCTAssertEqual(report.assessments.count, 1)
        XCTAssertEqual(report.assessments[0].publicMaterialAvailability, .available)
        XCTAssertEqual(report.assessments[0].revocationArtifactAvailability, .available)
        XCTAssertEqual(report.assessments[0].handleAvailability, .available)
    }

    func test_recoveryReportClassifiesDeviceBoundPostQuantumWithMissingHandlesAsMissing() throws {
        let identity = Self.identity(
            fingerprint: "device-bound-pq-orphan",
            keyVersion: 6,
            configurationIdentity: .deviceBoundPostQuantumV6,
            publicKeyData: Data("device-bound-pq-orphan-cert".utf8),
            revocationCert: Data("device-bound-pq-orphan-revocation".utf8)
        )
        let service = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: MockSecureEnclaveCustodyPublicBindingInspector(
                error: CypherAirError.invalidKeyData(reason: "p256 inspector must not be called")
            ),
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore()),
            compositeBindingInspector: MockSecureEnclaveCompositeBindingInspector(
                inspection: Self.compositeInspection(identity: identity)
            ),
            compositeHandleStore: SecureEnclaveCompositeHandleStore(keyStore: InMemoryCompositeKeyStore())
        )

        let report = service.classify(identities: [identity])

        // The key material is valid and associated; only the enclave handles are
        // gone — a precise "missing handles" state, never the false invalid-custody.
        XCTAssertEqual(report.assessments[0].publicMaterialAvailability, .available)
        XCTAssertEqual(report.assessments[0].handleAvailability, .unavailable(.privateHandleMissing))
    }

    func test_recoveryReportMarksCompleteMetadataAndHandlesAvailable() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let handleStore = makeHandleStore(keyStore: keyStore, handleSetIdentifier: "available")
        let pair = try handleStore.createHandlePair()
        let identity = Self.identity(
            fingerprint: "available",
            publicKeyData: Data("available-cert".utf8),
            revocationCert: Data("available-revocation".utf8)
        )
        let inspector = MockSecureEnclaveCustodyPublicBindingInspector(
            inspection: Self.inspection(
                identity: identity,
                signingPublicKeyX963: pair.signing.publicKeyX963,
                keyAgreementPublicKeyX963: pair.keyAgreement.publicKeyX963
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
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore())
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
        let partialReference = try Self.reference("partial", .signing)
        let partialSigning = try Self.binding(partialReference, byte: 0x31)
        partialKeyStore.insert(
            SecureEnclaveCustodyLoadedHandle(binding: partialSigning, privateKey: nil)
        )
        var partialReport = makeService(
            keyStore: partialKeyStore,
            inspection: Self.inspection(
                identity: identity,
                signingPublicKeyX963: partialSigning.publicKeyX963,
                keyAgreementPublicKeyX963: Self.publicKey(byte: 0x32)
            )
        )
        .classify(identities: [identity])
        XCTAssertEqual(
            partialReport.assessments[0].handleAvailability,
            .unavailable(.migrationOrRecoveryRequired)
        )

        let ambiguousKeyStore = MockSecureEnclaveCustodyKeyStore()
        let ambiguousStore = makeHandleStore(keyStore: ambiguousKeyStore, handleSetIdentifier: "ambiguous")
        let ambiguousPair = try ambiguousStore.createHandlePair()
        ambiguousKeyStore.insert(
            SecureEnclaveCustodyLoadedHandle(
                binding: try Self.binding(ambiguousPair.signing.reference, byte: 0x33),
                privateKey: nil
            ),
            allowingDuplicate: true
        )
        partialReport = makeService(
            keyStore: ambiguousKeyStore,
            inspection: Self.inspection(
                identity: identity,
                signingPublicKeyX963: ambiguousPair.signing.publicKeyX963,
                keyAgreementPublicKeyX963: ambiguousPair.keyAgreement.publicKeyX963
            )
        )
        .classify(identities: [identity])
        XCTAssertEqual(
            partialReport.assessments[0].handleAvailability,
            .unavailable(.privateHandleInaccessible)
        )

        let wrongPublicKeyStore = MockSecureEnclaveCustodyKeyStore()
        let wrongPublicStore = makeHandleStore(keyStore: wrongPublicKeyStore, handleSetIdentifier: "wrong-public")
        let wrongPublicPair = try wrongPublicStore.createHandlePair()
        let wrongPublicReport = makeService(
            keyStore: wrongPublicKeyStore,
            inspection: Self.inspection(
                identity: identity,
                signingPublicKeyX963: wrongPublicPair.signing.publicKeyX963,
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
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore())
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
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: MockSecureEnclaveCustodyKeyStore())
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
            handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        )
    }

    private func makeHandleStore(
        keyStore: MockSecureEnclaveCustodyKeyStore,
        handleSetIdentifier: String
    ) -> SecureEnclaveCustodyHandleStore {
        SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { handleSetIdentifier }
        )
    }

    private static func identity(
        fingerprint: String,
        keyVersion: UInt8 = 4,
        configurationIdentity: PGPKeyConfiguration.Identity = .compatibleP256V4,
        publicKeyData: Data = Data("public".utf8),
        revocationCert: Data = Data("revocation".utf8)
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: keyVersion,
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
            openPGPConfigurationIdentity: configurationIdentity,
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
            role: role
        )
    }

    private static func binding(
        _ reference: SecureEnclaveCustodyHandleReference,
        byte: UInt8
    ) throws -> SecureEnclaveCustodyHandlePublicBinding {
        try SecureEnclaveCustodyHandlePublicBinding(
            reference: reference,
            publicKeyX963: publicKey(byte: byte)
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
        tier: SecureEnclaveCompositeTier
    ) throws -> PGPSecureEnclaveCompositeBindingInspection {
        if let error {
            throw error
        }
        return try XCTUnwrap(inspection)
    }
}

/// Minimal in-memory `SecureEnclaveCompositeKeyStoring` for the `.postQuantum`
/// tier: only `inventoryBindings()` is exercised by handle location.
private final class InMemoryCompositeKeyStore: SecureEnclaveCompositeKeyStoring, @unchecked Sendable {
    private var rows: [String: Data] = [:]

    private func key(_ reference: SecureEnclaveCompositeHandleReference) -> String {
        "\(reference.handleSetIdentifier).\(reference.role.rawValue)"
    }

    func createKey(
        reference: SecureEnclaveCompositeHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCompositeLoadedHandle {
        throw SecureEnclaveCustodyHandleError.hardwareUnavailable
    }

    func loadKey(
        reference: SecureEnclaveCompositeHandleReference,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCompositeLoadedHandle? {
        nil
    }

    func inventoryBindings() throws -> [SecureEnclaveCompositeHandlePublicBinding] {
        try rows.compactMap { entry in
            let parts = entry.key.split(separator: ".")
            guard parts.count == 2,
                  let role = PGPPrivateOperationRole(rawValue: String(parts[1])) else {
                return nil
            }
            let reference = try SecureEnclaveCompositeHandleReference(
                handleSetIdentifier: String(parts[0]),
                role: role
            )
            return try SecureEnclaveCompositeHandlePublicBinding(
                reference: reference,
                publicKeyRaw: entry.value
            )
        }
    }

    func deleteKey(reference: SecureEnclaveCompositeHandleReference) throws {
        guard rows.removeValue(forKey: key(reference)) != nil else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(reference.role)
        }
    }

    func seed(handleSetIdentifier: String) throws {
        let signing = try SecureEnclaveCompositeHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .signing
        )
        let keyAgreement = try SecureEnclaveCompositeHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .keyAgreement
        )
        rows[key(signing)] = SecureEnclaveCustodyGenerationRecoveryServiceTests.compositeSigningPublicKey
        rows[key(keyAgreement)] = SecureEnclaveCustodyGenerationRecoveryServiceTests.compositeKeyAgreementPublicKey
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
