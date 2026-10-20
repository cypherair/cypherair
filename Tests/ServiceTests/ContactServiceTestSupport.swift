import XCTest
@testable import CypherAir

/// A contact service over a sandbox vault, opened before every test.
class ContactServiceTestCase: XCTestCase {
    var engine: PgpEngine!
    var sandbox: TestHelpers.Sandbox!
    var contactService: ContactService!
    var tempDir: URL { sandbox.directory }
    private(set) var certificationSignerKeys: [PGPKeyIdentity] = []

    override func setUp() async throws {
        try await super.setUp()
        engine = PgpEngine()
        certificationSignerKeys = []
        let opened = try await TestHelpers.makeContactService(engine: engine)
        contactService = opened.service
        sandbox = opened.sandbox
    }

    override func tearDown() {
        sandbox?.cleanup()
        certificationSignerKeys = []
        contactService = nil
        sandbox = nil
        engine = nil
        super.tearDown()
    }

    func loadFixture(_ name: String) throws -> Data {
        try FixtureLoader.loadData(name, ext: "gpg")
    }

    /// A second contact service over its own sandbox vault.
    func makeOpenedContactService() async throws -> (service: ContactService, sandbox: TestHelpers.Sandbox) {
        let opened = try await TestHelpers.makeContactService(engine: engine)
        XCTAssertEqual(opened.service.contactsAvailability, .available)
        return opened
    }

    /// Relaunches the sandbox: the vault is locked and reopened through its
    /// passphrase, and a fresh service reads the persisted contacts domain.
    func reopenContactService(
        sandbox: TestHelpers.Sandbox,
        ownSignerKeys: [PGPKeyIdentity]? = nil
    ) async throws -> ContactService {
        try await sandbox.reopen()
        let service = ContactService(engine: engine, vault: sandbox.vault)
        let availability = await service.openContacts(ownSignerKeys: ownSignerKeys ?? certificationSignerKeys)
        XCTAssertEqual(availability, .available)
        return service
    }

    func attachCertificationArtifact(
        artifactId: String,
        toKeyWithFingerprint fingerprint: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws {
        let keyIndex = try XCTUnwrap(
            snapshot.keyRecords.firstIndex { $0.fingerprint == fingerprint }
        )
        let artifact = makeValidCertificationArtifact(
            artifactId: artifactId,
            keyRecord: snapshot.keyRecords[keyIndex],
            signatureData: Data("test-signature-\(artifactId)".utf8)
        ) { artifact in
            artifact.source = .imported
            artifact.targetSelector = .directKey
            artifact.validationStatus = .revalidationNeeded
            artifact.lastValidatedAt = nil
        }
        snapshot.certificationArtifacts.append(artifact)
        snapshot.keyRecords[keyIndex].certificationArtifactIds.append(artifactId)
        snapshot.keyRecords[keyIndex].certificationProjection = ContactCertificationProjection(
            status: .revalidationNeeded,
            artifactIds: [artifactId],
            lastValidatedAt: nil
        )
    }

    func makeVerifiedCertificationArtifacts(
        service: ContactService,
        keyRecord: ContactKeyRecord,
        exportFilenames: (String, String)
    ) async throws -> (VerifiedContactCertificationArtifact, VerifiedContactCertificationArtifact) {
        let keyManagement = try await TestHelpers.makeKeyManagement(engine: engine).service
        let signer = try await TestHelpers.generateLegacyKey(
            service: keyManagement,
            name: "Certification Signer",
            email: "signer@example.invalid"
        )
        certificationSignerKeys.append(signer)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let certificateSignatureService = CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: keyManagement,
            contactService: service,
            certificationSigner: TestHelpers.makeContactCertificationSigner(
                engine: engine,
                keyManagement: keyManagement,
                certificateAdapter: certificateAdapter
            )
        )
        let targetKey = try XCTUnwrap(service.availableKey(keyId: keyRecord.keyId))
        let selectedUserId = try XCTUnwrap(
            certificateSignatureService.selectionCatalog(
                targetCert: keyRecord.publicKeyData
            ).userIds.first
        )
        let signature = try await certificateSignatureService.generateArmoredUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: keyRecord.publicKeyData,
            selectedUserId: selectedUserId,
            certificationKind: .generic
        )
        let first = try await certificateSignatureService.validateUserIdCertificationArtifact(
            signature: signature,
            targetKey: targetKey,
            targetCert: keyRecord.publicKeyData,
            selectedUserId: selectedUserId,
            source: .generated,
            exportFilename: exportFilenames.0
        )
        let duplicate = try await certificateSignatureService.validateUserIdCertificationArtifact(
            signature: signature,
            targetKey: targetKey,
            targetCert: keyRecord.publicKeyData,
            selectedUserId: selectedUserId,
            source: .imported,
            exportFilename: exportFilenames.1
        )
        return (
            try XCTUnwrap(first.artifact),
            try XCTUnwrap(duplicate.artifact)
        )
    }

    func makeVerifiedCertificationArtifact(
        service: ContactService,
        keyRecord: ContactKeyRecord,
        exportFilename: String
    ) async throws -> VerifiedContactCertificationArtifact {
        try await makeVerifiedCertificationArtifacts(
            service: service,
            keyRecord: keyRecord,
            exportFilenames: (exportFilename, "\(UUID().uuidString).asc")
        ).0
    }

    func makeValidCertificationArtifact(
        artifactId: String,
        keyRecord: ContactKeyRecord,
        signatureData: Data,
        configure: (inout ContactCertificationArtifactReference) -> Void = { _ in }
    ) -> ContactCertificationArtifactReference {
        let userId = keyRecord.primaryUserId ?? "Contact <contact@example.invalid>"
        var artifact = ContactCertificationArtifactReference(
            artifactId: artifactId,
            keyId: keyRecord.keyId,
            createdAt: Date(),
            canonicalSignatureData: signatureData,
            signatureDigest: ContactCertificationArtifactReference.sha256Hex(
                for: signatureData
            ),
            source: .generated,
            targetKeyFingerprint: keyRecord.fingerprint,
            targetSelector: .userId(
                data: Data(userId.utf8),
                displayText: userId,
                occurrenceIndex: 0
            ),
            signerPrimaryFingerprint: "cccccccccccccccccccccccccccccccccccccccc",
            signingKeyFingerprint: "cccccccccccccccccccccccccccccccccccccccc",
            certificationKind: .generic,
            validationStatus: .valid,
            targetCertificateDigest: ContactCertificationArtifactReference.sha256Hex(
                for: keyRecord.publicKeyData
            ),
            lastValidatedAt: Date(),
            updatedAt: Date(),
            exportFilename: "\(artifactId).asc"
        )
        configure(&artifact)
        return artifact
    }
}
