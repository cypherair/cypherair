import XCTest
@testable import CypherAir

class ContactServiceTestCase: XCTestCase {
    typealias ContactsProtectedHarness = (
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        wrappingRootKey: Data,
        store: ContactsDomainStore
    )

    var engine: PgpEngine!
    var contactService: ContactService!
    var tempDir: URL!

    override func setUp() async throws {
        try await super.setUp()
        engine = PgpEngine()
        let result = await TestHelpers.makeContactService(engine: engine)
        contactService = result.service
        tempDir = result.tempDir
    }

    override func tearDown() {
        TestHelpers.cleanupTempDir(tempDir)
        contactService = nil
        engine = nil
        tempDir = nil
        super.tearDown()
    }

    func loadFixture(_ name: String) throws -> Data {
        try FixtureLoader.loadData(name, ext: "gpg")
    }

    func contactsDomainArtifactsExist(in storageRoot: ProtectedDataStorageRoot) -> Bool {
        let fileManager = FileManager.default
        let urls = ProtectedDomainGenerationSlot.allCases.map {
            storageRoot.domainEnvelopeURL(for: ContactsDomainStore.domainID, slot: $0)
        } + [
            storageRoot.committedWrappedDomainMasterKeyURL(for: ContactsDomainStore.domainID),
            storageRoot.stagedWrappedDomainMasterKeyURL(for: ContactsDomainStore.domainID)
        ]
        return urls.contains { fileManager.fileExists(atPath: $0.path) }
    }

    func makeOpenedProtectedContactService(
        prefix: String,
        contactsDirectory: URL? = nil
    ) async throws -> (
        service: ContactService,
        harness: ContactsProtectedHarness,
        contactsDirectory: URL
    ) {
        let directory = contactsDirectory ?? tempDir
            .appendingPathComponent("\(prefix)-contacts-\(UUID().uuidString)", isDirectory: true)
        let harness = try makeContactsProtectedHarness(
            prefix: prefix,
            contactsDirectory: directory
        )
        let service = ContactService(
            engine: engine,
            contactsDomainStore: harness.store
        )

        let availability = await service.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(availability, .availableProtectedDomain)

        return (service, harness, directory)
    }

    func reopenProtectedContactService(
        harness: ContactsProtectedHarness,
        contactsDirectory: URL
    ) async -> (service: ContactService, store: ContactsDomainStore) {
        let store = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey },
            initialSnapshotProvider: {
                XCTFail("Committed Contacts domain should not recreate its initial snapshot.")
                return ContactsDomainSnapshot.empty()
            }
        )
        let service = ContactService(
            engine: engine,
            contactsDomainStore: store
        )
        let availability = await service.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(availability, .availableProtectedDomain)
        return (service, store)
    }

    func attachCertificationArtifact(
        artifactId: String,
        toKeyWithFingerprint fingerprint: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws {
        let keyIndex = try XCTUnwrap(
            snapshot.keyRecords.firstIndex { $0.fingerprint == fingerprint }
        )
        let keyId = snapshot.keyRecords[keyIndex].keyId
        let artifact = ContactCertificationArtifactReference(
            artifactId: artifactId,
            keyId: keyId,
            userId: snapshot.keyRecords[keyIndex].primaryUserId,
            createdAt: Date(),
            storageHint: "test-\(artifactId)"
        )
        snapshot.certificationArtifacts.append(artifact)
        snapshot.keyRecords[keyIndex].certificationArtifactIds.append(artifactId)
        snapshot.keyRecords[keyIndex].certificationProjection = ContactCertificationProjection(
            status: .revalidationNeeded,
            artifactIds: [artifactId],
            lastValidatedAt: nil,
            reconciliationMetadata: "test-\(artifactId)"
        )
    }

    func makeVerifiedCertificationArtifacts(
        service: ContactService,
        keyRecord: ContactKeyRecord,
        exportFilenames: (String, String)
    ) async throws -> (VerifiedContactCertificationArtifact, VerifiedContactCertificationArtifact) {
        let keyManagement = TestHelpers.makeKeyManagement(engine: engine).service
        let signer = try await TestHelpers.generateProfileAKey(
            service: keyManagement,
            name: "PR6 Certification Signer",
            email: "pr6-signer@example.invalid"
        )
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
            userId: userId,
            createdAt: Date(),
            storageHint: "test",
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

    func makeContactsProtectedHarness(
        prefix: String,
        contactsDirectory: URL
    ) throws -> ContactsProtectedHarness {
        let storageRoot = ProtectedDataStorageRoot(
            baseDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        )
        let registryStore = ProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.contacts.\(UUID().uuidString)"
        )
        _ = try registryStore.performSynchronousBootstrap()
        var registry = try registryStore.loadRegistry()
        registry.sharedResourceLifecycleState = .ready
        registry.committedMembership = [ProtectedSettingsStore.domainID: .active]
        try registryStore.saveRegistry(registry)

        let domainKeyManager = ProtectedDomainKeyManager(storageRoot: storageRoot)
        let wrappingRootKey = Data(repeating: 0xA4, count: 32)
        let store = ContactsDomainStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        return (
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            wrappingRootKey: wrappingRootKey,
            store: store
        )
    }

    func currentContactsEnvelope(in storageRoot: ProtectedDataStorageRoot) throws -> ProtectedDomainEnvelope {
        let data = try storageRoot.readManagedData(
            at: storageRoot.domainEnvelopeURL(
                for: ContactsDomainStore.domainID,
                slot: .current
            )
        )
        return try PropertyListDecoder().decode(ProtectedDomainEnvelope.self, from: data)
    }

    func authorizedContactsGate() -> ContactsPostAuthGateDecision {
        ContactsPostAuthGateDecision(
            postUnlockOutcome: .opened([ProtectedSettingsStore.domainID]),
            frameworkState: .sessionAuthorized
        )
    }

    func sourceBlock(
        in contents: String,
        from startMarker: String,
        to endMarker: String
    ) throws -> String {
        let start = try XCTUnwrap(contents.range(of: startMarker))
        let end = try XCTUnwrap(contents.range(of: endMarker, range: start.upperBound..<contents.endIndex))
        return String(contents[start.lowerBound..<end.lowerBound])
    }

    func cleanup(_ container: AppContainer) {
        try? FileManager.default.removeItem(
            at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
        )
        if let defaultsSuiteName = container.defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
        }
    }
}
