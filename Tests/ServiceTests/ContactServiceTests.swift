import XCTest
@testable import CypherAir

/// Tests for ContactService — public key storage, duplicate detection,
/// key update detection, contact removal, and lookup.
final class ContactServiceTests: XCTestCase {
    private typealias ContactsProtectedHarness = (
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        wrappingRootKey: Data,
        store: ContactsDomainStore
    )

    private var engine: PgpEngine!
    private var contactService: ContactService!
    private var tempDir: URL!

    override func setUp() {
        super.setUp()
        engine = PgpEngine()
        let result = TestHelpers.makeContactService(engine: engine)
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

    private func loadFixture(_ name: String) throws -> Data {
        try FixtureLoader.loadData(name, ext: "gpg")
    }

    // MARK: - Post-Auth Gate

    func test_postAuthGateResult_mappingMatchesPR3Contract() {
        struct MappingCase {
            let name: String
            let outcome: ProtectedDataPostUnlockOutcome
            let frameworkState: ProtectedDataFrameworkState
            let availability: ContactsAvailability
            let allowsLegacyLoad: Bool
            let allowsProtectedOpen: Bool
        }

        let settingsDomain = ProtectedDataDomainID(rawValue: "settings")
        let cases: [MappingCase] = [
            MappingCase(
                name: "restart override",
                outcome: .opened([settingsDomain]),
                frameworkState: .restartRequired,
                availability: .restartRequired,
                allowsLegacyLoad: false,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "framework recovery override",
                outcome: .opened([settingsDomain]),
                frameworkState: .frameworkRecoveryNeeded,
                availability: .frameworkUnavailable,
                allowsLegacyLoad: false,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "opened authorized",
                outcome: .opened([settingsDomain]),
                frameworkState: .sessionAuthorized,
                availability: .opening,
                allowsLegacyLoad: true,
                allowsProtectedOpen: true
            ),
            MappingCase(
                name: "no registered domain authorized",
                outcome: .noRegisteredDomainPresent,
                frameworkState: .sessionAuthorized,
                availability: .opening,
                allowsLegacyLoad: true,
                allowsProtectedOpen: true
            ),
            MappingCase(
                name: "no registered openers authorized",
                outcome: .noRegisteredOpeners,
                frameworkState: .sessionAuthorized,
                availability: .opening,
                allowsLegacyLoad: true,
                allowsProtectedOpen: true
            ),
            MappingCase(
                name: "no protected domain",
                outcome: .noProtectedDomainPresent,
                frameworkState: .sessionAuthorized,
                availability: .locked,
                allowsLegacyLoad: false,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "no authenticated context",
                outcome: .noAuthenticatedContext,
                frameworkState: .sessionAuthorized,
                availability: .locked,
                allowsLegacyLoad: false,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "authorization denied",
                outcome: .authorizationDenied,
                frameworkState: .sessionAuthorized,
                availability: .locked,
                allowsLegacyLoad: false,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "pending mutation recovery",
                outcome: .pendingMutationRecoveryRequired,
                frameworkState: .sessionAuthorized,
                availability: .frameworkUnavailable,
                allowsLegacyLoad: false,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "framework recovery outcome",
                outcome: .frameworkRecoveryNeeded,
                frameworkState: .sessionAuthorized,
                availability: .frameworkUnavailable,
                allowsLegacyLoad: false,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "domain open failed",
                outcome: .domainOpenFailed(settingsDomain),
                frameworkState: .sessionAuthorized,
                availability: .frameworkUnavailable,
                allowsLegacyLoad: false,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "locked framework state",
                outcome: .opened([settingsDomain]),
                frameworkState: .sessionLocked,
                availability: .locked,
                allowsLegacyLoad: false,
                allowsProtectedOpen: false
            ),
        ]

        for testCase in cases {
            let result = ContactsPostAuthGateResult(
                postUnlockOutcome: testCase.outcome,
                frameworkState: testCase.frameworkState
            )

            XCTAssertEqual(result.availability, testCase.availability, testCase.name)
            XCTAssertEqual(result.allowsLegacyCompatibilityLoad, testCase.allowsLegacyLoad, testCase.name)
            XCTAssertEqual(result.allowsProtectedDomainOpen, testCase.allowsProtectedOpen, testCase.name)
            XCTAssertTrue(result.clearsRuntime, testCase.name)
        }
    }

    func test_openLegacyCompatibilityAfterPostUnlock_authorizedGateLoadsLegacyContacts() async throws {
        let generated = try engine.generateKey(
            name: "Post Auth Load",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)

        try await contactService.relockProtectedData()
        XCTAssertTrue(contactService.availableContacts.isEmpty)
        XCTAssertEqual(contactService.contactsAvailability, .locked)

        let availability = contactService.openLegacyCompatibilityAfterPostUnlock(
            gateResult: ContactsPostAuthGateResult(
                postUnlockOutcome: .noRegisteredDomainPresent,
                frameworkState: .sessionAuthorized
            )
        )

        XCTAssertEqual(availability, .availableLegacyCompatibility)
        XCTAssertEqual(contactService.contactsAvailability, .availableLegacyCompatibility)
        XCTAssertEqual(contactService.availableContacts.map(\.fingerprint), [generated.fingerprint])
    }

    func test_openLegacyCompatibilityAfterPostUnlock_ineligibleGateClearsRuntimeAndBlocksMutations() throws {
        let generated = try engine.generateKey(
            name: "Post Auth Block",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        XCTAssertFalse(contactService.availableContacts.isEmpty)

        let availability = contactService.openLegacyCompatibilityAfterPostUnlock(
            gateResult: ContactsPostAuthGateResult(
                postUnlockOutcome: .authorizationDenied,
                frameworkState: .sessionAuthorized
            )
        )

        XCTAssertEqual(availability, .locked)
        XCTAssertTrue(contactService.availableContacts.isEmpty)
        XCTAssertThrowsError(try contactService.removeContact(fingerprint: generated.fingerprint)) { error in
            guard case .contactsUnavailable(.locked) = error as? CypherAirError else {
                return XCTFail("Expected contactsUnavailable(.locked), got \(error)")
            }
        }
    }

    func test_contactsPR4MigratesLegacyIntoProtectedDomainAndDeletesQuarantineOnLaterOpen() async throws {
        let generated = try engine.generateKey(
            name: "PR4 Migration",
            email: "pr4-migration@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        let quarantineDirectory = ContactRepository(contactsDirectory: tempDir).quarantineDirectory
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4Migration",
            contactsDirectory: tempDir
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: harness.store
        )

        let availability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .availableProtectedDomain)
        XCTAssertEqual(protectedService.availableContacts.map(\.fingerprint), [generated.fingerprint])
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: quarantineDirectory.path))

        try await protectedService.relockProtectedData()
        let reopenedStore = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey },
            initialSnapshotProvider: {
                XCTFail("Committed Contacts domain should not rebuild from legacy quarantine.")
                return ContactsDomainSnapshot.empty()
            }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: reopenedStore
        )

        let reopenedAvailability = await reopenedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(reopenedAvailability, .availableProtectedDomain)
        XCTAssertEqual(reopenedService.availableContacts.map(\.fingerprint), [generated.fingerprint])
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: quarantineDirectory.path))
    }

    func test_contactsPR4FreshInstallCreatesEmptyProtectedDomainWithoutLegacyDirectory() async throws {
        let documentDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirContactsFresh-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: documentDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: documentDirectory) }
        let contactsDirectory = documentDirectory.appendingPathComponent("contacts", isDirectory: true)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4Fresh",
            contactsDirectory: contactsDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: harness.store
        )

        let availability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .availableProtectedDomain)
        XCTAssertTrue(protectedService.availableContacts.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: contactsDirectory.path))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: ContactRepository(contactsDirectory: contactsDirectory).quarantineDirectory.path
        ))
    }

    func test_contactsPR4CorruptLegacySourceDoesNotPartiallyCutOver() async throws {
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        try Data("not-a-public-certificate".utf8).write(
            to: tempDir.appendingPathComponent("corrupt.gpg")
        )
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4CorruptLegacy",
            contactsDirectory: tempDir
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: harness.store
        )

        let availability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(protectedService.availableContacts.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: ContactRepository(contactsDirectory: tempDir).quarantineDirectory.path
        ))
        XCTAssertNil(try harness.registryStore.loadRegistry().committedMembership[ContactsDomainRepository.domainID])
    }

    func test_contactsPR4PreCutoverProtectedCreateFailureFallsBackToActiveLegacy() async throws {
        let generated = try engine.generateKey(
            name: "PR4 Pre Cutover Fallback",
            email: "pr4-pre-cutover-fallback@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4PreCutoverFallback",
            contactsDirectory: tempDir
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        var registry = try harness.registryStore.loadRegistry()
        registry.pendingMutation = .createDomain(
            targetDomainID: ContactsDomainRepository.domainID,
            phase: .journaled
        )
        try harness.registryStore.saveRegistry(registry)
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: harness.store
        )

        let availability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .availableLegacyCompatibility)
        XCTAssertEqual(protectedService.availableContacts.map(\.fingerprint), [generated.fingerprint])
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertNil(try harness.registryStore.loadRegistry().committedMembership[ContactsDomainRepository.domainID])
    }

    func test_contactsPR4CorruptProtectedDomainAfterCutoverRequiresRecoveryAndDoesNotReadQuarantine() async throws {
        let generated = try engine.generateKey(
            name: "PR4 Corruption",
            email: "pr4-corruption@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        let repository = ContactRepository(contactsDirectory: tempDir)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4CorruptProtected",
            contactsDirectory: tempDir
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: harness.store
        )
        let cutoverAvailability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(cutoverAvailability, .availableProtectedDomain)
        XCTAssertTrue(FileManager.default.fileExists(atPath: repository.quarantineDirectory.path))
        try harness.storageRoot.writeProtectedData(
            Data("not-a-readable-contacts-envelope".utf8),
            to: harness.storageRoot.domainEnvelopeURL(
                for: ContactsDomainRepository.domainID,
                slot: .current
            )
        )

        let reopenedStore = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey },
            initialSnapshotProvider: {
                XCTFail("Corrupt committed Contacts domain must not rebuild from quarantine.")
                return ContactsDomainSnapshot.empty()
            }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(reopenedService.availableContacts.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: repository.quarantineDirectory.path))
    }

    func test_contactsPR4CommittedDomainIgnoresCorruptRecreatedActiveLegacy() async throws {
        let generated = try engine.generateKey(
            name: "PR4 Stale Legacy",
            email: "pr4-stale-legacy@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        let repository = ContactRepository(contactsDirectory: tempDir)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4CommittedIgnoresLegacy",
            contactsDirectory: tempDir
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: harness.store
        )
        let cutoverAvailability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(cutoverAvailability, .availableProtectedDomain)
        XCTAssertTrue(FileManager.default.fileExists(atPath: repository.quarantineDirectory.path))

        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        try Data("not-a-public-certificate".utf8).write(
            to: tempDir.appendingPathComponent("corrupt.gpg")
        )
        let reopenedStore = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .availableProtectedDomain)
        XCTAssertEqual(reopenedService.availableContacts.map(\.fingerprint), [generated.fingerprint])
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: repository.quarantineDirectory.path))
    }

    func test_contactsPR4CommittedProtectedFailureDoesNotFallbackToActiveLegacy() async throws {
        let generated = try engine.generateKey(
            name: "PR4 No Fallback",
            email: "pr4-no-fallback@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        let repository = ContactRepository(contactsDirectory: tempDir)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4CommittedNoFallback",
            contactsDirectory: tempDir
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: harness.store
        )
        let cutoverAvailability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(cutoverAvailability, .availableProtectedDomain)
        XCTAssertTrue(FileManager.default.fileExists(atPath: repository.quarantineDirectory.path))
        try repository.savePublicKey(generated.publicKeyData, fingerprint: generated.fingerprint)
        try harness.storageRoot.writeProtectedData(
            Data("not-a-readable-contacts-envelope".utf8),
            to: harness.storageRoot.domainEnvelopeURL(
                for: ContactsDomainRepository.domainID,
                slot: .current
            )
        )

        let reopenedStore = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(reopenedService.availableContacts.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: repository.quarantineDirectory.path))
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ContactsDomainRepository.domainID],
            .recoveryNeeded
        )
    }

    func test_contactsPR4ProtectedMutationsPersistWithoutWritingActiveLegacy() async throws {
        let documentDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirContactsMutation-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: documentDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: documentDirectory) }
        let contactsDirectory = documentDirectory.appendingPathComponent("contacts", isDirectory: true)
        let repository = ContactRepository(contactsDirectory: contactsDirectory)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4Mutation",
            contactsDirectory: contactsDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: harness.store
        )
        let initialAvailability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(initialAvailability, .availableProtectedDomain)
        let generated = try engine.generateKey(
            name: "Protected Mutation",
            email: "protected-mutation@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )

        _ = try protectedService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        XCTAssertEqual(protectedService.availableContacts.map(\.fingerprint), [generated.fingerprint])
        XCTAssertFalse(FileManager.default.fileExists(atPath: contactsDirectory.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: repository.quarantineDirectory.path))
        try await protectedService.relockProtectedData()
        XCTAssertTrue(protectedService.contactsDomainRuntimeStateIsClearedForTests)

        let reopenedStore = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: reopenedStore
        )

        let reopenedAvailability = await reopenedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(reopenedAvailability, .availableProtectedDomain)
        XCTAssertEqual(reopenedService.availableContacts.map(\.fingerprint), [generated.fingerprint])
        XCTAssertEqual(reopenedService.availableContacts.first?.verificationState, .unverified)
        XCTAssertFalse(FileManager.default.fileExists(atPath: contactsDirectory.path))
    }

    func test_contactsPR4CorruptCurrentGenerationAfterMutationRequiresRecovery() async throws {
        let documentDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirContactsCorruptCurrent-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: documentDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: documentDirectory) }
        let contactsDirectory = documentDirectory.appendingPathComponent("contacts", isDirectory: true)
        let repository = ContactRepository(contactsDirectory: contactsDirectory)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4CorruptCurrent",
            contactsDirectory: contactsDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: harness.store
        )
        let initialAvailability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(initialAvailability, .availableProtectedDomain)
        let generated = try engine.generateKey(
            name: "Corrupt Current",
            email: "corrupt-current@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try protectedService.addContact(publicKeyData: generated.publicKeyData)
        try repository.savePublicKey(generated.publicKeyData, fingerprint: generated.fingerprint)
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: harness.storageRoot.domainEnvelopeURL(
                for: ContactsDomainRepository.domainID,
                slot: .previous
            ).path
        ))
        try harness.storageRoot.writeProtectedData(
            Data("not-a-readable-contacts-envelope".utf8),
            to: harness.storageRoot.domainEnvelopeURL(
                for: ContactsDomainRepository.domainID,
                slot: .current
            )
        )

        let reopenedStore = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(reopenedService.availableContacts.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: contactsDirectory.path))
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ContactsDomainRepository.domainID],
            .recoveryNeeded
        )
    }

    func test_contactsPR4MissingCurrentGenerationAfterMutationRequiresRecovery() async throws {
        let documentDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirContactsMissingCurrent-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: documentDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: documentDirectory) }
        let contactsDirectory = documentDirectory.appendingPathComponent("contacts", isDirectory: true)
        let repository = ContactRepository(contactsDirectory: contactsDirectory)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4MissingCurrent",
            contactsDirectory: contactsDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: harness.store
        )
        let initialAvailability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(initialAvailability, .availableProtectedDomain)
        let generated = try engine.generateKey(
            name: "Missing Current",
            email: "missing-current@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try protectedService.addContact(publicKeyData: generated.publicKeyData)
        try repository.savePublicKey(generated.publicKeyData, fingerprint: generated.fingerprint)
        let currentURL = harness.storageRoot.domainEnvelopeURL(
            for: ContactsDomainRepository.domainID,
            slot: .current
        )
        let previousURL = harness.storageRoot.domainEnvelopeURL(
            for: ContactsDomainRepository.domainID,
            slot: .previous
        )
        XCTAssertTrue(FileManager.default.fileExists(atPath: previousURL.path))
        try FileManager.default.removeItem(at: currentURL)

        let reopenedStore = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(reopenedService.availableContacts.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: contactsDirectory.path))
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ContactsDomainRepository.domainID],
            .recoveryNeeded
        )
    }

    func test_contactsPR4MissingBootstrapMetadataRequiresRecoveryWithoutLegacyFallback() async throws {
        let generated = try engine.generateKey(
            name: "Missing Bootstrap",
            email: "missing-bootstrap@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        let repository = ContactRepository(contactsDirectory: tempDir)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4MissingBootstrap",
            contactsDirectory: tempDir
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: harness.store
        )
        let cutoverAvailability = await protectedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(cutoverAvailability, .availableProtectedDomain)
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: repository.quarantineDirectory.path))
        try ProtectedDomainBootstrapStore(
            storageRoot: harness.storageRoot
        ).removeMetadata(for: ContactsDomainRepository.domainID)
        try repository.savePublicKey(generated.publicKeyData, fingerprint: generated.fingerprint)

        let reopenedStore = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey },
            initialSnapshotProvider: {
                XCTFail("Committed Contacts domain must not rebuild from legacy when bootstrap metadata is missing.")
                return ContactsDomainSnapshot.empty()
            }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDirectory: tempDir,
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(reopenedService.availableContacts.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: repository.quarantineDirectory.path))
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ContactsDomainRepository.domainID],
            .recoveryNeeded
        )
    }

    func test_contactsPR4AuthoritativeReadValidatesBootstrapBeforeUnwrappingDMK() throws {
        let contents = try RepositoryAuditLoader.loadString(
            relativePath: "Sources/Security/ProtectedData/ContactsDomainStore.swift"
        )
        let method = try sourceBlock(
            in: contents,
            from: "private func readAuthoritativeSnapshot",
            to: "private func expectedCurrentGenerationIdentifier"
        )
        let expectedGenerationRead = try XCTUnwrap(method.range(
            of: "let expectedCurrentGenerationIdentifier = try expectedCurrentGenerationIdentifier()"
        ))
        let dmkUnwrap = try XCTUnwrap(method.range(
            of: "var domainMasterKey = try domainKeyManager.unwrapDomainMasterKey"
        ))

        XCTAssertTrue(expectedGenerationRead.lowerBound < dmkUnwrap.lowerBound)
        XCTAssertTrue(method.contains("""
        catch {
                    domainMasterKey.protectedDataZeroize()
                    throw error
                }
        """))
    }

    func test_productionContactsCallsitesUseGatedAccessors() throws {
        let sourcesRoot = try RepositoryAuditLoader.sourcesRootURL()
        let allowedRelativePaths: Set<String> = [
            "App/Onboarding/TutorialSandboxContainer.swift",
            "Services/ContactService.swift",
        ]
        let forbiddenPatterns: [(label: String, regex: String)] = [
            ("raw loadContacts", #"contactService\.loadContacts\s*\("#),
            ("raw contacts property", #"contactService\.contacts\b"#),
            ("raw contact lookup", #"contactService\.contact\s*\("#),
            ("private raw add", #"contactService\.performAddContact\s*\("#),
            ("private raw remove", #"contactService\.performRemoveContact\s*\("#),
            ("private raw verification mutation", #"contactService\.performSetVerificationState\s*\("#),
            ("private raw legacy load", #"contactService\.loadLegacyCompatibilityRuntimeValues\s*\("#),
        ]
        var violations: [String] = []

        let enumerator = FileManager.default.enumerator(
            at: sourcesRoot,
            includingPropertiesForKeys: nil
        )
        while let fileURL = enumerator?.nextObject() as? URL {
            guard fileURL.pathExtension == "swift" else {
                continue
            }

            let relativePath = fileURL.path
                .replacingOccurrences(of: sourcesRoot.path + "/", with: "")
            guard !allowedRelativePaths.contains(relativePath) else {
                continue
            }

            let contents = try String(contentsOf: fileURL, encoding: .utf8)
            for pattern in forbiddenPatterns where contents.range(
                of: pattern.regex,
                options: .regularExpression
            ) != nil {
                violations.append("\(relativePath): \(pattern.label)")
            }
        }

        XCTAssertTrue(
            violations.isEmpty,
            "Production Contacts callsites must use gated accessors:\n\(violations.joined(separator: "\n"))"
        )
    }

    func test_contactsUnavailableStateDoesNotOfferAddContactAction() throws {
        let contents = try RepositoryAuditLoader.loadString(
            relativePath: "Sources/App/Contacts/ContactsView.swift"
        )
        let unavailableBlock = try sourceBlock(
            in: contents,
            from: "private func contactsUnavailableContent",
            to: "private var emptyStateContent"
        )
        let toolbarBlock = try sourceBlock(
            in: contents,
            from: ".toolbar {",
            to: ".alert("
        )

        XCTAssertFalse(unavailableBlock.contains("routeNavigator.open(.addContact)"))
        XCTAssertFalse(unavailableBlock.contains("contacts.add"))
        XCTAssertTrue(toolbarBlock.contains("if contactService.contactsAvailability.isAvailable"))
        XCTAssertTrue(toolbarBlock.contains("routeNavigator.open(.addContact)"))
    }

    func test_pr5ProductionRecipientResolutionUsesContactIdsOutsideCompatibilitySeams() throws {
        let sourcesRoot = try RepositoryAuditLoader.sourcesRootURL()
        let allowedRelativePaths: Set<String> = [
            "App/Encrypt/EncryptScreenModel.swift",
            "App/Encrypt/EncryptView.swift",
            "App/Onboarding/Tutorial/TutorialConfigurationFactory.swift",
            "Services/ContactRecipientResolver.swift",
            "Services/ContactService.swift",
            "Services/EncryptionService.swift",
        ]
        let forbiddenPatterns: [(label: String, regex: String)] = [
            ("fingerprint recipient parameter", #"recipientFingerprints\s*:"#),
            ("fingerprint recipient resolver", #"publicKeysForRecipientFingerprints\s*\("#),
            ("legacy fingerprint recipient resolver", #"legacyPublicKeysForRecipientFingerprints\s*\("#),
        ]
        var violations: [String] = []

        let enumerator = FileManager.default.enumerator(
            at: sourcesRoot,
            includingPropertiesForKeys: nil
        )
        while let fileURL = enumerator?.nextObject() as? URL {
            guard fileURL.pathExtension == "swift" else {
                continue
            }

            let relativePath = fileURL.path
                .replacingOccurrences(of: sourcesRoot.path + "/", with: "")
            guard !allowedRelativePaths.contains(relativePath) else {
                continue
            }

            let contents = try String(contentsOf: fileURL, encoding: .utf8)
            for pattern in forbiddenPatterns where contents.range(
                of: pattern.regex,
                options: .regularExpression
            ) != nil {
                violations.append("\(relativePath): \(pattern.label)")
            }
        }

        XCTAssertTrue(
            violations.isEmpty,
            "Production recipient resolution must use contact IDs outside compatibility seams:\n\(violations.joined(separator: "\n"))"
        )
    }

    // MARK: - PR5 Contact Identities

    func test_pr5ImportMatcher_sameFingerprintDoesNotReturnCandidate() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let matcher = ContactImportMatcher()
        let generated = try engine.generateKey(
            name: "Matcher Same Fingerprint",
            email: "matcher-same@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )

        _ = try mutator.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        let validation = try ContactImportPublicCertificateValidator.validate(
            generated.publicKeyData,
            using: engine
        )

        XCTAssertNil(matcher.candidateMatch(for: validation, in: snapshot))
    }

    func test_pr5SnapshotMutator_sameFingerprintUpdatePreservesCanonicalIds() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let generated = try engine.generateKey(
            name: "Mutator Stable Key",
            email: "mutator-stable@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try mutator.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        let beforeRecord = try XCTUnwrap(snapshot.keyRecords.first)

        let update = try mutator.addContact(
            publicKeyData: refreshed.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )

        guard case .updated(let fingerprint) = update.output else {
            return XCTFail("Expected .updated, got \(update.output)")
        }
        let afterRecord = try XCTUnwrap(snapshot.keyRecords.first)
        XCTAssertEqual(fingerprint, beforeRecord.fingerprint)
        XCTAssertEqual(afterRecord.contactId, beforeRecord.contactId)
        XCTAssertEqual(afterRecord.keyId, beforeRecord.keyId)
    }

    func test_pr5RecipientResolver_usesPreferredKeyAndLegacyExactFingerprintRows() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let resolver = ContactRecipientResolver()
        let firstKey = try engine.generateKey(
            name: "Resolver One",
            email: "resolver-one@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let secondKey = try engine.generateKey(
            name: "Resolver Two",
            email: "resolver-two@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )

        _ = try mutator.addContact(
            publicKeyData: firstKey.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        _ = try mutator.addContact(
            publicKeyData: secondKey.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        let targetContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == firstKey.fingerprint }?.contactId
        )
        let sourceContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == secondKey.fingerprint }?.contactId
        )
        _ = try mutator.mergeContact(
            sourceContactId: sourceContactId,
            into: targetContactId,
            in: &snapshot
        )

        XCTAssertEqual(
            try resolver.publicKeysForRecipientContactIDs([targetContactId], in: snapshot),
            [firstKey.publicKeyData]
        )
        XCTAssertEqual(
            try resolver.legacyPublicKeysForRecipientFingerprints(
                [secondKey.fingerprint],
                contacts: try ContactsDomainRepository().makeCompatibilityContacts(from: snapshot)
            ),
            [secondKey.publicKeyData]
        )
        XCTAssertThrowsError(
            try resolver.legacyPublicKeysForRecipientFingerprints(
                [targetContactId],
                contacts: try ContactsDomainRepository().makeCompatibilityContacts(from: snapshot)
            )
        )
    }

    func test_pr5SummaryProjector_recipientRowsUsePreferredKeyVerificationOnly() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let projector = ContactSummaryProjector()
        let preferredKey = try engine.generateKey(
            name: "Projector Preferred",
            email: "projector-preferred@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let historicalKey = try engine.generateKey(
            name: "Projector Historical",
            email: "projector-historical@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )

        _ = try mutator.addContact(
            publicKeyData: preferredKey.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        _ = try mutator.addContact(
            publicKeyData: historicalKey.publicKeyData,
            verificationState: .unverified,
            in: &snapshot
        )
        let targetContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == preferredKey.fingerprint }?.contactId
        )
        let sourceContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == historicalKey.fingerprint }?.contactId
        )
        _ = try mutator.mergeContact(
            sourceContactId: sourceContactId,
            into: targetContactId,
            in: &snapshot
        )
        _ = try mutator.setKeyUsageState(
            .historical,
            fingerprint: historicalKey.fingerprint,
            in: &snapshot
        )

        let identity = try XCTUnwrap(projector.identitySummary(contactId: targetContactId, in: snapshot))
        let recipient = try XCTUnwrap(
            projector.recipientSummaries(from: snapshot).first { $0.contactId == targetContactId }
        )
        XCTAssertTrue(identity.hasUnverifiedKeys)
        XCTAssertEqual(recipient.preferredKey.fingerprint, preferredKey.fingerprint)
        XCTAssertTrue(recipient.isPreferredKeyVerified)
    }

    func test_pr5ProtectedImport_sameEmailDifferentFingerprintCreatesNewIdentityAndStrongCandidate() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5StrongCandidate")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let firstKey = try engine.generateKey(
            name: "Strong Candidate",
            email: "candidate@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let secondKey = try engine.generateKey(
            name: "Strong Candidate",
            email: "candidate@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )

        let firstResult = try service.addContact(publicKeyData: firstKey.publicKeyData)
        guard case .added(let firstContact) = firstResult else {
            return XCTFail("Expected .added, got \(firstResult)")
        }

        let secondResult = try service.addContact(publicKeyData: secondKey.publicKeyData)
        guard case .addedWithCandidate(let secondContact, let candidate) = secondResult else {
            return XCTFail("Expected .addedWithCandidate, got \(secondResult)")
        }

        XCTAssertEqual(candidate.strength, .strong)
        XCTAssertEqual(candidate.contactIds, [try XCTUnwrap(firstContact.contactId)])
        XCTAssertNotEqual(firstContact.contactId, secondContact.contactId)
        XCTAssertEqual(service.availableContactIdentities.count, 2)
        XCTAssertEqual(service.availableContacts.map(\.fingerprint).sorted(), [
            firstKey.fingerprint,
            secondKey.fingerprint,
        ].sorted())
    }

    func test_pr5ProtectedImport_sameUserIdWithoutEmailCreatesWeakCandidateAndNeverAutoLinks() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5WeakCandidate")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let firstKey = try engine.generateKey(
            name: "Weak Candidate",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        let secondKey = try engine.generateKey(
            name: "Weak Candidate",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
        )

        let firstResult = try service.addContact(publicKeyData: firstKey.publicKeyData)
        guard case .added(let firstContact) = firstResult else {
            return XCTFail("Expected .added, got \(firstResult)")
        }

        let secondResult = try service.addContact(publicKeyData: secondKey.publicKeyData)
        guard case .addedWithCandidate(let secondContact, let candidate) = secondResult else {
            return XCTFail("Expected .addedWithCandidate, got \(secondResult)")
        }

        XCTAssertEqual(candidate.strength, .weak)
        XCTAssertEqual(candidate.contactIds, [try XCTUnwrap(firstContact.contactId)])
        XCTAssertNotEqual(firstContact.contactId, secondContact.contactId)
        XCTAssertEqual(service.availableContactIdentities.count, 2)
    }

    func test_pr5ProtectedSameFingerprintUpdatePreservesCanonicalIdentityAndKeyIds() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5SameFingerprintUpdate")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Stable Key",
            email: "stable@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try service.addContact(publicKeyData: generated.publicKeyData)
        let beforeSnapshot = try service.currentCompatibilitySnapshot()
        let beforeRecord = try XCTUnwrap(beforeSnapshot.keyRecords.first)

        let updateResult = try service.addContact(publicKeyData: refreshed.publicKeyData)
        guard case .updated(let updatedContact) = updateResult else {
            return XCTFail("Expected .updated, got \(updateResult)")
        }

        let afterSnapshot = try service.currentCompatibilitySnapshot()
        let afterRecord = try XCTUnwrap(afterSnapshot.keyRecords.first)
        XCTAssertEqual(updatedContact.contactId, beforeRecord.contactId)
        XCTAssertEqual(afterRecord.contactId, beforeRecord.contactId)
        XCTAssertEqual(afterRecord.keyId, beforeRecord.keyId)
        XCTAssertEqual(afterRecord.fingerprint, beforeRecord.fingerprint)
    }

    func test_pr5ProtectedMergePreservesKeyStateAndHistoricalSignerRecognition() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5MergeState")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let targetKey = try engine.generateKey(
            name: "Merge Target",
            email: "merge-target@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let sourceKey = try engine.generateKey(
            name: "Merge Source",
            email: "merge-source@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )

        _ = try service.addContact(publicKeyData: targetKey.publicKeyData, verificationState: .verified)
        _ = try service.addContact(publicKeyData: sourceKey.publicKeyData, verificationState: .unverified)
        let targetContactId = try XCTUnwrap(service.contactId(forFingerprint: targetKey.fingerprint))
        let sourceContactId = try XCTUnwrap(service.contactId(forFingerprint: sourceKey.fingerprint))

        let mergeResult = try service.mergeContact(sourceContactId: sourceContactId, into: targetContactId)

        XCTAssertEqual(mergeResult.survivingContact.contactId, targetContactId)
        XCTAssertFalse(mergeResult.preferredKeyNeedsSelection)

        let summary = try XCTUnwrap(service.availableContactIdentity(forContactID: targetContactId))
        XCTAssertEqual(summary.keys.count, 2)
        XCTAssertEqual(summary.preferredKey?.fingerprint, targetKey.fingerprint)
        let incomingKey = try XCTUnwrap(summary.keys.first { $0.fingerprint == sourceKey.fingerprint })
        XCTAssertEqual(incomingKey.usageState, .additionalActive)
        XCTAssertEqual(incomingKey.manualVerificationState, .unverified)

        let recipientKeys = try service.publicKeysForRecipientContactIDs([targetContactId])
        XCTAssertEqual(recipientKeys, [targetKey.publicKeyData])

        try service.setKeyUsageState(.historical, fingerprint: sourceKey.fingerprint)
        let historicalSummary = try XCTUnwrap(service.availableContactIdentity(forContactID: targetContactId))
        XCTAssertEqual(historicalSummary.historicalKeys.map(\.fingerprint), [sourceKey.fingerprint])
        XCTAssertEqual(try service.publicKeysForRecipientContactIDs([targetContactId]), [targetKey.publicKeyData])

        let verificationContext = service.contactsForVerificationContext()
        XCTAssertEqual(verificationContext.availability, .availableProtectedDomain)
        XCTAssertTrue(verificationContext.contacts.contains { $0.fingerprint == sourceKey.fingerprint })
        XCTAssertTrue(verificationContext.contacts.contains { $0.fingerprint == targetKey.fingerprint })
    }

    func test_pr5ProtectedMergeUnionsTagsAndRecipientListMemberships() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5MergeMembership")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let targetKey = try engine.generateKey(
            name: "Tagged Target",
            email: "tagged-target@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let sourceKey = try engine.generateKey(
            name: "Tagged Source",
            email: "tagged-source@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )

        _ = try service.addContact(publicKeyData: targetKey.publicKeyData)
        _ = try service.addContact(publicKeyData: sourceKey.publicKeyData)
        let targetContactId = try XCTUnwrap(service.contactId(forFingerprint: targetKey.fingerprint))
        let sourceContactId = try XCTUnwrap(service.contactId(forFingerprint: sourceKey.fingerprint))

        let now = Date()
        var snapshot = try service.currentCompatibilitySnapshot()
        snapshot.tags = [
            ContactTag(
                tagId: "tag-target",
                displayName: "Target Tag",
                normalizedName: ContactTag.normalizedName(for: "Target Tag"),
                createdAt: now,
                updatedAt: now
            ),
            ContactTag(
                tagId: "tag-source",
                displayName: "Source Tag",
                normalizedName: ContactTag.normalizedName(for: "Source Tag"),
                createdAt: now,
                updatedAt: now
            ),
        ]
        let targetIdentityIndex = try XCTUnwrap(
            snapshot.identities.firstIndex { $0.contactId == targetContactId }
        )
        let sourceIdentityIndex = try XCTUnwrap(
            snapshot.identities.firstIndex { $0.contactId == sourceContactId }
        )
        snapshot.identities[targetIdentityIndex].tagIds = ["tag-target"]
        snapshot.identities[sourceIdentityIndex].tagIds = ["tag-source"]
        snapshot.recipientLists = [
            RecipientList(
                recipientListId: "list-source",
                name: "Source List",
                memberContactIds: [sourceContactId],
                createdAt: now,
                updatedAt: now
            )
        ]
        try opened.harness.store.replaceSnapshot(snapshot)
        try await service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        let reopenedService = reopened.service

        _ = try reopenedService.mergeContact(sourceContactId: sourceContactId, into: targetContactId)

        let mergedSnapshot = try reopenedService.currentCompatibilitySnapshot()
        let mergedIdentity = try XCTUnwrap(
            mergedSnapshot.identities.first { $0.contactId == targetContactId }
        )
        XCTAssertEqual(Set(mergedIdentity.tagIds), Set(["tag-target", "tag-source"]))
        XCTAssertEqual(mergedSnapshot.recipientLists.first?.memberContactIds, [targetContactId])
        XCTAssertFalse(mergedSnapshot.identities.contains { $0.contactId == sourceContactId })
    }

    func test_pr5ProtectedPreferredKeySelectionPersistsAndMissingPreferredFailsClosed() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5PreferredPersistence")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let firstKey = try engine.generateKey(
            name: "Preferred One",
            email: "preferred-one@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let secondKey = try engine.generateKey(
            name: "Preferred Two",
            email: "preferred-two@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )

        _ = try service.addContact(publicKeyData: firstKey.publicKeyData)
        _ = try service.addContact(publicKeyData: secondKey.publicKeyData)
        let targetContactId = try XCTUnwrap(service.contactId(forFingerprint: firstKey.fingerprint))
        let sourceContactId = try XCTUnwrap(service.contactId(forFingerprint: secondKey.fingerprint))
        _ = try service.mergeContact(sourceContactId: sourceContactId, into: targetContactId)

        try service.setPreferredKey(fingerprint: secondKey.fingerprint, for: targetContactId)
        try await service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        let reopenedService = reopened.service
        XCTAssertEqual(
            reopenedService.availableContactIdentity(forContactID: targetContactId)?.preferredKey?.fingerprint,
            secondKey.fingerprint
        )
        XCTAssertEqual(try reopenedService.publicKeysForRecipientContactIDs([targetContactId]), [secondKey.publicKeyData])

        var unresolvedSnapshot = try reopenedService.currentCompatibilitySnapshot()
        for index in unresolvedSnapshot.keyRecords.indices
            where unresolvedSnapshot.keyRecords[index].contactId == targetContactId {
            unresolvedSnapshot.keyRecords[index].usageState = .additionalActive
        }
        try reopened.store.replaceSnapshot(unresolvedSnapshot)
        try await reopenedService.relockProtectedData()
        let unresolved = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        let unresolvedService = unresolved.service

        XCTAssertNil(unresolvedService.availableContactIdentity(forContactID: targetContactId)?.preferredKey)
        XCTAssertThrowsError(try unresolvedService.publicKeysForRecipientContactIDs([targetContactId])) { error in
            guard case .invalidKeyData = error as? CypherAirError else {
                return XCTFail("Expected invalidKeyData for missing preferred key, got \(error)")
            }
        }
    }

    // MARK: - Load Contacts

    func test_loadContacts_emptyDirectory_returnsEmpty() throws {
        try contactService.openLegacyCompatibilityForTests()
        XCTAssertTrue(contactService.availableContacts.isEmpty,
                      "Loading from empty directory should produce no contacts")
    }

    func test_loadContacts_secretCertificateOnDiskFailsClosed() throws {
        let valid = try engine.generateKey(
            name: "Stored Valid",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        let secretBearing = try engine.generateKey(
            name: "Stored Secret",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
        )

        try valid.publicKeyData.write(
            to: tempDir.appendingPathComponent("\(valid.fingerprint).gpg"),
            options: .atomic
        )
        try secretBearing.certData.write(
            to: tempDir.appendingPathComponent("\(secretBearing.fingerprint).gpg"),
            options: .atomic
        )

        let metadataURL = tempDir.appendingPathComponent("contact-metadata.json")
        let manifest: [String: Any] = [
            "verificationStates": [
                valid.fingerprint: ContactVerificationState.verified.rawValue,
                secretBearing.fingerprint: ContactVerificationState.verified.rawValue,
            ]
        ]
        let metadata = try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
        try metadata.write(to: metadataURL, options: .atomic)

        XCTAssertThrowsError(try contactService.openLegacyCompatibilityForTests())
        XCTAssertTrue(contactService.availableContacts.isEmpty)
        XCTAssertEqual(contactService.contactsAvailability, .recoveryNeeded)
    }

    // MARK: - Add Contact

    func test_addContact_validPublicKey_returnsAdded() throws {
        let generated = try engine.generateKey(
            name: "Alice", email: "alice@example.com",
            expirySeconds: nil, profile: .universal
        )

        let result = try contactService.addContact(publicKeyData: generated.publicKeyData)

        if case .added(let contact) = result {
            XCTAssertFalse(contact.fingerprint.isEmpty)
        } else {
            XCTFail("Expected .added, got \(result)")
        }

        XCTAssertEqual(contactService.availableContacts.count, 1)
    }

    func test_addContact_secretCertificateRejectedWithoutPersisting() throws {
        let generated = try engine.generateKey(
            name: "Secret Contact Reject",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        XCTAssertThrowsError(try contactService.addContact(publicKeyData: generated.certData)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .contactImportRequiresPublicCertificate = cypherError else {
                return XCTFail("Expected .contactImportRequiresPublicCertificate, got \(cypherError)")
            }
        }

        XCTAssertTrue(contactService.availableContacts.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("\(generated.fingerprint).gpg").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("contact-metadata.json").path))
    }

    func test_addContact_armoredSecretCertificateRejectedWithoutPersisting() throws {
        let generated = try engine.generateKey(
            name: "Armored Secret Contact Reject",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
        )
        let armoredSecret = try engine.armor(data: generated.certData, kind: .secretKey)

        XCTAssertThrowsError(try contactService.addContact(publicKeyData: armoredSecret)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .contactImportRequiresPublicCertificate = cypherError else {
                return XCTFail("Expected .contactImportRequiresPublicCertificate, got \(cypherError)")
            }
        }

        XCTAssertTrue(contactService.availableContacts.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("\(generated.fingerprint).gpg").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("contact-metadata.json").path))
    }

    func test_addContact_duplicateFingerprint_returnsDuplicate() throws {
        let generated = try engine.generateKey(
            name: "Bob", email: "bob@example.com",
            expirySeconds: nil, profile: .universal
        )

        // Add once
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)

        // Add again — same fingerprint
        let result = try contactService.addContact(publicKeyData: generated.publicKeyData)

        if case .duplicate = result {
            // Expected
        } else {
            XCTFail("Expected .duplicate, got \(result)")
        }

        XCTAssertEqual(contactService.availableContacts.count, 1,
                       "Duplicate should not increase contact count")
    }

    func test_addContact_sameFingerprintMaterialUpdate_returnsUpdated() throws {
        let generated = try engine.generateKey(
            name: "Update", email: "update@example.com",
            expirySeconds: nil, profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        let result = try contactService.addContact(publicKeyData: refreshed.publicKeyData)

        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertEqual(contactService.availableContacts.count, 1)
        XCTAssertEqual(updatedContact.fingerprint, generated.fingerprint)
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: updatedContact.publicKeyData).expiryTimestamp,
            refreshed.keyInfo.expiryTimestamp
        )

        let storedFile = tempDir.appendingPathComponent("\(generated.fingerprint).gpg")
        let storedData = try Data(contentsOf: storedFile)
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: storedData).expiryTimestamp,
            refreshed.keyInfo.expiryTimestamp,
            "Stored contact file should be updated in place"
        )

        let restarted = ContactService(engine: engine, contactsDirectory: tempDir)
        try restarted.openLegacyCompatibilityForTests()
        XCTAssertEqual(restarted.availableContacts.count, 1)
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: restarted.availableContacts[0].publicKeyData).expiryTimestamp,
            refreshed.keyInfo.expiryTimestamp
        )
    }

    func test_addContact_sameFingerprintMaterialUpdate_preservesUnverifiedState() throws {
        let generated = try engine.generateKey(
            name: "Update Unverified", email: "update-unverified@example.com",
            expirySeconds: nil, profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        let result = try contactService.addContact(
            publicKeyData: refreshed.publicKeyData,
            verificationState: .unverified
        )
        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertFalse(updatedContact.isVerified)

        let restarted = ContactService(engine: engine, contactsDirectory: tempDir)
        try restarted.openLegacyCompatibilityForTests()
        XCTAssertFalse(restarted.availableContacts[0].isVerified)
    }

    func test_addContact_sameFingerprintMaterialUpdate_verifiedImportPromotesExistingUnverifiedContact() throws {
        let generated = try engine.generateKey(
            name: "Update Promote", email: "update-promote@example.com",
            expirySeconds: nil, profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        let result = try contactService.addContact(
            publicKeyData: refreshed.publicKeyData,
            verificationState: .verified
        )
        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.isVerified)
        XCTAssertTrue(contactService.availableContact(forFingerprint: updatedContact.fingerprint)?.isVerified == true)
    }

    func test_addContact_sameFingerprintPrimaryUserIdUpdate_returnsUpdatedAndRefreshesDisplayIdentity() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")

        let baseInfo = try engine.parseKeyInfo(keyData: base)
        XCTAssertEqual(baseInfo.userId, "aaaaa")

        _ = try contactService.addContact(publicKeyData: base)
        let result = try contactService.addContact(publicKeyData: update)

        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertEqual(updatedContact.fingerprint, baseInfo.fingerprint)
        XCTAssertEqual(updatedContact.userId, "bbbbb")
        XCTAssertEqual(updatedContact.displayName, "bbbbb")
        XCTAssertEqual(contactService.availableContacts.count, 1)

        let storedData = try Data(contentsOf: tempDir.appendingPathComponent("\(baseInfo.fingerprint).gpg"))
        XCTAssertEqual(try engine.parseKeyInfo(keyData: storedData).userId, "bbbbb")
    }

    func test_addContact_sameFingerprintPrimaryUserIdCollision_returnsKeyUpdateDetectedWithoutPersistingMerge() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")
        let conflictingKey = try engine.generateKey(
            name: "bbbbb",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let originalInfo = try engine.parseKeyInfo(keyData: base)

        _ = try contactService.addContact(publicKeyData: base)
        _ = try contactService.addContact(publicKeyData: conflictingKey.publicKeyData)

        let result = try contactService.addContact(publicKeyData: update)
        guard case .keyUpdateDetected(let newContact, let existingContact, let keyData) = result else {
            return XCTFail("Expected .keyUpdateDetected, got \(result)")
        }

        XCTAssertEqual(newContact.fingerprint, originalInfo.fingerprint)
        XCTAssertEqual(newContact.userId, "bbbbb")
        XCTAssertEqual(existingContact.fingerprint, conflictingKey.fingerprint)
        XCTAssertEqual(contactService.availableContacts.count, 2)
        XCTAssertEqual(contactService.availableContact(forFingerprint: originalInfo.fingerprint)?.userId, "aaaaa")
        XCTAssertEqual(try engine.parseKeyInfo(keyData: keyData).userId, "bbbbb")

        let storedData = try Data(contentsOf: tempDir.appendingPathComponent("\(originalInfo.fingerprint).gpg"))
        XCTAssertEqual(try engine.parseKeyInfo(keyData: storedData).userId, "aaaaa")
    }

    func test_confirmKeyUpdate_sameFingerprintMergeCollisionRemovesConflictingContact() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")
        let conflictingKey = try engine.generateKey(
            name: "bbbbb",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let originalInfo = try engine.parseKeyInfo(keyData: base)

        _ = try contactService.addContact(publicKeyData: base)
        _ = try contactService.addContact(publicKeyData: conflictingKey.publicKeyData)

        let result = try contactService.addContact(publicKeyData: update)
        guard case .keyUpdateDetected(_, let existingContact, let keyData) = result else {
            return XCTFail("Expected .keyUpdateDetected, got \(result)")
        }

        try contactService.confirmKeyUpdate(
            existingFingerprint: existingContact.fingerprint,
            keyData: keyData
        )

        XCTAssertEqual(contactService.availableContacts.count, 1)
        let survivingContact = try XCTUnwrap(contactService.availableContact(forFingerprint: originalInfo.fingerprint))
        XCTAssertEqual(survivingContact.userId, "bbbbb")
        XCTAssertTrue(survivingContact.isVerified)
        XCTAssertFalse(contactService.availableContacts.contains { $0.fingerprint == existingContact.fingerprint })

        let survivingFile = tempDir.appendingPathComponent("\(originalInfo.fingerprint).gpg")
        XCTAssertTrue(FileManager.default.fileExists(atPath: survivingFile.path))
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: Data(contentsOf: survivingFile)).userId,
            "bbbbb"
        )

        let removedFile = tempDir.appendingPathComponent("\(existingContact.fingerprint).gpg")
        XCTAssertFalse(FileManager.default.fileExists(atPath: removedFile.path))
    }

    func test_addContact_sameFingerprintRevocationUpdate_profileA_refreshesRevocationState() throws {
        let base = try loadFixture("merge_revocation_profile_a_base")
        let update = try loadFixture("merge_revocation_profile_a_update")

        _ = try contactService.addContact(publicKeyData: base)
        let result = try contactService.addContact(publicKeyData: update)

        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.isRevoked)
        XCTAssertFalse(updatedContact.canEncryptTo)

        let restarted = ContactService(engine: engine, contactsDirectory: tempDir)
        try restarted.openLegacyCompatibilityForTests()
        XCTAssertTrue(restarted.availableContacts[0].isRevoked)
    }

    func test_addContact_sameFingerprintRevocationUpdate_profileB_refreshesRevocationState() throws {
        let base = try loadFixture("merge_revocation_profile_b_base")
        let update = try loadFixture("merge_revocation_profile_b_update")

        _ = try contactService.addContact(publicKeyData: base)
        let result = try contactService.addContact(publicKeyData: update)

        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.isRevoked)
        XCTAssertFalse(updatedContact.canEncryptTo)
        XCTAssertEqual(updatedContact.profile, .advanced)
    }

    func test_addContact_sameFingerprintEncryptionSubkeyUpdate_profileA_refreshesEncryptionCapability() throws {
        let base = try loadFixture("merge_add_encryption_subkey_profile_a_base")
        let update = try loadFixture("merge_add_encryption_subkey_profile_a_update")

        let added = try contactService.addContact(publicKeyData: base)
        guard case .added(let baseContact) = added else {
            return XCTFail("Expected .added, got \(added)")
        }
        XCTAssertFalse(baseContact.hasEncryptionSubkey)
        XCTAssertFalse(baseContact.canEncryptTo)

        let result = try contactService.addContact(publicKeyData: update)
        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.hasEncryptionSubkey)
        XCTAssertTrue(updatedContact.canEncryptTo)
    }

    func test_addContact_sameFingerprintEncryptionSubkeyUpdate_profileB_refreshesEncryptionCapability() throws {
        let base = try loadFixture("merge_add_encryption_subkey_profile_b_base")
        let update = try loadFixture("merge_add_encryption_subkey_profile_b_update")

        let added = try contactService.addContact(publicKeyData: base)
        guard case .added(let baseContact) = added else {
            return XCTFail("Expected .added, got \(added)")
        }
        XCTAssertFalse(baseContact.hasEncryptionSubkey)
        XCTAssertFalse(baseContact.canEncryptTo)

        let result = try contactService.addContact(publicKeyData: update)
        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.hasEncryptionSubkey)
        XCTAssertTrue(updatedContact.canEncryptTo)
        XCTAssertEqual(updatedContact.profile, .advanced)
    }

    func test_addContact_sameUserIdDifferentFingerprint_returnsKeyUpdateDetected() throws {
        // Generate two keys with the same userId but different fingerprints
        let key1 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )
        let key2 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )

        // Add first key
        _ = try contactService.addContact(publicKeyData: key1.publicKeyData)

        // Add second key with same userId
        let result = try contactService.addContact(publicKeyData: key2.publicKeyData)

        if case .keyUpdateDetected(let newContact, let existingContact, _) = result {
            XCTAssertNotEqual(newContact.fingerprint, existingContact.fingerprint,
                              "Key update should have different fingerprints")
        } else {
            XCTFail("Expected .keyUpdateDetected, got \(result)")
        }

        // Count should still be 1 — update not yet confirmed
        XCTAssertEqual(contactService.availableContacts.count, 1)
    }

    // MARK: - Remove Contact

    func test_removeContact_existingContact_removesFromArray() throws {
        let generated = try engine.generateKey(
            name: "Dave", email: nil,
            expirySeconds: nil, profile: .advanced
        )

        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        XCTAssertEqual(contactService.availableContacts.count, 1)

        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        try contactService.removeContact(fingerprint: keyInfo.fingerprint)

        XCTAssertEqual(contactService.availableContacts.count, 0,
                       "Contact should be removed from array")
    }

    // MARK: - Confirm Key Update

    func test_confirmKeyUpdate_replacesOldContact() throws {
        let key1 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )
        let key2 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )

        // Add first key
        _ = try contactService.addContact(publicKeyData: key1.publicKeyData)
        XCTAssertEqual(contactService.availableContacts.count, 1)
        let oldFingerprint = contactService.availableContacts[0].fingerprint

        // Detect update
        let result = try contactService.addContact(publicKeyData: key2.publicKeyData)
        guard case .keyUpdateDetected(let newContact, _, let keyData) = result else {
            return XCTFail("Expected .keyUpdateDetected")
        }

        // Confirm update
        let confirmedContact = try contactService.confirmKeyUpdate(
            existingFingerprint: oldFingerprint,
            keyData: keyData
        )

        // Verify: old contact replaced, new contact present
        XCTAssertEqual(contactService.availableContacts.count, 1)
        XCTAssertEqual(contactService.availableContacts[0].fingerprint, newContact.fingerprint)
        XCTAssertNotEqual(contactService.availableContacts[0].fingerprint, oldFingerprint)
        XCTAssertEqual(confirmedContact.fingerprint, newContact.fingerprint)

        // Verify: new file exists on disk
        let newFile = tempDir.appendingPathComponent("\(newContact.fingerprint).gpg")
        XCTAssertTrue(FileManager.default.fileExists(atPath: newFile.path),
                      "New key file should exist after confirmKeyUpdate")

        // Verify: old file removed
        let oldFile = tempDir.appendingPathComponent("\(oldFingerprint).gpg")
        XCTAssertFalse(FileManager.default.fileExists(atPath: oldFile.path),
                       "Old key file should be removed after confirmKeyUpdate")
    }

    func test_confirmKeyUpdate_secretKeyDataRejectedWithoutReplacingExistingContact() throws {
        let key1 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )
        let key2 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )

        _ = try contactService.addContact(publicKeyData: key1.publicKeyData)
        let oldFingerprint = contactService.availableContacts[0].fingerprint

        let result = try contactService.addContact(publicKeyData: key2.publicKeyData)
        guard case .keyUpdateDetected = result else {
            return XCTFail("Expected .keyUpdateDetected")
        }

        XCTAssertThrowsError(
            try contactService.confirmKeyUpdate(
                existingFingerprint: oldFingerprint,
                keyData: key2.certData
            )
        ) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .contactImportRequiresPublicCertificate = cypherError else {
                return XCTFail("Expected .contactImportRequiresPublicCertificate, got \(cypherError)")
            }
        }

        XCTAssertEqual(contactService.availableContacts.count, 1)
        XCTAssertEqual(contactService.availableContacts[0].fingerprint, oldFingerprint)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("\(oldFingerprint).gpg").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("\(key2.fingerprint).gpg").path))
    }

    // MARK: - Binary Key Import

    func test_addContact_binaryPublicKey_profileA_returnsAdded() throws {
        // generateKey returns publicKeyData in binary OpenPGP format (not armored).
        // This confirms the service accepts raw binary Data — the same format
        // the views should pass after the binary import fix.
        let generated = try engine.generateKey(
            name: "BinaryA", email: nil,
            expirySeconds: nil, profile: .universal
        )

        // Verify the data is actually binary (not ASCII armor)
        let firstByte = generated.publicKeyData.first
        XCTAssertNotEqual(firstByte, UInt8(ascii: "-"),
                          "publicKeyData should be binary, not armored")

        let result = try contactService.addContact(publicKeyData: generated.publicKeyData)
        if case .added(let contact) = result {
            XCTAssertFalse(contact.fingerprint.isEmpty)
        } else {
            XCTFail("Expected .added for binary Profile A key, got \(result)")
        }
    }

    func test_addContact_binaryPublicKey_profileB_returnsAdded() throws {
        let generated = try engine.generateKey(
            name: "BinaryB", email: nil,
            expirySeconds: nil, profile: .advanced
        )

        let firstByte = generated.publicKeyData.first
        XCTAssertNotEqual(firstByte, UInt8(ascii: "-"),
                          "publicKeyData should be binary, not armored")

        let result = try contactService.addContact(publicKeyData: generated.publicKeyData)
        if case .added(let contact) = result {
            XCTAssertFalse(contact.fingerprint.isEmpty)
        } else {
            XCTFail("Expected .added for binary Profile B key, got \(result)")
        }
    }

    func test_addContact_armoredPublicKey_profileA_returnsAdded() throws {
        // Verify armored format also works (regression guard)
        let generated = try engine.generateKey(
            name: "ArmoredA", email: nil,
            expirySeconds: nil, profile: .universal
        )

        let armoredData = try engine.armorPublicKey(certData: generated.publicKeyData)
        let firstChar = String(data: armoredData.prefix(5), encoding: .utf8)
        XCTAssertTrue(firstChar?.hasPrefix("-----") == true,
                      "Armored data should start with PGP header")

        let result = try contactService.addContact(publicKeyData: armoredData)
        if case .added(let contact) = result {
            XCTAssertFalse(contact.fingerprint.isEmpty)
        } else {
            XCTFail("Expected .added for armored Profile A key, got \(result)")
        }
    }

    // MARK: - Lookup

    func test_contactsMatchingKeyIds_returnsCorrectContacts() throws {
        let key1 = try engine.generateKey(
            name: "Eve", email: nil,
            expirySeconds: nil, profile: .universal
        )
        let key2 = try engine.generateKey(
            name: "Frank", email: nil,
            expirySeconds: nil, profile: .advanced
        )

        _ = try contactService.addContact(publicKeyData: key1.publicKeyData)
        _ = try contactService.addContact(publicKeyData: key2.publicKeyData)
        XCTAssertEqual(contactService.availableContacts.count, 2)

        let info1 = try engine.parseKeyInfo(keyData: key1.publicKeyData)

        // Lookup by full fingerprint
        let found = contactService.availableContact(forFingerprint: info1.fingerprint)
        XCTAssertNotNil(found, "Should find contact by full fingerprint")
        XCTAssertEqual(found?.fingerprint, info1.fingerprint)
    }

    // MARK: - M5: Contact Persistence Across Restart

    func test_contactPersistence_survivesServiceRestart() throws {
        let generated = try engine.generateKey(
            name: "Persist Test", email: "persist@example.com",
            expirySeconds: nil, profile: .universal
        )

        // Add contact to first service instance
        let addResult = try contactService.addContact(publicKeyData: generated.publicKeyData)
        guard case .added(let contact) = addResult else {
            XCTFail("Expected .added"); return
        }
        let originalFingerprint = contact.fingerprint

        // Create a NEW service instance pointing to the same temp directory
        let newService = ContactService(engine: engine, contactsDirectory: tempDir)
        try newService.openLegacyCompatibilityForTests()

        XCTAssertEqual(newService.availableContacts.count, 1, "Contact should survive service restart")
        XCTAssertEqual(newService.availableContacts.first?.fingerprint, originalFingerprint,
                       "Fingerprint should match after restart")
    }

    func test_addContact_unverified_persistsAcrossRestart() throws {
        let generated = try engine.generateKey(
            name: "Unverified Persist", email: "pending@example.com",
            expirySeconds: nil, profile: .universal
        )

        let addResult = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        guard case .added(let contact) = addResult else {
            XCTFail("Expected .added"); return
        }
        XCTAssertFalse(contact.isVerified)

        let newService = ContactService(engine: engine, contactsDirectory: tempDir)
        try newService.openLegacyCompatibilityForTests()

        XCTAssertEqual(newService.availableContacts.count, 1)
        XCTAssertEqual(newService.availableContacts.first?.fingerprint, contact.fingerprint)
        XCTAssertFalse(newService.availableContacts.first?.isVerified ?? true)
    }

    func test_setVerificationState_promotesContactToVerified_andPersists() throws {
        let generated = try engine.generateKey(
            name: "Manual Verify", email: "manual@example.com",
            expirySeconds: nil, profile: .universal
        )

        let addResult = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        guard case .added(let contact) = addResult else {
            XCTFail("Expected .added"); return
        }

        try contactService.setVerificationState(.verified, for: contact.fingerprint)
        XCTAssertTrue(contactService.availableContact(forFingerprint: contact.fingerprint)?.isVerified == true)

        let newService = ContactService(engine: engine, contactsDirectory: tempDir)
        try newService.openLegacyCompatibilityForTests()
        XCTAssertTrue(newService.availableContact(forFingerprint: contact.fingerprint)?.isVerified == true)
    }

    func test_addContact_duplicateVerifiedImport_upgradesExistingUnverifiedContact() throws {
        let generated = try engine.generateKey(
            name: "Duplicate Upgrade", email: "upgrade@example.com",
            expirySeconds: nil, profile: .universal
        )

        _ = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        let duplicateResult = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .verified
        )
        guard case .duplicate(let upgradedContact) = duplicateResult else {
            XCTFail("Expected .duplicate"); return
        }

        XCTAssertTrue(upgradedContact.isVerified)
        XCTAssertTrue(contactService.availableContact(forFingerprint: upgradedContact.fingerprint)?.isVerified == true)
    }

    func test_protectedDomainCompatibilitySnapshot_roundTripsLegacyContactProjection() throws {
        let generated = try engine.generateKey(
            name: "Projection", email: "projection@example.com",
            expirySeconds: nil, profile: .universal
        )
        let addResult = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        guard case .added(let contact) = addResult else {
            return XCTFail("Expected .added")
        }

        let snapshot = try contactService.currentCompatibilitySnapshot()
        XCTAssertEqual(snapshot.schemaVersion, ContactsDomainSnapshot.currentSchemaVersion)
        XCTAssertEqual(snapshot.identities.map(\.contactId), ["legacy-contact-\(contact.fingerprint)"])
        XCTAssertEqual(snapshot.keyRecords.map(\.keyId), ["legacy-key-\(contact.fingerprint)"])
        XCTAssertEqual(snapshot.keyRecords.first?.usageState, .preferred)

        let projectedContacts = try contactService.compatibilityContacts(from: snapshot)
        let projected = try XCTUnwrap(projectedContacts.first)
        XCTAssertEqual(projectedContacts.count, 1)
        XCTAssertEqual(projected.fingerprint, contact.fingerprint)
        XCTAssertEqual(projected.profile, contact.profile)
        XCTAssertEqual(projected.userId, contact.userId)
        XCTAssertEqual(projected.publicKeyData, contact.publicKeyData)
        XCTAssertEqual(projected.canEncryptTo, contact.canEncryptTo)
        XCTAssertFalse(projected.isVerified)
    }

    func test_protectedDomainCompatibilitySnapshot_marksNonEncryptableLegacyContactHistorical() throws {
        let repository = ContactsDomainRepository()
        let contact = Contact(
            fingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            keyVersion: 4,
            profile: .universal,
            userId: "Historical <history@example.com>",
            isRevoked: false,
            isExpired: false,
            hasEncryptionSubkey: false,
            verificationState: .verified,
            publicKeyData: Data([0x01]),
            primaryAlgo: "Ed25519",
            subkeyAlgo: nil
        )

        let snapshot = try repository.makeCompatibilitySnapshot(from: [contact])

        XCTAssertEqual(snapshot.keyRecords.first?.usageState, .historical)
        XCTAssertNoThrow(try snapshot.validateContract())
    }

    func test_protectedDomainRelockClearsContactsRuntimeState() async throws {
        let generated = try engine.generateKey(
            name: "Relock", email: "relock@example.com",
            expirySeconds: nil, profile: .universal
        )
        _ = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        contactService.seedContactsDomainRuntimeStateForTests()

        XCTAssertFalse(contactService.availableContacts.isEmpty)
        XCTAssertEqual(contactService.contactsAvailability, .availableLegacyCompatibility)

        try await contactService.relockProtectedData()

        XCTAssertTrue(contactService.availableContacts.isEmpty)
        XCTAssertEqual(contactService.contactsAvailability, .locked)
        XCTAssertTrue(contactService.contactsDomainRuntimeStateIsClearedForTests)
    }

    @MainActor
    func test_protectedDomainAppContainerRelockClearsContactsWithoutCreatingDomainArtifacts() async throws {
        let container = AppContainer.makeUITest(preloadContact: true)
        defer {
            try? FileManager.default.removeItem(
                at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
            )
            if let contactsDirectory = container.contactsDirectory {
                try? FileManager.default.removeItem(at: contactsDirectory.deletingLastPathComponent())
            }
            if let defaultsSuiteName = container.defaultsSuiteName {
                UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
            }
        }

        XCTAssertFalse(container.contactService.availableContacts.isEmpty)
        XCTAssertFalse(contactsDomainArtifactsExist(in: container.protectedDataStorageRoot))

        await container.protectedDataSessionCoordinator.relockCurrentSession()

        XCTAssertTrue(container.contactService.availableContacts.isEmpty)
        XCTAssertTrue(container.contactService.contactsDomainRuntimeStateIsClearedForTests)
        XCTAssertFalse(contactsDomainArtifactsExist(in: container.protectedDataStorageRoot))
    }

    @MainActor
    func test_makeUITest_authBypassOpensLegacyCompatibilityGateForContacts() throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }

        XCTAssertEqual(container.contactService.contactsAvailability, .availableLegacyCompatibility)

        let generated = try container.engine.generateKey(
            name: "Auth Bypass Contact",
            email: "auth-bypass@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let result = try container.contactService.addContact(publicKeyData: generated.publicKeyData)

        guard case .added(let contact) = result else {
            return XCTFail("Expected .added, got \(result)")
        }
        XCTAssertEqual(contact.fingerprint, generated.fingerprint)
    }

    @MainActor
    func test_makeUITest_manualAuthenticationDoesNotPreopenContactsGate() throws {
        let container = AppContainer.makeUITest(requiresManualAuthentication: true)
        defer {
            cleanup(container)
        }

        XCTAssertEqual(container.contactService.contactsAvailability, .locked)
        XCTAssertTrue(container.contactService.availableContacts.isEmpty)
    }

    private func contactsDomainArtifactsExist(in storageRoot: ProtectedDataStorageRoot) -> Bool {
        let fileManager = FileManager.default
        let urls = ProtectedDomainGenerationSlot.allCases.map {
            storageRoot.domainEnvelopeURL(for: ContactsDomainRepository.domainID, slot: $0)
        } + [
            storageRoot.committedWrappedDomainMasterKeyURL(for: ContactsDomainRepository.domainID),
            storageRoot.stagedWrappedDomainMasterKeyURL(for: ContactsDomainRepository.domainID)
        ]
        return urls.contains { fileManager.fileExists(atPath: $0.path) }
    }

    private func makeOpenedProtectedContactService(
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
            contactsDirectory: directory,
            contactsDomainStore: harness.store
        )

        let availability = await service.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(availability, .availableProtectedDomain)

        return (service, harness, directory)
    }

    private func reopenProtectedContactService(
        harness: ContactsProtectedHarness,
        contactsDirectory: URL
    ) async -> (service: ContactService, store: ContactsDomainStore) {
        let store = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey },
            initialSnapshotProvider: {
                XCTFail("Committed Contacts domain should not rebuild from legacy source.")
                return ContactsDomainSnapshot.empty()
            }
        )
        let service = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: store
        )
        let availability = await service.openContactsAfterPostUnlock(
            gateResult: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(availability, .availableProtectedDomain)
        return (service, store)
    }

    private func makeContactsProtectedHarness(
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
        let migrationSource = ContactsLegacyMigrationSource(
            engine: engine,
            repository: ContactRepository(contactsDirectory: contactsDirectory)
        )
        let store = ContactsDomainStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey },
            initialSnapshotProvider: {
                try migrationSource.makeInitialSnapshot()
            }
        )

        return (
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            wrappingRootKey: wrappingRootKey,
            store: store
        )
    }

    private func authorizedContactsGate() -> ContactsPostAuthGateResult {
        ContactsPostAuthGateResult(
            postUnlockOutcome: .opened([ProtectedSettingsStore.domainID]),
            frameworkState: .sessionAuthorized
        )
    }

    private func sourceBlock(
        in contents: String,
        from startMarker: String,
        to endMarker: String
    ) throws -> String {
        let start = try XCTUnwrap(contents.range(of: startMarker))
        let end = try XCTUnwrap(contents.range(of: endMarker, range: start.upperBound..<contents.endIndex))
        return String(contents[start.lowerBound..<end.lowerBound])
    }

    private func cleanup(_ container: AppContainer) {
        try? FileManager.default.removeItem(
            at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
        )
        if let contactsDirectory = container.contactsDirectory {
            try? FileManager.default.removeItem(at: contactsDirectory.deletingLastPathComponent())
        }
        if let defaultsSuiteName = container.defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
        }
    }
}
