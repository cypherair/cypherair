import XCTest
@testable import CypherAir

final class ContactServiceProtectedDomainTests: ContactServiceTestCase {
    // MARK: - Post-Auth Gate

    func test_postAuthGateDecision_mappingMatchesProtectedDataBoundaryContract() {
        struct MappingCase {
            let name: String
            let outcome: ProtectedDataPostUnlockOutcome
            let frameworkState: ProtectedDataFrameworkState
            let availability: ContactsAvailability
            let allowsProtectedOpen: Bool
        }

        let settingsDomain = ProtectedDataDomainID(rawValue: "settings")
        let cases: [MappingCase] = [
            MappingCase(
                name: "restart override",
                outcome: .opened([settingsDomain]),
                frameworkState: .restartRequired,
                availability: .restartRequired,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "framework recovery override",
                outcome: .opened([settingsDomain]),
                frameworkState: .frameworkRecoveryNeeded,
                availability: .frameworkUnavailable,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "opened authorized",
                outcome: .opened([settingsDomain]),
                frameworkState: .sessionAuthorized,
                availability: .opening,
                allowsProtectedOpen: true
            ),
            MappingCase(
                name: "no registered domain authorized",
                outcome: .noRegisteredDomainPresent,
                frameworkState: .sessionAuthorized,
                availability: .opening,
                allowsProtectedOpen: true
            ),
            MappingCase(
                name: "no registered openers authorized",
                outcome: .noRegisteredOpeners,
                frameworkState: .sessionAuthorized,
                availability: .opening,
                allowsProtectedOpen: true
            ),
            MappingCase(
                name: "no protected domain",
                outcome: .noProtectedDomainPresent,
                frameworkState: .sessionAuthorized,
                availability: .locked,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "no authenticated context",
                outcome: .noAuthenticatedContext,
                frameworkState: .sessionAuthorized,
                availability: .locked,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "authorization denied",
                outcome: .authorizationDenied,
                frameworkState: .sessionAuthorized,
                availability: .locked,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "pending mutation recovery",
                outcome: .pendingMutationRecoveryRequired,
                frameworkState: .sessionAuthorized,
                availability: .frameworkUnavailable,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "framework recovery outcome",
                outcome: .frameworkRecoveryNeeded,
                frameworkState: .sessionAuthorized,
                availability: .frameworkUnavailable,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "domain open failed",
                outcome: .domainOpenFailed(settingsDomain),
                frameworkState: .sessionAuthorized,
                availability: .frameworkUnavailable,
                allowsProtectedOpen: false
            ),
            MappingCase(
                name: "locked framework state",
                outcome: .opened([settingsDomain]),
                frameworkState: .sessionLocked,
                availability: .locked,
                allowsProtectedOpen: false
            ),
        ]

        for testCase in cases {
            let decision = ContactsPostAuthGateDecision(
                postUnlockOutcome: testCase.outcome,
                frameworkState: testCase.frameworkState
            )

            XCTAssertEqual(decision.availability, testCase.availability, testCase.name)
            XCTAssertEqual(decision.allowsProtectedDomainOpen, testCase.allowsProtectedOpen, testCase.name)
            XCTAssertTrue(decision.clearsRuntime, testCase.name)
        }
    }

    func test_openContactsAfterPostUnlock_authorizedGateReopensProtectedContacts() async throws {
        let generated = try engine.generateKey(
            name: "Post Auth Load",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.importContact(publicKeyData: generated.publicKeyData)

        try await contactService.relockProtectedData()
        XCTAssertTrue(contactService.testContactKeyRecords.isEmpty)
        XCTAssertEqual(contactService.contactsAvailability, .locked)

        let availability = await contactService.openContactsAfterPostUnlock(
            gateDecision: ContactsPostAuthGateDecision(
                postUnlockOutcome: .noRegisteredDomainPresent,
                frameworkState: .sessionAuthorized
            ),
            wrappingRootKey: { Data(repeating: 0xA4, count: 32) }
        )

        XCTAssertEqual(availability, .availableProtectedDomain)
        XCTAssertEqual(contactService.contactsAvailability, .availableProtectedDomain)
        XCTAssertEqual(contactService.testContactFingerprints, [generated.fingerprint])
    }

    func test_openContactsAfterPostUnlock_ineligibleGateClearsRuntimeAndBlocksMutations() async throws {
        let generated = try engine.generateKey(
            name: "Post Auth Block",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.importContact(publicKeyData: generated.publicKeyData)
        XCTAssertFalse(contactService.testContactKeyRecords.isEmpty)

        let availability = await contactService.openContactsAfterPostUnlock(
            gateDecision: ContactsPostAuthGateDecision(
                postUnlockOutcome: .authorizationDenied,
                frameworkState: .sessionAuthorized
            ),
            wrappingRootKey: { Data(repeating: 0xA4, count: 32) }
        )

        XCTAssertEqual(availability, .locked)
        XCTAssertTrue(contactService.testContactKeyRecords.isEmpty)
        XCTAssertThrowsError(try contactService.removeContact(fingerprint: generated.fingerprint)) { error in
            guard case .contactsUnavailable(.locked) = error as? CypherAirError else {
                return XCTFail("Expected contactsUnavailable(.locked), got \(error)")
            }
        }
    }

    func test_contactsFreshInstallCreatesEmptyProtectedDomain() async throws {
        let contactsDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirContactsFresh-\(UUID().uuidString)", isDirectory: true)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4Fresh",
            contactsDirectory: contactsDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDomainStore: harness.store
        )

        let availability = await protectedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .availableProtectedDomain)
        XCTAssertTrue(protectedService.testContactKeyRecords.isEmpty)
        XCTAssertNil(try harness.registryStore.loadRegistry().pendingMutation)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ContactsDomainStore.domainID],
            .active
        )
    }

    func test_contactsDomainStoreInitialSnapshotValidationMapsToProtectedDataInvalidEnvelope() async throws {
        let contactsDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirContactsInvalidInitial-\(UUID().uuidString)", isDirectory: true)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsInvalidInitial",
            contactsDirectory: contactsDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }

        var invalidSnapshot = ContactsDomainSnapshot.empty()
        invalidSnapshot.schemaVersion = ContactsDomainSnapshot.currentSchemaVersion + 1

        do {
            try await harness.store.ensureCommittedIfNeeded(
                wrappingRootKey: harness.wrappingRootKey,
                initialSnapshotProvider: {
                    invalidSnapshot
                }
            )
            XCTFail("Expected invalid Contacts snapshot to fail at the ProtectedData storage boundary.")
        } catch {
            XCTAssertEqual(
                error as? ProtectedDataError,
                .invalidEnvelope("Contacts payload has an unsupported schema version.")
            )
        }

        XCTAssertNil(try harness.registryStore.loadRegistry().committedMembership[ContactsDomainStore.domainID])
    }

    func test_contactsProtectedCreateFailureLeavesNoCommittedDomain() async throws {
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4PreCutoverRetry",
            contactsDirectory: tempDir
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        var registry = try harness.registryStore.loadRegistry()
        registry.pendingMutation = .createDomain(
            targetDomainID: ContactsDomainStore.domainID,
            phase: .journaled
        )
        try harness.registryStore.saveRegistry(registry)
        let protectedService = ContactService(
            engine: engine,
            contactsDomainStore: harness.store
        )

        let availability = await protectedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(protectedService.testContactKeyRecords.isEmpty)
        XCTAssertNil(try harness.registryStore.loadRegistry().committedMembership[ContactsDomainStore.domainID])
    }

    func test_contactsCorruptProtectedDomainRequiresRecovery() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsCorruptProtected")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let generated = try engine.generateKey(
            name: "Protected Corruption",
            email: "protected-corruption@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try opened.service.importContact(publicKeyData: generated.publicKeyData)
        try await opened.service.relockProtectedData()
        try opened.harness.storageRoot.writeProtectedData(
            Data("not-a-readable-contacts-envelope".utf8),
            to: opened.harness.storageRoot.domainEnvelopeURL(
                for: ContactsDomainStore.domainID,
                slot: .current
            )
        )

        let reopenedStore = ContactsDomainStore(
            storageRoot: opened.harness.storageRoot,
            registryStore: opened.harness.registryStore,
            domainKeyManager: opened.harness.domainKeyManager,
            currentWrappingRootKey: { opened.harness.wrappingRootKey },
            initialSnapshotProvider: {
                XCTFail("Committed Contacts domain must not be recreated after current-state corruption.")
                return ContactsDomainSnapshot.empty()
            }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { opened.harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(reopenedService.testContactKeyRecords.isEmpty)
        XCTAssertEqual(
            try opened.harness.registryStore.loadRegistry().committedMembership[ContactsDomainStore.domainID],
            .recoveryNeeded
        )
    }

    func test_contactsProtectedMutationsPersistAcrossReopen() async throws {
        let documentDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirContactsMutation-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: documentDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: documentDirectory) }
        let contactsDirectory = documentDirectory.appendingPathComponent("contacts", isDirectory: true)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4Mutation",
            contactsDirectory: contactsDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDomainStore: harness.store
        )
        let initialAvailability = await protectedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(initialAvailability, .availableProtectedDomain)
        let generated = try engine.generateKey(
            name: "Protected Mutation",
            email: "protected-mutation@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )

        _ = try protectedService.importContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        XCTAssertEqual(protectedService.testContactFingerprints, [generated.fingerprint])
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
            contactsDomainStore: reopenedStore
        )

        let reopenedAvailability = await reopenedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(reopenedAvailability, .availableProtectedDomain)
        XCTAssertEqual(reopenedService.testContactFingerprints, [generated.fingerprint])
        XCTAssertEqual(reopenedService.testContactKeyRecords.first?.manualVerificationState, .unverified)
    }

    func test_contactsCorruptCurrentGenerationAfterMutationRequiresRecovery() async throws {
        let documentDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirContactsCorruptCurrent-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: documentDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: documentDirectory) }
        let contactsDirectory = documentDirectory.appendingPathComponent("contacts", isDirectory: true)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4CorruptCurrent",
            contactsDirectory: contactsDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDomainStore: harness.store
        )
        let initialAvailability = await protectedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(initialAvailability, .availableProtectedDomain)
        let generated = try engine.generateKey(
            name: "Corrupt Current",
            email: "corrupt-current@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try protectedService.importContact(publicKeyData: generated.publicKeyData)
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: harness.storageRoot.domainEnvelopeURL(
                for: ContactsDomainStore.domainID,
                slot: .previous
            ).path
        ))
        try harness.storageRoot.writeProtectedData(
            Data("not-a-readable-contacts-envelope".utf8),
            to: harness.storageRoot.domainEnvelopeURL(
                for: ContactsDomainStore.domainID,
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
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(reopenedService.testContactKeyRecords.isEmpty)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ContactsDomainStore.domainID],
            .recoveryNeeded
        )
    }

    func test_contactsMissingCurrentGenerationAfterMutationRequiresRecovery() async throws {
        let documentDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirContactsMissingCurrent-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: documentDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: documentDirectory) }
        let contactsDirectory = documentDirectory.appendingPathComponent("contacts", isDirectory: true)
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4MissingCurrent",
            contactsDirectory: contactsDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDomainStore: harness.store
        )
        let initialAvailability = await protectedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(initialAvailability, .availableProtectedDomain)
        let generated = try engine.generateKey(
            name: "Missing Current",
            email: "missing-current@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try protectedService.importContact(publicKeyData: generated.publicKeyData)
        let currentURL = harness.storageRoot.domainEnvelopeURL(
            for: ContactsDomainStore.domainID,
            slot: .current
        )
        let previousURL = harness.storageRoot.domainEnvelopeURL(
            for: ContactsDomainStore.domainID,
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
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(reopenedService.testContactKeyRecords.isEmpty)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ContactsDomainStore.domainID],
            .recoveryNeeded
        )
    }

    func test_contactsMissingBootstrapMetadataRequiresRecovery() async throws {
        let generated = try engine.generateKey(
            name: "Missing Bootstrap",
            email: "missing-bootstrap@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let harness = try makeContactsProtectedHarness(
            prefix: "ContactsPR4MissingBootstrap",
            contactsDirectory: tempDir
        )
        defer {
            try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let protectedService = ContactService(
            engine: engine,
            contactsDomainStore: harness.store
        )
        let openAvailability = await protectedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(openAvailability, .availableProtectedDomain)
        _ = try protectedService.importContact(publicKeyData: generated.publicKeyData)
        try await protectedService.relockProtectedData()
        try ProtectedDomainBootstrapStore(
            storageRoot: harness.storageRoot
        ).removeMetadata(for: ContactsDomainStore.domainID)

        let reopenedStore = ContactsDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey },
            initialSnapshotProvider: {
                XCTFail("Committed Contacts domain must not be recreated when bootstrap metadata is missing.")
                return ContactsDomainSnapshot.empty()
            }
        )
        let reopenedService = ContactService(
            engine: engine,
            contactsDomainStore: reopenedStore
        )

        let availability = await reopenedService.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )

        XCTAssertEqual(availability, .recoveryNeeded)
        XCTAssertTrue(reopenedService.testContactKeyRecords.isEmpty)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ContactsDomainStore.domainID],
            .recoveryNeeded
        )
    }

    // MARK: - Relock And UI Test Contacts

    func test_protectedDomainRelockClearsContactsRuntimeState() async throws {
        let generated = try engine.generateKey(
            name: "Relock", email: "relock@example.com",
            expirySeconds: nil, profile: .universal
        )
        _ = try contactService.importContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        XCTAssertFalse(contactService.testContactKeyRecords.isEmpty)
        XCTAssertEqual(contactService.contactsAvailability, .availableProtectedDomain)

        try await contactService.relockProtectedData()

        XCTAssertTrue(contactService.testContactKeyRecords.isEmpty)
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
            if let defaultsSuiteName = container.defaultsSuiteName {
                UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
            }
        }

        XCTAssertEqual(container.contactService.contactsAvailability, .locked)
        XCTAssertTrue(container.contactService.testContactKeyRecords.isEmpty)
        let firstAvailability = await container.prepareUITestContactsIfNeeded()
        XCTAssertEqual(firstAvailability, .availableProtectedDomain)
        let preloadedRecordCount = container.contactService.testContactKeyRecords.count
        XCTAssertGreaterThan(preloadedRecordCount, 0)
        let secondAvailability = await container.prepareUITestContactsIfNeeded()
        XCTAssertEqual(secondAvailability, .availableProtectedDomain)
        XCTAssertEqual(container.contactService.testContactKeyRecords.count, preloadedRecordCount)
        XCTAssertFalse(contactsDomainArtifactsExist(in: container.protectedDataStorageRoot))

        await container.protectedDataSessionCoordinator.relockCurrentSession()

        XCTAssertTrue(container.contactService.testContactKeyRecords.isEmpty)
        XCTAssertTrue(container.contactService.contactsDomainRuntimeStateIsClearedForTests)
        XCTAssertFalse(contactsDomainArtifactsExist(in: container.protectedDataStorageRoot))
    }

    @MainActor
    func test_makeUITest_prepareContactsReopensAfterRelockWithoutDuplicatingPreload() async throws {
        let container = AppContainer.makeUITest(preloadContact: true)
        defer {
            cleanup(container)
        }

        XCTAssertEqual(container.contactService.contactsAvailability, .locked)
        XCTAssertTrue(container.contactService.testContactKeyRecords.isEmpty)

        let firstAvailability = await container.prepareUITestContactsIfNeeded()
        XCTAssertEqual(firstAvailability, .availableProtectedDomain)
        XCTAssertEqual(container.contactService.contactsAvailability, .availableProtectedDomain)
        let preloadedRecords = container.contactService.testContactKeyRecords
        let preloadedFingerprints = Set(preloadedRecords.map(\.fingerprint))
        XCTAssertGreaterThan(preloadedRecords.count, 0)
        XCTAssertEqual(preloadedFingerprints.count, preloadedRecords.count)
        XCTAssertFalse(contactsDomainArtifactsExist(in: container.protectedDataStorageRoot))

        await container.protectedDataSessionCoordinator.relockCurrentSession()

        XCTAssertEqual(container.contactService.contactsAvailability, .locked)
        XCTAssertTrue(container.contactService.testContactKeyRecords.isEmpty)
        XCTAssertTrue(container.contactService.contactsDomainRuntimeStateIsClearedForTests)
        XCTAssertFalse(contactsDomainArtifactsExist(in: container.protectedDataStorageRoot))

        let reopenedAvailability = await container.prepareUITestContactsIfNeeded()
        XCTAssertEqual(reopenedAvailability, .availableProtectedDomain)
        XCTAssertEqual(container.contactService.contactsAvailability, .availableProtectedDomain)
        let reopenedRecords = container.contactService.testContactKeyRecords
        XCTAssertEqual(reopenedRecords.count, preloadedRecords.count)
        XCTAssertEqual(Set(reopenedRecords.map(\.fingerprint)), preloadedFingerprints)
        XCTAssertFalse(contactsDomainArtifactsExist(in: container.protectedDataStorageRoot))
    }

    @MainActor
    func test_makeUITest_authBypassPreparesContactsWithAsyncBootstrap() async throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }

        XCTAssertEqual(container.contactService.contactsAvailability, .locked)
        XCTAssertTrue(container.contactService.testContactKeyRecords.isEmpty)
        let availability = await container.prepareUITestContactsIfNeeded()
        XCTAssertEqual(availability, .availableProtectedDomain)
        XCTAssertEqual(container.contactService.contactsAvailability, .availableProtectedDomain)

        let generated = try container.engine.generateKey(
            name: "Auth Bypass Contact",
            email: "auth-bypass@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let result = try container.contactService.importContact(publicKeyData: generated.publicKeyData)

        guard case .added(_, let key) = result else {
            return XCTFail("Expected .added, got \(result)")
        }
        XCTAssertEqual(key.fingerprint, generated.fingerprint)
    }

    @MainActor
    func test_makeUITest_manualAuthenticationDoesNotPreopenContactsGate() async throws {
        let container = AppContainer.makeUITest(requiresManualAuthentication: true)
        defer {
            cleanup(container)
        }

        XCTAssertEqual(container.contactService.contactsAvailability, .locked)
        XCTAssertTrue(container.contactService.testContactKeyRecords.isEmpty)
        let availability = await container.prepareUITestContactsIfNeeded()
        XCTAssertEqual(availability, .locked)
        XCTAssertEqual(container.contactService.contactsAvailability, .locked)
        XCTAssertTrue(container.contactService.testContactKeyRecords.isEmpty)
    }
}
