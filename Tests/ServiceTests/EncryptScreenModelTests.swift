import Foundation
import XCTest
@testable import CypherAir

private actor EncryptOperationGate {
    private var continuation: CheckedContinuation<Void, Never>?

    func suspend() async {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }

    func isSuspended() -> Bool {
        continuation != nil
    }

    func resume() {
        continuation?.resume()
        continuation = nil
    }
}

private actor EncryptClipboardNoticeGate {
    private var continuation: CheckedContinuation<Bool, Never>?

    func decision() async -> Bool {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }

    func isSuspended() -> Bool {
        continuation != nil
    }

    func resume(returning value: Bool) {
        continuation?.resume(returning: value)
        continuation = nil
    }
}

final class EncryptScreenModelTests: XCTestCase {
    private typealias ContactsProtectedHarness = (
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        wrappingRootKey: Data,
        store: ContactsDomainStore
    )

    private var stack: TestHelpers.ServiceStack!
    private var config: AppConfiguration!
    private var protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator!
    private var defaultsSuiteName: String!

    override func setUp() async throws {
        try await super.setUp()
        stack = await TestHelpers.makeServiceStack()
        defaultsSuiteName = "com.cypherair.tests.encryptscreen.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        config = AppConfiguration(defaults: defaults)
        protectedOrdinarySettings = ProtectedOrdinarySettingsCoordinator(
            persistence: InMemoryOrdinarySettingsStore()
        )
        protectedOrdinarySettings.loadFromUngatedEphemeralPersistence()
    }

    override func tearDown() {
        if let defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?
                .removePersistentDomain(forName: defaultsSuiteName)
        }
        stack.cleanup()
        stack = nil
        config = nil
        protectedOrdinarySettings = nil
        defaultsSuiteName = nil
        super.tearDown()
    }

    @MainActor
    func test_handleAppear_preservesCurrentPlaintextAndRecipients_butResetsSigningState() async throws {
        let signerIdentity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Signer"
        )
        let recipientIdentity = try await TestHelpers.generateModernHighKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)

        var configuration = EncryptView.Configuration()
        configuration.prefilledPlaintext = "Prefilled message"
        configuration.initialRecipientContactIds = [recipientContactId]
        configuration.signingPolicy = .initial(false)
        configuration.encryptToSelfPolicy = .initial(true)

        let model = makeModel(configuration: configuration)

        model.handleAppear()

        XCTAssertEqual(model.plaintext, "Prefilled message")
        XCTAssertEqual(model.selectedRecipients, [recipientContactId])
        XCTAssertEqual(model.signerFingerprint, signerIdentity.fingerprint)
        XCTAssertEqual(model.encryptToSelfFingerprint, signerIdentity.fingerprint)
        XCTAssertFalse(model.signMessage)
        XCTAssertEqual(model.encryptToSelf, true)

        model.plaintext = "User edited plaintext"
        model.selectedRecipients = ["override"]
        model.signerFingerprint = "override"
        model.encryptToSelfFingerprint = "override"
        model.signMessage = true
        model.encryptToSelf = false

        model.handleAppear()

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertEqual(model.selectedRecipients, ["override"])
        XCTAssertEqual(model.signerFingerprint, signerIdentity.fingerprint)
        XCTAssertEqual(model.encryptToSelfFingerprint, signerIdentity.fingerprint)
        XCTAssertFalse(model.signMessage)
        XCTAssertEqual(model.encryptToSelf, true)
    }

    @MainActor
    func test_updateConfiguration_updatesTutorialState_withoutOverwritingEditedPlaintext() async throws {
        let signerIdentity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Signer"
        )
        let recipientIdentity = try await TestHelpers.generateModernHighKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)

        let model = makeModel()
        model.plaintext = "User edited plaintext"
        model.selectedRecipients = ["manual-recipient"]
        model.signerFingerprint = "manual-signer"
        model.encryptToSelfFingerprint = "manual-self"
        model.signMessage = true
        model.encryptToSelf = false

        var configuration = EncryptView.Configuration()
        configuration.prefilledPlaintext = "Prefilled message"
        configuration.initialRecipientContactIds = [recipientContactId]
        configuration.initialSignerFingerprint = signerIdentity.fingerprint
        configuration.signingPolicy = .initial(false)
        configuration.encryptToSelfPolicy = .initial(true)
        configuration.allowsResultExport = false

        model.updateConfiguration(configuration)

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertEqual(model.selectedRecipients, [recipientContactId])
        XCTAssertEqual(model.signerFingerprint, signerIdentity.fingerprint)
        XCTAssertEqual(model.encryptToSelfFingerprint, signerIdentity.fingerprint)
        XCTAssertFalse(model.signMessage)
        XCTAssertEqual(model.encryptToSelf, true)
        XCTAssertFalse(model.configuration.allowsResultExport)
    }

    @MainActor
    func test_updateConfiguration_clearsTutorialRecipientSeed_whenConfigurationBecomesInactive() async throws {
        let recipientIdentity = try await TestHelpers.generateModernHighKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)

        let model = makeModel()
        model.plaintext = "User edited plaintext"

        var activeConfiguration = EncryptView.Configuration()
        activeConfiguration.prefilledPlaintext = "Prefilled message"
        activeConfiguration.initialRecipientContactIds = [recipientContactId]

        model.updateConfiguration(activeConfiguration)

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertEqual(model.selectedRecipients, [recipientContactId])

        model.updateConfiguration(.default)

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertTrue(model.selectedRecipients.isEmpty)
    }

    @MainActor
    func test_initialRecipientContactIdsFiltersStaleIdsWhenContactsAreAvailable() async throws {
        let recipientIdentity = try await TestHelpers.generateModernHighKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientContactIds = ["stale-contact-id", recipientContactId]
        let model = makeModel(configuration: configuration)

        model.handleAppear()

        XCTAssertEqual(model.selectedRecipients, [recipientContactId])
    }

    @MainActor
    func test_handleAppear_preservesInitialContactIdsWhenContactsAreLocked() async throws {
        let recipientIdentity = try await TestHelpers.generateModernHighKey(
            service: stack.keyManagement,
            name: "Delayed Recipient"
        )
        let delayed = try await makeLockedProtectedContactServiceSeeded(with: recipientIdentity)
        defer { try? FileManager.default.removeItem(at: delayed.directory) }

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientContactIds = [delayed.contactId]
        let model = makeModel(
            contactService: delayed.service,
            configuration: configuration
        )

        model.handleAppear()

        XCTAssertEqual(model.selectedRecipients, [delayed.contactId])
    }

    @MainActor
    func test_encryptText_usesCallbackCapturedAtOperationStart_whenConfigurationChangesMidFlight() async throws {
        let recipientIdentity = try await TestHelpers.generateModernHighKey(
            service: stack.keyManagement,
            name: "Callback Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)
        let gate = EncryptOperationGate()
        var firstCallbackCiphertext: Data?
        var secondCallbackCiphertext: Data?

        var configuration = EncryptView.Configuration()
        configuration.onEncrypted = { firstCallbackCiphertext = $0 }

        let model = makeModel(
            configuration: configuration,
            textEncryptionAction: { _, _, _, _, _ in
                await gate.suspend()
                return Data("ciphertext".utf8)
            }
        )
        model.plaintext = "Secret"
        model.selectedRecipients = [recipientContactId]

        model.encryptText()

        await waitUntil("text encryption to suspend") {
            guard model.operation.isRunning else {
                return false
            }
            return await gate.isSuspended()
        }

        configuration.onEncrypted = { secondCallbackCiphertext = $0 }
        configuration.allowsResultExport = false
        model.updateConfiguration(configuration)

        await gate.resume()

        await waitUntil("text encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(firstCallbackCiphertext, Data("ciphertext".utf8))
        XCTAssertNil(secondCallbackCiphertext)
    }

    @MainActor
    func test_requestEncrypt_withUnverifiedRecipients_showsWarningUntilConfirmed() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateModernHighKey(
            service: stack.keyManagement,
            name: "Unverified Recipient"
        )
        try stack.contactService.importContact(
            publicKeyData: recipientIdentity.publicKeyData,
            verificationState: .unverified
        )
        let recipientContactId = try XCTUnwrap(
            stack.contactService.contactId(forFingerprint: recipientIdentity.fingerprint)
        )

        var encryptCount = 0
        var callbackCiphertext: Data?
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientContactIds = [recipientContactId]
        configuration.onEncrypted = { callbackCiphertext = $0 }

        let model = makeModel(
            configuration: configuration,
            textEncryptionAction: { _, _, _, _, _ in
                encryptCount += 1
                return Data("ciphertext".utf8)
            }
        )
        model.plaintext = "Secret"
        model.handleAppear()

        model.requestEncrypt()

        XCTAssertTrue(model.showUnverifiedRecipientsWarning)
        XCTAssertEqual(encryptCount, 0)
        XCTAssertNil(model.ciphertext)

        model.confirmEncryptWithUnverifiedRecipients()

        await waitUntil("confirmed encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertFalse(model.showUnverifiedRecipientsWarning)
        XCTAssertEqual(encryptCount, 1)
        XCTAssertEqual(model.ciphertext, Data("ciphertext".utf8))
        XCTAssertEqual(callbackCiphertext, Data("ciphertext".utf8))
    }

    @MainActor
    func test_requestEncrypt_verifiedPreferredWithUnverifiedHistoricalKeyDoesNotWarn() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptPreferredVerification")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let preferred = try stack.engine.generateKey(
            name: "Preferred Recipient",
            email: "preferred-recipient@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let historical = try stack.engine.generateKey(
            name: "Historical Recipient",
            email: "historical-recipient@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )
        try opened.service.importContact(publicKeyData: preferred.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: historical.publicKeyData, verificationState: .unverified)
        let targetContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: preferred.fingerprint))
        let sourceContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: historical.fingerprint))
        _ = try opened.service.mergeContact(sourceContactId: sourceContactId, into: targetContactId)
        try opened.service.setKeyUsageState(.historical, fingerprint: historical.fingerprint)

        let mergedIdentity = try XCTUnwrap(opened.service.availableContactIdentity(forContactID: targetContactId))
        XCTAssertTrue(mergedIdentity.hasUnverifiedKeys)

        var encryptCount = 0
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientContactIds = [targetContactId]
        let encryptionService = EncryptionService(
            keyManagement: stack.keyManagement,
            contactService: opened.service,
            textEncryptor: stack.textEncryptor,
            fileEncryptor: stack.fileEncryptor
        )
        let model = EncryptScreenModel(
            encryptionService: encryptionService,
            keyManagement: stack.keyManagement,
            contactService: opened.service,
            config: config,
            protectedOrdinarySettings: protectedOrdinarySettings,
            configuration: configuration,
            textEncryptionAction: { _, _, _, _, _ in
                encryptCount += 1
                return Data("ciphertext".utf8)
            }
        )
        model.plaintext = "Secret"
        model.handleAppear()

        XCTAssertTrue(model.selectedUnverifiedContacts.isEmpty)
        model.requestEncrypt()

        await waitUntil("preferred-only encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertFalse(model.showUnverifiedRecipientsWarning)
        XCTAssertEqual(encryptCount, 1)
        XCTAssertEqual(model.ciphertext, Data("ciphertext".utf8))
    }

    @MainActor
    func test_tagSelectionAddsDedupesSupportsManualUncheckAndClearAll() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagSelection")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let first = try stack.engine.generateKey(
            name: "Tag First",
            email: "encrypt-tag-first@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let second = try stack.engine.generateKey(
            name: "Tag Second",
            email: "encrypt-tag-second@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )
        try opened.service.importContact(publicKeyData: first.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: second.publicKeyData, verificationState: .verified)
        let firstContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: first.fingerprint))
        let secondContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: second.fingerprint))
        let tag = try opened.service.addTag(named: "Team", toContactId: firstContactId)
        _ = try opened.service.addTag(named: "Team", toContactId: secondContactId)

        var capturedRecipients: [String] = []
        let model = makeModel(
            contactService: opened.service,
            textEncryptionAction: { _, recipients, _, _, _ in
                capturedRecipients = recipients
                return Data("ciphertext".utf8)
            }
        )
        model.plaintext = "Secret"
        // Pre-select one member, then filter by the tag and add all shown — the
        // second member joins and the pre-selected one is not duplicated.
        model.selectedRecipients = [firstContactId]
        model.toggleRecipientTagFilter(tag.tagId)
        model.addAllVisibleRecipients()
        XCTAssertEqual(Set(model.effectiveRecipientContactIds), Set([firstContactId, secondContactId]))

        // Search narrows the visible candidates without dropping the selection.
        model.recipientSearchText = "Second"
        XCTAssertEqual(model.filteredRecipientContacts.map(\.contactId), [secondContactId])

        // Manual uncheck removes one; re-adding the visible set restores it.
        model.recipientSearchText = ""
        model.toggleRecipient(secondContactId, isOn: false)
        XCTAssertEqual(model.effectiveRecipientContactIds, [firstContactId])
        model.addAllVisibleRecipients()
        XCTAssertEqual(Set(model.effectiveRecipientContactIds), Set([firstContactId, secondContactId]))

        model.requestEncrypt()
        await waitUntil("tag-selection encryption to finish") {
            model.operation.isRunning == false
        }
        XCTAssertEqual(Set(capturedRecipients), Set([firstContactId, secondContactId]))

        model.clearRecipients()
        XCTAssertTrue(model.selectedRecipients.isEmpty)
        XCTAssertTrue(model.effectiveRecipientContactIds.isEmpty)
    }

    @MainActor
    func test_tagFilterExcludesContactsWithoutPreferredKeyFromCandidates() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagSelectionSkip")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let selectable = try stack.engine.generateKey(
            name: "Selectable Tag Member",
            email: "selectable-tag-member@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let missingPreferred = try stack.engine.generateKey(
            name: "Missing Preferred Tag Member",
            email: "missing-preferred-tag@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )
        try opened.service.importContact(publicKeyData: selectable.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: missingPreferred.publicKeyData, verificationState: .verified)
        let selectableContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: selectable.fingerprint))
        let missingPreferredContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: missingPreferred.fingerprint))
        let tag = try opened.service.addTag(named: "Partial Team", toContactId: selectableContactId)
        _ = try opened.service.addTag(named: "Partial Team", toContactId: missingPreferredContactId)

        var snapshot = try opened.service.currentContactsDomainSnapshot()
        for index in snapshot.keyRecords.indices
            where snapshot.keyRecords[index].contactId == missingPreferredContactId {
            snapshot.keyRecords[index].usageState = .historical
        }
        try opened.harness.store.replaceSnapshot(snapshot)
        try await opened.service.relockProtectedData()
        let reopened = await makeReopenedProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )

        let model = makeModel(contactService: reopened.service)
        model.toggleRecipientTagFilter(tag.tagId)

        // The contact without a preferred encryption key is not a candidate, so
        // "Select All Shown" adds only the selectable member.
        XCTAssertEqual(model.filteredRecipientContacts.map(\.contactId), [selectableContactId])
        model.addAllVisibleRecipients()
        XCTAssertEqual(model.effectiveRecipientContactIds, [selectableContactId])
    }

    @MainActor
    func test_filteredRecipientContacts_appliesMultiSelectTagFilter() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptRecipientFilterTag")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let tagged = try stack.engine.generateKey(
            name: "Tagged Member",
            email: "filter-tagged@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let untagged = try stack.engine.generateKey(
            name: "Untagged Member",
            email: "filter-untagged@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: tagged.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: untagged.publicKeyData, verificationState: .verified)
        let taggedContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: tagged.fingerprint))
        let untaggedContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: untagged.fingerprint))
        let tag = try opened.service.addTag(named: "Filtered", toContactId: taggedContactId)

        let model = makeModel(contactService: opened.service)

        XCTAssertEqual(
            Set(model.filteredRecipientContacts.map(\.contactId)),
            Set([taggedContactId, untaggedContactId])
        )

        // Selecting a tag narrows the candidates to that tag's members.
        model.toggleRecipientTagFilter(tag.tagId)
        XCTAssertEqual(model.filteredRecipientContacts.map(\.contactId), [taggedContactId])

        // Toggling the same tag off restores the full candidate list.
        model.toggleRecipientTagFilter(tag.tagId)
        XCTAssertEqual(
            Set(model.filteredRecipientContacts.map(\.contactId)),
            Set([taggedContactId, untaggedContactId])
        )
    }

    @MainActor
    func test_recipientTagFilter_togglesAndResetsOnContentClearButNotOnClearRecipients() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagFilterToggle")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let member = try stack.engine.generateKey(
            name: "Filter Member",
            email: "filter-toggle-member@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: member.publicKeyData, verificationState: .verified)
        let memberContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: member.fingerprint))
        let tag = try opened.service.addTag(named: "Toggle", toContactId: memberContactId)

        let model = makeModel(contactService: opened.service)

        model.toggleRecipientTagFilter(tag.tagId)
        XCTAssertEqual(model.selectedRecipientTagFilterIds, [tag.tagId])

        model.toggleRecipientTagFilter(tag.tagId)
        XCTAssertTrue(model.selectedRecipientTagFilterIds.isEmpty)

        // Clearing the selected recipients must NOT reset the browse filter.
        model.toggleRecipientTagFilter(tag.tagId)
        model.clearRecipients()
        XCTAssertEqual(model.selectedRecipientTagFilterIds, [tag.tagId])

        // A content-clear (e.g. app backgrounding) resets the browse filter.
        model.handleContentClearGenerationChange()
        XCTAssertTrue(model.selectedRecipientTagFilterIds.isEmpty)
    }

    @MainActor
    func test_selectedRecipientSummaries_resolvesSelectedIdsAndDropsStale() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptSelectedSummaries")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let first = try stack.engine.generateKey(
            name: "Summary First",
            email: "summary-first@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let second = try stack.engine.generateKey(
            name: "Summary Second",
            email: "summary-second@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: first.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: second.publicKeyData, verificationState: .verified)
        let firstContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: first.fingerprint))
        let secondContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: second.fingerprint))

        let model = makeModel(contactService: opened.service)
        model.selectedRecipients = [firstContactId, secondContactId, "stale-contact-id"]

        let summaryIds = model.selectedRecipientSummaries.map(\.contactId)
        XCTAssertEqual(Set(summaryIds), Set([firstContactId, secondContactId]))
        XCTAssertFalse(summaryIds.contains("stale-contact-id"))
        // Resolved summaries follow presentation order (by display name: "Summary
        // First" before "Summary Second") with the stale id dropped. Asserted against
        // an explicit expected order rather than effectiveRecipientContactIds, which
        // would be self-referential.
        XCTAssertEqual(summaryIds, [firstContactId, secondContactId])
    }

    @MainActor
    func test_resultQuantumSafety_derivesFromArtifactAndSurvivesSelectionChanges() async throws {
        // The quantum-safe claim describes the
        // produced message — its actual PKESK algorithms — never the live
        // selection, which can change after encryption without re-encrypting.
        let signer = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptQuantumSafety")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let pqOne = try stack.engine.generateKey(
            name: "PQ One",
            email: "pq-one@example.invalid",
            expirySeconds: nil,
            suite: .mlDsa65Ed25519MlKem768X25519
        )
        let classical = try stack.engine.generateKey(
            name: "Classic Recipient",
            email: "classic-recipient@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: pqOne.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: classical.publicKeyData, verificationState: .verified)
        let pqOneId = try XCTUnwrap(opened.service.contactId(forFingerprint: pqOne.fingerprint))
        let classicalId = try XCTUnwrap(opened.service.contactId(forFingerprint: classical.fingerprint))

        let model = makeModel(contactService: opened.service)
        model.encryptToSelf = false
        model.signMessage = false
        model.signerFingerprint = nil
        model.plaintext = "artifact-derived quantum safety"

        // No result yet: no claim in either direction.
        XCTAssertFalse(model.showsQuantumSafeBadge)
        XCTAssertFalse(model.showsMixedQuantumSafetyCaption)

        // PQ-only artifact: the badge, from the real PKESK algorithms.
        model.selectedRecipients = [pqOneId]
        model.requestEncrypt()
        await waitUntil("PQ-only encryption to finish") {
            model.operation.isRunning == false
        }
        XCTAssertNotNil(model.ciphertext)
        XCTAssertTrue(model.showsQuantumSafeBadge)
        XCTAssertFalse(model.showsMixedQuantumSafetyCaption)

        // Verifier finding #1 regression: mutating the live selection after
        // encryption must NOT change the displayed result's claim.
        model.selectedRecipients = [pqOneId, classicalId]
        XCTAssertTrue(model.showsQuantumSafeBadge)
        XCTAssertFalse(model.showsMixedQuantumSafetyCaption)

        // Re-encrypting with the mixed selection reclassifies from the new
        // artifact: caption, never the badge.
        model.requestEncrypt()
        await waitUntil("mixed encryption to finish") {
            model.operation.isRunning == false
        }
        XCTAssertFalse(model.showsQuantumSafeBadge)
        XCTAssertTrue(model.showsMixedQuantumSafetyCaption)

        // Classical-only artifact: neither.
        model.selectedRecipients = [classicalId]
        model.requestEncrypt()
        await waitUntil("classical encryption to finish") {
            model.operation.isRunning == false
        }
        XCTAssertFalse(model.showsQuantumSafeBadge)
        XCTAssertFalse(model.showsMixedQuantumSafetyCaption)

        // Encrypt-to-self with a classical own key: the artifact itself
        // carries a classical self-PKESK, so an all-PQ selection is mixed.
        model.selectedRecipients = [pqOneId]
        model.encryptToSelf = true
        model.encryptToSelfFingerprint = signer.fingerprint
        model.requestEncrypt()
        await waitUntil("encrypt-to-self encryption to finish") {
            model.operation.isRunning == false
        }
        XCTAssertFalse(model.showsQuantumSafeBadge)
        XCTAssertTrue(model.showsMixedQuantumSafetyCaption)

        // Clearing the transient input clears the claim with the result.
        model.clearTransientInput()
        XCTAssertNil(model.resultQuantumSafety)
        XCTAssertFalse(model.showsQuantumSafeBadge)
        XCTAssertFalse(model.showsMixedQuantumSafetyCaption)
    }

    @MainActor
    func test_effectiveRecipientContactIds_dropStaleWhenAvailableAndGateEncryptButton() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptResolvedSelection")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let valid = try stack.engine.generateKey(
            name: "Available Recipient",
            email: "available-recipient@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: valid.publicKeyData, verificationState: .verified)
        let validContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: valid.fingerprint))

        let model = makeModel(contactService: opened.service)

        model.selectedRecipients = [validContactId]
        XCTAssertEqual(model.effectiveRecipientContactIds, [validContactId])

        // A live contact plus a stale id (its contact was deleted): the stale id is
        // dropped from the resolved set while contacts are available.
        model.selectedRecipients = [validContactId, "stale-contact-id"]
        XCTAssertEqual(model.effectiveRecipientContactIds, [validContactId])

        // A selection made only of stale ids resolves to empty and disables Encrypt,
        // instead of leaving the button enabled against a phantom recipient.
        model.selectedRecipients = ["stale-contact-id"]
        XCTAssertTrue(model.effectiveRecipientContactIds.isEmpty)
        XCTAssertTrue(model.encryptButtonDisabled)
    }

    @MainActor
    func test_staleSelectedRecipientGatesButtonUntilRemoved() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptStaleGate")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let valid = try stack.engine.generateKey(
            name: "Valid Recipient",
            email: "valid-recipient@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: valid.publicKeyData, verificationState: .verified)
        let validContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: valid.fingerprint))

        let model = makeModel(contactService: opened.service)
        model.plaintext = "Secret"
        model.encryptToSelf = false
        model.selectedRecipients = [validContactId, "stale-contact-id"]

        // The displayed count stays honest (valid only), but a stale selected id keeps
        // the button disabled — it is never enabled-yet-erroring.
        XCTAssertTrue(model.hasStaleSelectedRecipients)
        XCTAssertEqual(model.effectiveRecipientContactIds, [validContactId])
        XCTAssertTrue(model.encryptButtonDisabled)

        model.removeStaleRecipients()

        // Removing the unavailable recipient reconciles the selection and enables Encrypt.
        XCTAssertEqual(model.selectedRecipients, [validContactId])
        XCTAssertFalse(model.hasStaleSelectedRecipients)
        XCTAssertFalse(model.encryptButtonDisabled)
    }

    @MainActor
    func test_togglingRecipientDoesNotReorderFilteredList() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptStableList")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let alpha = try stack.engine.generateKey(
            name: "Stable Alpha",
            email: "stable-alpha@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let bravo = try stack.engine.generateKey(
            name: "Stable Bravo",
            email: "stable-bravo@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let charlie = try stack.engine.generateKey(
            name: "Stable Charlie",
            email: "stable-charlie@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        for key in [alpha, bravo, charlie] {
            try opened.service.importContact(publicKeyData: key.publicKeyData, verificationState: .verified)
        }
        let bravoContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: bravo.fingerprint))

        let model = makeModel(contactService: opened.service)
        let order = model.filteredRecipientContacts.map(\.contactId)
        XCTAssertEqual(order.count, 3)

        // Selecting the middle recipient must not reorder the list (spatial stability).
        model.toggleRecipient(bravoContactId, isOn: true)
        XCTAssertEqual(model.filteredRecipientContacts.map(\.contactId), order)

        // Deselecting must also leave the order untouched.
        model.toggleRecipient(bravoContactId, isOn: false)
        XCTAssertEqual(model.filteredRecipientContacts.map(\.contactId), order)
    }

    @MainActor
    func test_recipientTagFilters_excludesTagsWithNoEncryptableMember() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptEncryptableTagFilter")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let encryptable = try stack.engine.generateKey(
            name: "Active Member",
            email: "active-tag-member@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let nonEncryptable = try stack.engine.generateKey(
            name: "Inactive Member",
            email: "inactive-tag-member@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: encryptable.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: nonEncryptable.publicKeyData, verificationState: .verified)
        let encryptableContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: encryptable.fingerprint))
        let nonEncryptableContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: nonEncryptable.fingerprint))
        let activeTag = try opened.service.addTag(named: "Active", toContactId: encryptableContactId)
        let doomedTag = try opened.service.addTag(named: "Doomed", toContactId: nonEncryptableContactId)

        // Strip the second contact of a preferred (encryptable) key so it stops being a
        // recipient candidate, then relock/reopen to pick up the edited snapshot.
        var snapshot = try opened.service.currentContactsDomainSnapshot()
        for index in snapshot.keyRecords.indices
            where snapshot.keyRecords[index].contactId == nonEncryptableContactId {
            snapshot.keyRecords[index].usageState = .historical
        }
        try opened.harness.store.replaceSnapshot(snapshot)
        try await opened.service.relockProtectedData()
        let reopened = await makeReopenedProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )

        let model = makeModel(contactService: reopened.service)
        let filterTagIds = Set(model.recipientTagFilters.map(\.tagId))
        // The tag whose only member can be encrypted to is offered; the tag whose only
        // member is no longer encryptable is not (every chip resolves to ≥1 recipient).
        XCTAssertTrue(filterTagIds.contains(activeTag.tagId))
        XCTAssertFalse(filterTagIds.contains(doomedTag.tagId))
    }

    @MainActor
    func test_selectAllShownSelectsEveryVisibleRecipient() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptSelectAllShown")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let only = try stack.engine.generateKey(
            name: "Solo Recipient",
            email: "solo-recipient@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: only.publicKeyData, verificationState: .verified)
        let onlyContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: only.fingerprint))

        let model = makeModel(contactService: opened.service)
        // A single visible candidate is still covered by "Select All Shown".
        XCTAssertEqual(model.filteredRecipientContacts.map(\.contactId), [onlyContactId])
        model.addAllVisibleRecipients()
        XCTAssertEqual(model.effectiveRecipientContactIds, [onlyContactId])
    }

    @MainActor
    func test_hiddenSelectedRecipientCount_surfacesAndRevealsFilteredSelections() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptHiddenSelected")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let shown = try stack.engine.generateKey(
            name: "Shown Recipient",
            email: "shown-recipient@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let hidden = try stack.engine.generateKey(
            name: "Other Recipient",
            email: "other-recipient@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: shown.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: hidden.publicKeyData, verificationState: .verified)
        let shownContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: shown.fingerprint))
        let hiddenContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: hidden.fingerprint))
        let tag = try opened.service.addTag(named: "Shown", toContactId: shownContactId)

        let model = makeModel(contactService: opened.service)
        model.selectedRecipients = [shownContactId, hiddenContactId]

        // No filter: every selected recipient appears in the list, nothing is hidden.
        XCTAssertEqual(model.hiddenSelectedRecipientCount, 0)

        // A tag filter matching only one selected recipient hides the other from the
        // list — surfaced via the count.
        model.toggleRecipientTagFilter(tag.tagId)
        XCTAssertEqual(model.filteredRecipientContacts.map(\.contactId), [shownContactId])
        XCTAssertEqual(model.hiddenSelectedRecipientCount, 1)

        // The search path hides it too.
        model.toggleRecipientTagFilter(tag.tagId)
        model.recipientSearchText = "Shown"
        XCTAssertEqual(model.filteredRecipientContacts.map(\.contactId), [shownContactId])
        XCTAssertEqual(model.hiddenSelectedRecipientCount, 1)

        // "Show All" clears search + tag filters but keeps the selection intact.
        model.toggleRecipientTagFilter(tag.tagId)
        XCTAssertEqual(model.selectedRecipientTagFilterIds, [tag.tagId])
        model.clearRecipientSearchAndFilters()
        XCTAssertTrue(model.recipientSearchText.isEmpty)
        XCTAssertTrue(model.selectedRecipientTagFilterIds.isEmpty)
        XCTAssertEqual(model.hiddenSelectedRecipientCount, 0)
        XCTAssertEqual(model.selectedRecipients, [shownContactId, hiddenContactId])
    }

    @MainActor
    func test_recipientTagFilter_prunesDeletedTagFromActiveFilter() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagFilterPrune")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let member = try stack.engine.generateKey(
            name: "Prune Member",
            email: "prune-member@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: member.publicKeyData, verificationState: .verified)
        let memberContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: member.fingerprint))
        let tag = try opened.service.addTag(named: "Doomed", toContactId: memberContactId)

        let model = makeModel(contactService: opened.service)
        model.toggleRecipientTagFilter(tag.tagId)
        XCTAssertEqual(model.selectedRecipientTagFilterIds, [tag.tagId])

        // Deleting the tag removes it from the available tags; the active filter
        // prunes the now-missing tag on read instead of stranding an empty list.
        try opened.service.deleteTag(tagId: tag.tagId)
        XCTAssertTrue(model.recipientTagFilters.allSatisfy { $0.tagId != tag.tagId })
        XCTAssertTrue(model.selectedRecipientTagFilterIds.isEmpty)
    }

    @MainActor
    func test_addAllVisibleRecipients_doesNotAddSearchHiddenRecipients() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptAddAllVisible")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let visible = try stack.engine.generateKey(
            name: "Visible Alpha",
            email: "visible-alpha@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let hidden = try stack.engine.generateKey(
            name: "Hidden Beta",
            email: "hidden-beta@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: visible.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: hidden.publicKeyData, verificationState: .verified)
        let visibleContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: visible.fingerprint))
        let hiddenContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: hidden.fingerprint))
        let tag = try opened.service.addTag(named: "Mixed", toContactId: visibleContactId)
        _ = try opened.service.addTag(named: "Mixed", toContactId: hiddenContactId)

        let model = makeModel(contactService: opened.service)
        model.toggleRecipientTagFilter(tag.tagId)
        // A search term that matches only the visible member.
        model.recipientSearchText = "Alpha"
        XCTAssertEqual(model.addableRecipientContacts.map(\.contactId), [visibleContactId])

        model.addAllVisibleRecipients()

        // Only the visible candidate is added; the search-hidden member is not.
        XCTAssertEqual(model.effectiveRecipientContactIds, [visibleContactId])
        XCTAssertFalse(model.selectedRecipients.contains(hiddenContactId))
    }

    @MainActor
    func test_requestEncryptFailsAndClearsStaleDirectRecipientSelection() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptStaleDirectRecipient")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let retained = try stack.engine.generateKey(
            name: "Retained Direct Recipient",
            email: "retained-direct@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let removed = try stack.engine.generateKey(
            name: "Removed Direct Recipient",
            email: "removed-direct@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )
        try opened.service.importContact(publicKeyData: retained.publicKeyData, verificationState: .verified)
        try opened.service.importContact(publicKeyData: removed.publicKeyData, verificationState: .verified)
        let retainedContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: retained.fingerprint))
        let removedContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: removed.fingerprint))

        var didEncrypt = false
        let model = makeModel(
            contactService: opened.service,
            textEncryptionAction: { _, _, _, _, _ in
                didEncrypt = true
                return Data("ciphertext".utf8)
            }
        )
        model.plaintext = "Secret"
        model.selectedRecipients = [retainedContactId, removedContactId]

        try opened.service.removeContactIdentity(contactId: removedContactId)
        model.requestEncrypt()

        XCTAssertFalse(didEncrypt)
        XCTAssertTrue(model.operation.isShowingError)
        XCTAssertEqual(model.selectedRecipients, [retainedContactId])
    }

    @MainActor
    func test_tagSelectionKeepsExistingUnverifiedRecipientWarning() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagUnverifiedWarning")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let unverified = try stack.engine.generateKey(
            name: "Unverified Tag Member",
            email: "unverified-tag-member@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: unverified.publicKeyData, verificationState: .unverified)
        let unverifiedContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: unverified.fingerprint))
        let tag = try opened.service.addTag(named: "Warning Team", toContactId: unverifiedContactId)

        var didEncrypt = false
        let model = makeModel(
            contactService: opened.service,
            textEncryptionAction: { _, _, _, _, _ in
                didEncrypt = true
                return Data("ciphertext".utf8)
            }
        )
        model.plaintext = "Secret"
        model.toggleRecipientTagFilter(tag.tagId)
        model.addAllVisibleRecipients()

        XCTAssertEqual(model.selectedUnverifiedContacts.map(\.contactId), [unverifiedContactId])

        model.requestEncrypt()
        XCTAssertFalse(didEncrypt)
        XCTAssertTrue(model.showUnverifiedRecipientsWarning)
    }

    @MainActor
    func test_confirmEncryptRevalidatesTagSelectedRecipientsAfterUnverifiedWarning() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagConfirmRevalidate")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory)
        }
        let unverified = try stack.engine.generateKey(
            name: "Warning Removed Tag Member",
            email: "warning-removed-tag-member@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        try opened.service.importContact(publicKeyData: unverified.publicKeyData, verificationState: .unverified)
        let unverifiedContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: unverified.fingerprint))
        let tag = try opened.service.addTag(named: "Warning Removed Team", toContactId: unverifiedContactId)

        var didEncrypt = false
        let model = makeModel(
            contactService: opened.service,
            textEncryptionAction: { _, _, _, _, _ in
                didEncrypt = true
                return Data("ciphertext".utf8)
            }
        )
        model.plaintext = "Secret"
        model.toggleRecipientTagFilter(tag.tagId)
        model.addAllVisibleRecipients()

        model.requestEncrypt()
        XCTAssertTrue(model.showUnverifiedRecipientsWarning)

        try opened.service.removeContactIdentity(contactId: unverifiedContactId)
        model.confirmEncryptWithUnverifiedRecipients()

        XCTAssertFalse(didEncrypt)
        XCTAssertFalse(model.showUnverifiedRecipientsWarning)
        XCTAssertTrue(model.operation.isShowingError)
        XCTAssertFalse(model.selectedRecipients.contains(unverifiedContactId))
    }

    @MainActor
    func test_encryptText_routesClipboardAndExportThroughInterceptionPolicy() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateModernHighKey(
            service: stack.keyManagement,
            name: "Verified Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)

        var interceptedClipboard: String?
        var interceptedExportFilename: String?
        var callbackCiphertext: Data?
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientContactIds = [recipientContactId]
        configuration.outputInterceptionPolicy = OutputInterceptionPolicy(
            interceptClipboardCopy: { string, _, kind in
                XCTAssertEqual(kind, .ciphertext)
                interceptedClipboard = string
                return true
            },
            interceptDataExport: { _, filename, kind in
                XCTAssertEqual(kind, .ciphertext)
                interceptedExportFilename = filename
                return true
            }
        )
        configuration.onEncrypted = { callbackCiphertext = $0 }

        let model = makeModel(
            configuration: configuration,
            textEncryptionAction: { _, _, _, _, _ in
                Data("ciphertext-body".utf8)
            }
        )
        model.plaintext = "Hello"
        model.handleAppear()

        model.requestEncrypt()

        await waitUntil("text encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(model.ciphertextString, "ciphertext-body")
        XCTAssertEqual(callbackCiphertext, Data("ciphertext-body".utf8))

        model.copyCiphertextToClipboard()
        XCTAssertEqual(interceptedClipboard, "ciphertext-body")
        XCTAssertFalse(model.operation.isShowingClipboardNotice)

        model.exportCiphertext()
        XCTAssertEqual(interceptedExportFilename, "encrypted.asc")
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_contentClearDuringTextEncryptionSuppressesLateCiphertextAndCallback() async throws {
        let recipientIdentity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Privacy Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)
        let gate = EncryptOperationGate()
        var callbackCiphertext: Data?

        var configuration = EncryptView.Configuration()
        configuration.onEncrypted = { callbackCiphertext = $0 }

        let model = makeModel(
            configuration: configuration,
            textEncryptionAction: { _, _, _, _, _ in
                await gate.suspend()
                return Data("late-ciphertext".utf8)
            }
        )
        model.plaintext = "Sensitive plaintext"
        model.selectedRecipients = [recipientContactId]

        model.encryptText()

        await waitUntil("text encryption to suspend for content clear") {
            guard model.operation.isRunning else {
                return false
            }
            return await gate.isSuspended()
        }

        model.handleContentClearGenerationChange()
        XCTAssertFalse(model.operation.isRunning)
        XCTAssertNil(model.ciphertext)

        await gate.resume()
        await settleAsyncWork()

        XCTAssertNil(model.ciphertext)
        XCTAssertNil(callbackCiphertext)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_encryptFile_handlesSelection_andRoutesFileExportThroughInterceptionPolicy() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)

        let inputURL = try makeTemporaryFile(
            named: "message.txt",
            contents: Data("plaintext".utf8)
        )
        let outputURL = try makeTemporaryFile(
            named: "message.txt.gpg",
            contents: Data("ciphertext".utf8)
        )
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        var interceptedURL: URL?
        var interceptedFilename: String?
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientContactIds = [recipientContactId]
        configuration.outputInterceptionPolicy = OutputInterceptionPolicy(
            interceptFileExport: { url, filename, kind in
                XCTAssertEqual(kind, .ciphertext)
                interceptedURL = url
                interceptedFilename = filename
                return true
            }
        )

        let model = makeModel(
            configuration: configuration,
            fileEncryptionAction: { _ in TemporaryFileOutput(fileURL: outputURL) }
        )
        model.encryptMode = .file
        model.handleAppear()
        model.handleImportedFile(inputURL)

        model.encryptFile()

        await waitUntil("file encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(model.selectedFileName, inputURL.lastPathComponent)
        XCTAssertEqual(model.encryptedFileURL, outputURL)

        model.exportEncryptedFile()

        XCTAssertEqual(interceptedURL, outputURL)
        XCTAssertEqual(interceptedFilename, "\(inputURL.lastPathComponent).gpg")
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_encryptFile_cancellation_clearsProgress_andDoesNotPublishOutputURL() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)

        let gate = EncryptOperationGate()
        var capturedProgress: FileProgressReporter?
        let operation = OperationController(progressFactory: {
            let reporter = FileProgressReporter()
            capturedProgress = reporter
            return reporter
        })
        let inputURL = try makeTemporaryFile(
            named: "cancel.txt",
            contents: Data("cancel".utf8)
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientContactIds = [recipientContactId]

        let model = makeModel(
            configuration: configuration,
            operation: operation,
            fileEncryptionAction: { _ in
                _ = capturedProgress?.onProgress(bytesProcessed: 5, totalBytes: 10)
                await gate.suspend()
                try Task.checkCancellation()
                return TemporaryFileOutput(fileURL: inputURL)
            }
        )
        model.encryptMode = .file
        model.handleAppear()
        model.handleImportedFile(inputURL)

        model.encryptFile()

        await waitUntil("file encryption to suspend") {
            guard model.operation.isRunning, model.operation.progress != nil else {
                return false
            }
            return await gate.isSuspended()
        }

        model.operation.cancel()

        XCTAssertTrue(model.operation.isRunning)
        XCTAssertTrue(model.operation.isCancelling)

        await gate.resume()

        await waitUntil("cancelled file encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.encryptedFileURL)
        XCTAssertNil(model.operation.progress)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_encryptFile_cancellationAfterServiceSuccess_cleansUnpublishedOutput() async throws {
        _ = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)
        let operation = OperationController()
        let inputURL = try makeTemporaryFile(
            named: "cancel-after-success.txt",
            contents: Data("plaintext".utf8)
        )
        let outputURL = try makeTemporaryFile(
            named: "cancel-after-success.txt.gpg",
            contents: Data("ciphertext".utf8)
        )
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientContactIds = [recipientContactId]
        let model = makeModel(
            configuration: configuration,
            operation: operation,
            fileEncryptionAction: { _ in
                operation.cancel()
                return TemporaryFileOutput(fileURL: outputURL)
            }
        )
        model.encryptMode = .file
        model.handleAppear()
        model.handleImportedFile(inputURL)

        model.encryptFile()

        await waitUntil("cancelled after service success") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.encryptedFileURL)
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_configurationFlags_gateFileImportAndExports() {
        var configuration = EncryptView.Configuration()
        configuration.allowsFileInput = false
        configuration.allowsResultExport = false
        configuration.allowsFileResultExport = false

        let model = makeModel(configuration: configuration)

        model.requestFileImport()
        XCTAssertFalse(model.showFileImporter)

        model.ciphertext = Data("ciphertext".utf8)
        model.exportCiphertext()
        XCTAssertNil(model.exportController.payload)

        model.encryptedFileURL = URL(fileURLWithPath: "/tmp/encrypted.gpg")
        model.exportEncryptedFile()
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_handleFileImporterResult_afterContentClear_ignoresStaleSelection() throws {
        let model = makeModel()
        let fileURL = URL(fileURLWithPath: "/tmp/plaintext.txt")

        model.requestFileImport()
        let token = try XCTUnwrap(model.fileImportRequestToken)
        model.clearTransientInput()
        model.handleFileImporterResult(.success([fileURL]), token: token)

        XCTAssertNil(model.selectedFileURL)
        XCTAssertNil(model.selectedFileName)
    }

    @MainActor
    private func makeModel(
        contactService: ContactService? = nil,
        configuration: EncryptView.Configuration = .default,
        operation: OperationController = OperationController(),
        textEncryptionAction: EncryptScreenModel.TextEncryptionAction? = nil,
        fileEncryptionAction: EncryptScreenModel.FileEncryptionAction? = nil,
        clipboardNoticeDecision: EncryptScreenModel.ClipboardNoticeDecision? = nil,
        clipboardWriter: EncryptScreenModel.ClipboardWriter? = nil
    ) -> EncryptScreenModel {
        let resolvedContactService = contactService ?? stack.contactService
        let resolvedEncryptionService = contactService.map {
            EncryptionService(
                keyManagement: stack.keyManagement,
                contactService: $0,
                textEncryptor: stack.textEncryptor,
                fileEncryptor: stack.fileEncryptor
            )
        } ?? stack.encryptionService
        return EncryptScreenModel(
            encryptionService: resolvedEncryptionService,
            keyManagement: stack.keyManagement,
            contactService: resolvedContactService,
            config: config,
            protectedOrdinarySettings: protectedOrdinarySettings,
            configuration: configuration,
            operation: operation,
            textEncryptionAction: textEncryptionAction,
            fileEncryptionAction: fileEncryptionAction,
            clipboardNoticeDecision: clipboardNoticeDecision,
            clipboardWriter: clipboardWriter
        )
    }

    private func importContactAndResolveContactId(for identity: PGPKeyIdentity) throws -> String {
        _ = try stack.contactService.importContact(publicKeyData: identity.publicKeyData)
        return try XCTUnwrap(stack.contactService.contactId(forFingerprint: identity.fingerprint))
    }

    private func makeLockedProtectedContactServiceSeeded(
        with identity: PGPKeyIdentity
    ) async throws -> (service: ContactService, contactId: String, directory: URL) {
        let opened = try await makeOpenedProtectedContactService(
            prefix: "EncryptDelayedPrefill"
        )
        _ = try opened.service.importContact(publicKeyData: identity.publicKeyData)
        let contactId = try XCTUnwrap(
            opened.service.contactId(forFingerprint: identity.fingerprint)
        )
        let lockedStore = ContactsDomainStore(
            storageRoot: opened.harness.storageRoot,
            registryStore: opened.harness.registryStore,
            domainKeyManager: opened.harness.domainKeyManager,
            currentWrappingRootKey: { opened.harness.wrappingRootKey },
            initialSnapshotProvider: {
                XCTFail("Committed Contacts domain should not recreate its initial snapshot.")
                return ContactsDomainSnapshot.empty()
            }
        )
        let locked = ContactService(
            engine: stack.engine,
            contactsDomainStore: lockedStore
        )
        XCTAssertEqual(locked.contactsAvailability, .locked)
        return (locked, contactId, opened.contactsDirectory)
    }

    private func makeOpenedProtectedContactService(
        prefix: String
    ) async throws -> (
        service: ContactService,
        harness: ContactsProtectedHarness,
        contactsDirectory: URL
    ) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-contacts-\(UUID().uuidString)", isDirectory: true)
        let harness = try makeContactsProtectedHarness(
            prefix: prefix,
            contactsDirectory: directory
        )
        let service = ContactService(
            engine: stack.engine,
            contactsDomainStore: harness.store
        )
        let availability = await service.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
            wrappingRootKey: { harness.wrappingRootKey }
        )
        XCTAssertEqual(availability, .availableProtectedDomain)
        return (service, harness, directory)
    }

    private func makeReopenedProtectedContactService(
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
            engine: stack.engine,
            contactsDomainStore: store
        )
        let availability = await service.openContactsAfterPostUnlock(
            gateDecision: authorizedContactsGate(),
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
            sharedRightIdentifier: "com.cypherair.tests.encrypt.\(UUID().uuidString)"
        )
        _ = try registryStore.performSynchronousBootstrap()
        var registry = try registryStore.loadRegistry()
        registry.sharedResourceLifecycleState = .ready
        registry.committedMembership = [ProtectedSettingsStore.domainID: .active]
        try registryStore.saveRegistry(registry)

        let domainKeyManager = ProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let wrappingRootKey = Data(repeating: 0xB5, count: 32)
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

    private func authorizedContactsGate() -> ContactsPostAuthGateDecision {
        ContactsPostAuthGateDecision(
            postUnlockOutcome: .opened([ProtectedSettingsStore.domainID]),
            frameworkState: .sessionAuthorized
        )
    }

    private func makeTemporaryFile(named name: String, contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirEncryptScreenTests-\(UUID().uuidString)-\(name)")
        try contents.write(to: url, options: .atomic)
        return url
    }

    @MainActor
    func test_handleContentClearGenerationChange_clearsInputSearchRecipientsAndResults() {
        let model = makeModel()
        model.plaintext = "Sensitive plaintext"
        model.recipientSearchText = "alice"
        model.selectedRecipients = ["contact-1"]
        model.ciphertext = Data("ciphertext".utf8)
        model.selectedFileURL = URL(fileURLWithPath: "/tmp/plain.txt")
        model.selectedFileName = "plain.txt"
        model.showFileImporter = true
        model.showUnverifiedRecipientsWarning = true

        model.handleContentClearGenerationChange()

        XCTAssertEqual(model.plaintext, "")
        XCTAssertEqual(model.recipientSearchText, "")
        XCTAssertTrue(model.selectedRecipients.isEmpty)
        XCTAssertNil(model.ciphertext)
        XCTAssertNil(model.selectedFileURL)
        XCTAssertNil(model.selectedFileName)
        XCTAssertFalse(model.showFileImporter)
        XCTAssertFalse(model.showUnverifiedRecipientsWarning)
    }

    @MainActor
    func test_contentClearDuringClipboardNoticeSuppressesLateClipboardWrite() async {
        let gate = EncryptClipboardNoticeGate()
        var copiedPayloads: [(String, Bool)] = []
        let model = makeModel(
            clipboardNoticeDecision: {
                await gate.decision()
            },
            clipboardWriter: { text, shouldShowNotice in
                copiedPayloads.append((text, shouldShowNotice))
            }
        )
        model.ciphertext = Data("late-ciphertext".utf8)

        model.copyCiphertextToClipboard()

        await waitUntil("encrypt clipboard notice decision to suspend") {
            await gate.isSuspended()
        }

        model.handleContentClearGenerationChange()

        await gate.resume(returning: true)
        await settleAsyncWork()

        XCTAssertTrue(copiedPayloads.isEmpty)
        XCTAssertFalse(model.operation.isShowingClipboardNotice)
    }

    @MainActor
    private func waitUntil(
        _ description: String,
        timeout: TimeInterval = 2,
        condition: @escaping @MainActor () async -> Bool
    ) async {
        let deadline = Date().addingTimeInterval(timeout)

        while Date() < deadline {
            if await condition() {
                return
            }
            await Task.yield()
        }

        XCTFail("Timed out waiting for \(description)")
    }

    private func settleAsyncWork() async {
        for _ in 0..<10 {
            await Task.yield()
        }
    }
}
