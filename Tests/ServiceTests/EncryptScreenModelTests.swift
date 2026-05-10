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

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
        defaultsSuiteName = "com.cypherair.tests.encryptscreen.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        config = AppConfiguration(defaults: defaults)
        protectedOrdinarySettings = ProtectedOrdinarySettingsCoordinator(
            persistence: LegacyOrdinarySettingsStore(defaults: defaults)
        )
        protectedOrdinarySettings.loadForAuthenticatedTestBypass()
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
        let signerIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Signer"
        )
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)

        var configuration = EncryptView.Configuration()
        configuration.prefilledPlaintext = "Prefilled message"
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
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
        let signerIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Signer"
        )
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
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
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
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
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)

        let model = makeModel()
        model.plaintext = "User edited plaintext"

        var activeConfiguration = EncryptView.Configuration()
        activeConfiguration.prefilledPlaintext = "Prefilled message"
        activeConfiguration.initialRecipientFingerprints = [recipientIdentity.fingerprint]

        model.updateConfiguration(activeConfiguration)

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertEqual(model.selectedRecipients, [recipientContactId])

        model.updateConfiguration(.default)

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertTrue(model.selectedRecipients.isEmpty)
    }

    @MainActor
    func test_initialRecipientContactIdsTakePrecedenceOverCompatibilityFingerprints() async throws {
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let recipientContactId = try importContactAndResolveContactId(for: recipientIdentity)
        let model = makeModel()
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientContactIds = [recipientContactId]
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]

        model.updateConfiguration(configuration)

        XCTAssertEqual(model.selectedRecipients, [recipientContactId])
    }

    @MainActor
    func test_initialRecipientContactIdsFiltersStaleIdsWhenContactsAreAvailable() async throws {
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
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
    func test_handleAppear_ignoresStaleInitialRecipientFingerprints() async throws {
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Stale Recipient"
        )

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]

        let model = makeModel(configuration: configuration)
        model.handleAppear()

        XCTAssertTrue(model.selectedRecipients.isEmpty)
    }

    @MainActor
    func test_updateConfiguration_clearsSelectionForStaleCompatibilityFingerprint() {
        let model = makeModel()
        model.selectedRecipients = ["manual-recipient"]

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = ["stale-fingerprint"]

        model.updateConfiguration(configuration)

        XCTAssertTrue(model.selectedRecipients.isEmpty)
    }

    @MainActor
    func test_contactsAvailabilityChange_restoresPendingCompatibilityFingerprint() async throws {
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Delayed Recipient"
        )
        let delayed = try makeLockedLegacyContactServiceSeeded(with: recipientIdentity)
        defer { try? FileManager.default.removeItem(at: delayed.directory) }

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
        let model = makeModel(
            contactService: delayed.service,
            configuration: configuration
        )

        model.handleAppear()

        XCTAssertTrue(model.selectedRecipients.isEmpty)

        let previousAvailability = delayed.service.contactsAvailability
        let currentAvailability = try delayed.service.openLegacyCompatibilityForTests()
        model.handleContactsAvailabilityChange(
            from: previousAvailability,
            to: currentAvailability
        )

        XCTAssertEqual(model.selectedRecipients, [delayed.contactId])
    }

    @MainActor
    func test_configurationDefaultClearsPendingCompatibilityFingerprintBeforeContactsBecomeAvailable() async throws {
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Cleared Delayed Recipient"
        )
        let delayed = try makeLockedLegacyContactServiceSeeded(with: recipientIdentity)
        defer { try? FileManager.default.removeItem(at: delayed.directory) }

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
        let model = makeModel(
            contactService: delayed.service,
            configuration: configuration
        )

        model.handleAppear()
        model.updateConfiguration(.default)

        let previousAvailability = delayed.service.contactsAvailability
        let currentAvailability = try delayed.service.openLegacyCompatibilityForTests()
        model.handleContactsAvailabilityChange(
            from: previousAvailability,
            to: currentAvailability
        )

        XCTAssertTrue(model.selectedRecipients.isEmpty)
    }

    @MainActor
    func test_delayedCompatibilityFingerprintResolutionAppendsToManualSelection() async throws {
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Union Delayed Recipient"
        )
        let delayed = try makeLockedLegacyContactServiceSeeded(with: recipientIdentity)
        defer { try? FileManager.default.removeItem(at: delayed.directory) }

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
        let model = makeModel(
            contactService: delayed.service,
            configuration: configuration
        )
        model.selectedRecipients = ["manual-recipient"]

        model.handleAppear()

        let previousAvailability = delayed.service.contactsAvailability
        let currentAvailability = try delayed.service.openLegacyCompatibilityForTests()
        model.handleContactsAvailabilityChange(
            from: previousAvailability,
            to: currentAvailability
        )

        XCTAssertEqual(model.selectedRecipients, ["manual-recipient", delayed.contactId])
    }

    @MainActor
    func test_encryptText_usesCallbackCapturedAtOperationStart_whenConfigurationChangesMidFlight() async throws {
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
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
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Unverified Recipient"
        )
        try stack.contactService.addContact(
            publicKeyData: recipientIdentity.publicKeyData,
            verificationState: .unverified
        )

        var encryptCount = 0
        var callbackCiphertext: Data?
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
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
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptPreferredVerification")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory.deletingLastPathComponent())
        }
        let preferred = try stack.engine.generateKey(
            name: "Preferred Recipient",
            email: "preferred-recipient@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let historical = try stack.engine.generateKey(
            name: "Historical Recipient",
            email: "historical-recipient@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        try opened.service.addContact(publicKeyData: preferred.publicKeyData, verificationState: .verified)
        try opened.service.addContact(publicKeyData: historical.publicKeyData, verificationState: .unverified)
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
            engine: stack.engine,
            keyManagement: stack.keyManagement,
            contactService: opened.service
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
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagSelection")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory.deletingLastPathComponent())
        }
        let first = try stack.engine.generateKey(
            name: "Tag First",
            email: "encrypt-tag-first@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let second = try stack.engine.generateKey(
            name: "Tag Second",
            email: "encrypt-tag-second@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        try opened.service.addContact(publicKeyData: first.publicKeyData, verificationState: .verified)
        try opened.service.addContact(publicKeyData: second.publicKeyData, verificationState: .verified)
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
        model.selectedRecipients = [firstContactId]
        model.selectRecipients(withTagId: tag.tagId)

        XCTAssertEqual(Set(model.effectiveRecipientContactIds), Set([firstContactId, secondContactId]))
        let tagOption = try XCTUnwrap(model.recipientTagOptions.first { $0.tagId == tag.tagId })
        XCTAssertEqual(model.selectedRecipientCount(for: tagOption), 2)

        model.recipientSearchText = "Second"
        XCTAssertEqual(model.encryptableContacts.map(\.contactId), [secondContactId])

        model.toggleRecipient(secondContactId, isOn: false)
        XCTAssertEqual(model.effectiveRecipientContactIds, [firstContactId])

        model.selectRecipients(withTagId: tag.tagId)
        XCTAssertEqual(Set(model.effectiveRecipientContactIds), Set([firstContactId, secondContactId]))

        model.requestEncrypt()
        await waitUntil("tag-selection encryption to finish") {
            model.operation.isRunning == false
        }
        XCTAssertEqual(Set(capturedRecipients), Set([firstContactId, secondContactId]))

        model.clearRecipients()
        XCTAssertTrue(model.selectedRecipients.isEmpty)
        XCTAssertTrue(model.effectiveRecipientContactIds.isEmpty)
        XCTAssertNil(model.tagSelectionSkipMessage)
    }

    @MainActor
    func test_tagSelectionSkipsContactsWithoutPreferredKeyAndReportsCount() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagSelectionSkip")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory.deletingLastPathComponent())
        }
        let selectable = try stack.engine.generateKey(
            name: "Selectable Tag Member",
            email: "selectable-tag-member@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let missingPreferred = try stack.engine.generateKey(
            name: "Missing Preferred Tag Member",
            email: "missing-preferred-tag@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        try opened.service.addContact(publicKeyData: selectable.publicKeyData, verificationState: .verified)
        try opened.service.addContact(publicKeyData: missingPreferred.publicKeyData, verificationState: .verified)
        let selectableContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: selectable.fingerprint))
        let missingPreferredContactId = try XCTUnwrap(opened.service.contactId(forFingerprint: missingPreferred.fingerprint))
        let tag = try opened.service.addTag(named: "Partial Team", toContactId: selectableContactId)
        _ = try opened.service.addTag(named: "Partial Team", toContactId: missingPreferredContactId)

        var snapshot = try opened.service.currentCompatibilitySnapshot()
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
        model.selectRecipients(withTagId: tag.tagId)

        XCTAssertEqual(model.effectiveRecipientContactIds, [selectableContactId])
        XCTAssertEqual(model.tagSelectionSkippedContactCount, 1)
        XCTAssertEqual(model.tagSelectionSkippedTagName, "Partial Team")
        XCTAssertNotNil(model.tagSelectionSkipMessage)
        model.dismissTagSelectionSkipMessage()
        XCTAssertNil(model.tagSelectionSkipMessage)
    }

    @MainActor
    func test_requestEncryptFailsAndClearsStaleDirectRecipientSelection() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptStaleDirectRecipient")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory.deletingLastPathComponent())
        }
        let retained = try stack.engine.generateKey(
            name: "Retained Direct Recipient",
            email: "retained-direct@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let removed = try stack.engine.generateKey(
            name: "Removed Direct Recipient",
            email: "removed-direct@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        try opened.service.addContact(publicKeyData: retained.publicKeyData, verificationState: .verified)
        try opened.service.addContact(publicKeyData: removed.publicKeyData, verificationState: .verified)
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
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagUnverifiedWarning")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory.deletingLastPathComponent())
        }
        let unverified = try stack.engine.generateKey(
            name: "Unverified Tag Member",
            email: "unverified-tag-member@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        try opened.service.addContact(publicKeyData: unverified.publicKeyData, verificationState: .unverified)
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
        model.selectRecipients(withTagId: tag.tagId)

        XCTAssertEqual(model.selectedUnverifiedContacts.map(\.contactId), [unverifiedContactId])

        model.requestEncrypt()
        XCTAssertFalse(didEncrypt)
        XCTAssertTrue(model.showUnverifiedRecipientsWarning)
    }

    @MainActor
    func test_confirmEncryptRevalidatesTagSelectedRecipientsAfterUnverifiedWarning() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let opened = try await makeOpenedProtectedContactService(prefix: "EncryptTagConfirmRevalidate")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: opened.contactsDirectory.deletingLastPathComponent())
        }
        let unverified = try stack.engine.generateKey(
            name: "Warning Removed Tag Member",
            email: "warning-removed-tag-member@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        try opened.service.addContact(publicKeyData: unverified.publicKeyData, verificationState: .unverified)
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
        model.selectRecipients(withTagId: tag.tagId)

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
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Verified Recipient"
        )
        try stack.contactService.addContact(publicKeyData: recipientIdentity.publicKeyData)

        var interceptedClipboard: String?
        var interceptedExportFilename: String?
        var callbackCiphertext: Data?
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
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
    func test_encryptFile_handlesSelection_andRoutesFileExportThroughInterceptionPolicy() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        try stack.contactService.addContact(publicKeyData: recipientIdentity.publicKeyData)

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
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
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
            fileEncryptionAction: { _, _, _, _, _, _ in CypherAir.AppTemporaryArtifact(fileURL: outputURL) }
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
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        try stack.contactService.addContact(publicKeyData: recipientIdentity.publicKeyData)

        let gate = EncryptOperationGate()
        let inputURL = try makeTemporaryFile(
            named: "cancel.txt",
            contents: Data("cancel".utf8)
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]

        let model = makeModel(
            configuration: configuration,
            fileEncryptionAction: { _, _, _, _, _, progress in
                _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
                await gate.suspend()
                try Task.checkCancellation()
                return CypherAir.AppTemporaryArtifact(fileURL: inputURL)
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
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        try stack.contactService.addContact(publicKeyData: recipientIdentity.publicKeyData)
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
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
        let model = makeModel(
            configuration: configuration,
            operation: operation,
            fileEncryptionAction: { _, _, _, _, _, _ in
                operation.cancel()
                return CypherAir.AppTemporaryArtifact(fileURL: outputURL)
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
    private func makeModel(
        contactService: ContactService? = nil,
        configuration: EncryptView.Configuration = .default,
        operation: OperationController = OperationController(),
        textEncryptionAction: EncryptScreenModel.TextEncryptionAction? = nil,
        fileEncryptionAction: EncryptScreenModel.FileEncryptionAction? = nil
    ) -> EncryptScreenModel {
        let resolvedContactService = contactService ?? stack.contactService
        let resolvedEncryptionService = contactService.map {
            EncryptionService(
                engine: stack.engine,
                keyManagement: stack.keyManagement,
                contactService: $0
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
            fileEncryptionAction: fileEncryptionAction
        )
    }

    private func importContactAndResolveContactId(for identity: PGPKeyIdentity) throws -> String {
        _ = try stack.contactService.addContact(publicKeyData: identity.publicKeyData)
        return try XCTUnwrap(stack.contactService.contactId(forFingerprint: identity.fingerprint))
    }

    private func makeLockedLegacyContactServiceSeeded(
        with identity: PGPKeyIdentity
    ) throws -> (service: ContactService, contactId: String, directory: URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("EncryptDelayedPrefill-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )

        let writer = ContactService(
            engine: stack.engine,
            contactsDirectory: directory
        )
        try writer.openLegacyCompatibilityForTests()
        _ = try writer.addContact(publicKeyData: identity.publicKeyData)
        let contactId = try XCTUnwrap(writer.contactId(forFingerprint: identity.fingerprint))

        let locked = ContactService(
            engine: stack.engine,
            contactsDirectory: directory
        )
        XCTAssertEqual(locked.contactsAvailability, .locked)
        return (locked, contactId, directory)
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
                XCTFail("Committed Contacts domain should not rebuild from legacy source.")
                return ContactsDomainSnapshot.empty()
            }
        )
        let service = ContactService(
            engine: stack.engine,
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
            sharedRightIdentifier: "com.cypherair.tests.encrypt.\(UUID().uuidString)"
        )
        _ = try registryStore.performSynchronousBootstrap()
        var registry = try registryStore.loadRegistry()
        registry.sharedResourceLifecycleState = .ready
        registry.committedMembership = [ProtectedSettingsStore.domainID: .active]
        try registryStore.saveRegistry(registry)

        let domainKeyManager = ProtectedDomainKeyManager(storageRoot: storageRoot)
        let wrappingRootKey = Data(repeating: 0xB5, count: 32)
        let migrationSource = ContactsLegacyMigrationSource(
            engine: stack.engine,
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

    private func makeTemporaryFile(named name: String, contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirEncryptScreenTests-\(UUID().uuidString)-\(name)")
        try contents.write(to: url, options: .atomic)
        return url
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
}
