import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class TutorialSessionStoreTests: XCTestCase {
    func test_tutorialSandboxContainer_usesSandboxStorageAndMocks() throws {
        let container = try TutorialSandboxContainer()
        defer { container.cleanup() }

        XCTAssertTrue(FileManager.default.fileExists(atPath: container.contactsDirectory.path))
        XCTAssertTrue(container.defaultsSuiteName.hasPrefix("com.cypherair.tutorial."))
        XCTAssertEqual(container.authManager.currentMode, .standard)
        XCTAssertEqual(container.contactService.contacts.count, 0)
        XCTAssertEqual(container.keyManagement.keys.count, 0)
        XCTAssertFalse(container.contactsDirectory.path.contains("/Documents/contacts"))
    }

    func test_tutorialSessionStore_returnToOverview_keepsLiveSandboxSideEffects() async throws {
        let store = TutorialSessionStore()
        store.ensureSession()
        let firstContainer = try XCTUnwrap(store.container)

        let alice = try await firstContainer.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced,
            authMode: .standard
        )
        await store.noteAliceGenerated(alice)

        await store.openTask(.importBobKey)
        let resumedContainer = try XCTUnwrap(store.container)

        XCTAssertTrue(store.session.isShellPresented)
        XCTAssertEqual(firstContainer.defaultsSuiteName, resumedContainer.defaultsSuiteName)
        XCTAssertEqual(store.session.artifacts.aliceIdentity?.fingerprint, alice.fingerprint)
        XCTAssertNotNil(store.session.artifacts.bobArmoredPublicKey)

        store.returnToOverview()

        XCTAssertFalse(store.session.isShellPresented)
        XCTAssertNotNil(store.container)
        XCTAssertEqual(store.container?.defaultsSuiteName, firstContainer.defaultsSuiteName)
        XCTAssertEqual(store.session.artifacts.aliceIdentity?.fingerprint, alice.fingerprint)
    }

    func test_tutorialSessionStore_reset_recreatesSandboxAndClearsProgress() async throws {
        let store = TutorialSessionStore()
        store.ensureSession()
        let oldContainer = try XCTUnwrap(store.container)
        let oldDirectory = oldContainer.contactsDirectory

        let alice = try await oldContainer.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced,
            authMode: .standard
        )
        await store.noteAliceGenerated(alice)

        store.resetTutorial()

        XCTAssertFalse(FileManager.default.fileExists(atPath: oldDirectory.path))
        XCTAssertFalse(store.isCompleted(.generateAliceKey))
        XCTAssertNil(store.session.artifacts.aliceIdentity)
        XCTAssertNil(store.session.artifacts.bobArmoredPublicKey)

        let newContainer = try XCTUnwrap(store.container)
        XCTAssertNotEqual(newContainer.defaultsSuiteName, oldContainer.defaultsSuiteName)
        XCTAssertTrue(FileManager.default.fileExists(atPath: newContainer.contactsDirectory.path))
    }

    func test_tutorialSessionStore_recordsTaskArtifactsAcrossFlow() async throws {
        let store = TutorialSessionStore()
        store.ensureSession()
        let container = try XCTUnwrap(store.container)

        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced,
            authMode: .standard
        )
        await store.noteAliceGenerated(alice)
        XCTAssertTrue(store.isCompleted(.generateAliceKey))

        let bobArmored = try XCTUnwrap(store.session.artifacts.bobArmoredPublicKey)
        let addResult = try container.contactService.addContact(publicKeyData: Data(bobArmored.utf8))
        guard case .added(let contact) = addResult else {
            return XCTFail("Expected Bob contact to be added")
        }
        store.noteBobImported(contact)
        XCTAssertTrue(store.isCompleted(.importBobKey))

        let ciphertext = try await container.encryptionService.encryptText(
            "Hello Bob from the guided tutorial",
            recipientFingerprints: [contact.fingerprint],
            signWithFingerprint: alice.fingerprint,
            encryptToSelf: false
        )
        store.noteEncrypted(ciphertext)
        XCTAssertTrue(store.isCompleted(.composeAndEncryptMessage))

        let phase1 = try await container.decryptionService.parseRecipients(ciphertext: ciphertext)
        store.noteParsed(phase1)
        XCTAssertTrue(store.isCompleted(.parseRecipients))
        XCTAssertEqual(store.session.artifacts.parseResult?.matchedKey?.fingerprint, store.session.artifacts.bobIdentity?.fingerprint)

        let decryptResult = try await container.decryptionService.decrypt(phase1: phase1)
        store.noteDecrypted(plaintext: decryptResult.plaintext, verification: decryptResult.signature)
        XCTAssertTrue(store.isCompleted(.decryptMessage))
        XCTAssertEqual(store.session.artifacts.decryptedVerification?.status, .valid)

        let backup = try await container.keyManagement.exportKey(
            fingerprint: alice.fingerprint,
            passphrase: "demo-backup-passphrase"
        )
        store.noteBackupExported(backup)
        XCTAssertTrue(store.isCompleted(.exportBackup))
        XCTAssertTrue(store.session.artifacts.backupArmoredKey?.contains("BEGIN PGP PRIVATE KEY BLOCK") == true)

        try await container.authManager.switchMode(
            to: .highSecurity,
            fingerprints: container.keyManagement.keys.map(\.fingerprint),
            hasBackup: true,
            authenticator: container.mockAuthenticator
        )
        container.config.authMode = .highSecurity
        store.noteHighSecurityEnabled(.highSecurity)
        XCTAssertTrue(store.isCompleted(.enableHighSecurity))
        XCTAssertEqual(store.session.artifacts.authMode, .highSecurity)
    }

    func test_tutorialSessionStore_finalCompletion_marksCurrentTutorialVersion() {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.\(UUID().uuidString)")!
        let config = AppConfiguration(defaults: defaults)
        let store = TutorialSessionStore()
        store.configurePersistence(appConfiguration: config)

        completeTutorialFlow(store: store)

        XCTAssertEqual(config.guidedTutorialCompletedVersion, GuidedTutorialVersion.current)
        XCTAssertTrue(config.hasCompletedCurrentGuidedTutorialVersion)
    }

    func test_tutorialSessionStore_incompleteFlowDoesNotMarkTutorialCompleted() async throws {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.\(UUID().uuidString)")!
        let config = AppConfiguration(defaults: defaults)
        let store = TutorialSessionStore()
        store.configurePersistence(appConfiguration: config)

        store.ensureSession()
        let container = try XCTUnwrap(store.container)
        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced,
            authMode: .standard
        )
        await store.noteAliceGenerated(alice)
        store.returnToOverview()

        XCTAssertEqual(config.guidedTutorialCompletedVersion, 0)
        XCTAssertEqual(config.guidedTutorialCompletionState, .neverCompleted)
    }

    func test_tutorialSessionStore_showCompletionViewAfterFinalTaskShowsCompletionPhase() async {
        let store = TutorialSessionStore()
        store.ensureSession()
        completeTutorialFlow(store: store)
        await store.openTask(.enableHighSecurity)

        store.showCompletionView()

        XCTAssertFalse(store.session.isShellPresented)
        XCTAssertTrue(store.isShowingCompletionView)
        XCTAssertEqual(store.flowPhase, .completion)
    }

    func test_tutorialSessionStore_nonFinalTaskCompletion_setsPendingCompletionPrompt() async {
        let store = TutorialSessionStore()
        await store.openTask(.generateAliceKey)

        store.markCompletedForTesting(.generateAliceKey)

        XCTAssertEqual(store.pendingCompletionPromptTask, .generateAliceKey)
        XCTAssertEqual(store.session.activeTask, .generateAliceKey)
    }

    func test_tutorialSessionStore_pendingCompletionPrompt_survivesRoutePush() async {
        let store = TutorialSessionStore()
        await store.openTask(.generateAliceKey)
        let identity = makeIdentity(
            fingerprint: "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
            userId: "Alice Demo <alice@demo.invalid>"
        )

        store.markCompletedForTesting(.generateAliceKey)
        store.navigateToPostGenerationPrompt(identity)

        XCTAssertEqual(store.pendingCompletionPromptTask, .generateAliceKey)
        XCTAssertEqual(store.routePath, [.postGenerationPrompt(identity: identity)])
        XCTAssertEqual(store.session.activeTask, .generateAliceKey)
    }

    func test_tutorialSessionStore_dismissCompletionPrompt_keepsCompletedTaskFact() async {
        let store = TutorialSessionStore()
        await store.openTask(.generateAliceKey)

        store.markCompletedForTesting(.generateAliceKey)
        store.dismissCompletionPrompt()

        XCTAssertTrue(store.isCompleted(.generateAliceKey))
        XCTAssertNil(store.pendingCompletionPromptTask)
        XCTAssertEqual(store.session.activeTask, .generateAliceKey)
    }

    func test_tutorialSessionStore_handlePrimaryCompletionPromptAction_nonFinal_returnsOverview() async {
        let store = TutorialSessionStore()
        await store.openTask(.generateAliceKey)

        store.markCompletedForTesting(.generateAliceKey)
        store.handlePrimaryCompletionPromptAction()

        XCTAssertNil(store.pendingCompletionPromptTask)
        XCTAssertEqual(store.flowPhase, .overview)
        XCTAssertNil(store.session.activeTask)
    }

    func test_tutorialSessionStore_handlePrimaryCompletionPromptAction_final_showsCompletion() async {
        let store = TutorialSessionStore()
        store.ensureSession()
        completeTutorialFlow(store: store)
        await store.openTask(.enableHighSecurity)

        store.markCompletedForTesting(.enableHighSecurity)
        store.handlePrimaryCompletionPromptAction()

        XCTAssertNil(store.pendingCompletionPromptTask)
        XCTAssertEqual(store.flowPhase, .completion)
        XCTAssertTrue(store.isShowingCompletionView)
    }

    func test_tutorialSessionStore_finishAndCleanupTutorial_clearsSandboxArtifacts() async throws {
        let store = TutorialSessionStore()
        store.ensureSession()
        let container = try XCTUnwrap(store.container)
        let oldSuite = container.defaultsSuiteName

        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced,
            authMode: .standard
        )
        await store.noteAliceGenerated(alice)
        store.showCompletionView()

        store.finishAndCleanupTutorial()

        XCTAssertNil(store.container)
        XCTAssertNil(store.session.artifacts.aliceIdentity)
        XCTAssertEqual(store.flowPhase, .overview)

        store.ensureSession()
        XCTAssertNotEqual(store.container?.defaultsSuiteName, oldSuite)
    }

    func test_tutorialSessionStore_prepareForPresentation_afterReopen_returnsCleanOverview() async {
        let store = TutorialSessionStore()
        await store.openTask(.generateAliceKey)
        store.markCompletedForTesting(.generateAliceKey)

        store.prepareForPresentation()

        XCTAssertEqual(store.flowPhase, .overview)
        XCTAssertNil(store.pendingCompletionPromptTask)
        XCTAssertEqual(store.selectedTab, .home)
    }

    func test_tutorialSessionStore_pendingCompletionPrompt_survivesTabSwitch() async {
        let store = TutorialSessionStore()
        await store.openTask(.generateAliceKey)

        store.markCompletedForTesting(.generateAliceKey)
        store.selectTab(.home)
        store.selectTab(.keys)

        XCTAssertEqual(store.pendingCompletionPromptTask, .generateAliceKey)
        XCTAssertEqual(store.session.activeTask, .generateAliceKey)
    }

    func test_tutorialSessionStore_pendingCompletionPrompt_survivesModalRoundTrip() async {
        let store = TutorialSessionStore()
        await store.openTask(.generateAliceKey)

        store.markCompletedForTesting(.generateAliceKey)
        store.presentAuthModeConfirmation(
            AuthModeChangeConfirmationRequest(
                pendingMode: .highSecurity,
                title: "Demo",
                message: "Demo",
                requiresRiskAcknowledgement: false,
                onConfirm: { },
                onCancel: { }
            )
        )
        store.dismissModal()

        XCTAssertEqual(store.pendingCompletionPromptTask, .generateAliceKey)
        XCTAssertEqual(store.session.activeTask, .generateAliceKey)
    }

    func test_tutorialSessionStore_openTask_understandSandbox_showsAcknowledgementPhase() async {
        let store = TutorialSessionStore()

        await store.openTask(.understandSandbox)

        XCTAssertEqual(store.flowPhase, .sandboxAcknowledgement)
        XCTAssertFalse(store.isCompleted(.understandSandbox))
        XCTAssertNil(store.session.activeTask)
    }

    func test_tutorialSessionStore_confirmSandboxAcknowledgement_completesIntroAndReturnsOverview() {
        let store = TutorialSessionStore()
        store.openSandboxAcknowledgement()

        store.confirmSandboxAcknowledgement()

        XCTAssertTrue(store.isCompleted(.understandSandbox))
        XCTAssertEqual(store.flowPhase, .overview)
        XCTAssertEqual(store.selectedTab, .home)
    }

    func test_tutorialSessionStore_resetTutorial_requiresSandboxAcknowledgementAgain() {
        let store = TutorialSessionStore()
        store.openSandboxAcknowledgement()
        store.confirmSandboxAcknowledgement()

        XCTAssertTrue(store.isCompleted(.understandSandbox))

        store.resetTutorial()

        XCTAssertFalse(store.isCompleted(.understandSandbox))
        XCTAssertEqual(store.flowPhase, .overview)
    }

    func test_tutorialSessionStore_prepareForPresentation_returnsToOverview() async {
        let store = TutorialSessionStore()
        await store.openTask(.generateAliceKey)

        store.prepareForPresentation()

        XCTAssertEqual(store.flowPhase, .overview)
        XCTAssertFalse(store.session.isShellPresented)
        XCTAssertTrue(store.routePath.isEmpty)
    }

    func test_tutorialSessionStore_selectTabPreservesPerTabRouteAndClearsModalState() {
        let store = TutorialSessionStore()
        store.ensureSession()

        store.setRoutePath([.addContact])
        store.presentImportConfirmation(makeImportConfirmationRequest())

        XCTAssertEqual(store.routePath, [.addContact])
        XCTAssertNotNil(store.activeModal)

        store.selectTab(.contacts)

        XCTAssertEqual(store.selectedTab, .contacts)
        XCTAssertTrue(store.routePath.isEmpty)
        XCTAssertNil(store.activeModal)

        store.selectTab(.home)

        XCTAssertEqual(store.routePath, [.addContact])
    }

    func test_tutorialSessionStore_postGenerationPrompt_appendsRouteOnSelectedTab() {
        let store = TutorialSessionStore()
        store.ensureSession()
        store.selectTab(.keys)

        let identity = makeIdentity(
            fingerprint: "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
            userId: "Alice Demo <alice@demo.invalid>"
        )

        store.navigateToPostGenerationPrompt(identity)

        XCTAssertEqual(store.routePath, [.postGenerationPrompt(identity: identity)])
        XCTAssertEqual(store.visibleRoute, .postGenerationPrompt(identity: identity))
    }

    func test_tutorialSessionStore_postGenerationPrompt_routePreservesCompletedKeyTaskAndArtifacts() async throws {
        let store = TutorialSessionStore()
        store.ensureSession()
        let container = try XCTUnwrap(store.container)

        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced,
            authMode: .standard
        )
        await store.noteAliceGenerated(alice)
        await store.openTask(.generateAliceKey)
        store.navigateToPostGenerationPrompt(alice)

        XCTAssertTrue(store.isCompleted(.generateAliceKey))
        XCTAssertEqual(store.session.artifacts.aliceIdentity?.fingerprint, alice.fingerprint)
        XCTAssertNotNil(store.session.artifacts.bobArmoredPublicKey)
        XCTAssertTrue(store.session.isShellPresented)
        XCTAssertEqual(store.session.activeTask, .generateAliceKey)
        XCTAssertEqual(store.routePath, [.postGenerationPrompt(identity: alice)])
    }

    func test_tutorialSessionStore_setRoutePath_forTab_preservesIndependentTabStacks() {
        let store = TutorialSessionStore()
        store.ensureSession()

        store.setRoutePath([.addContact], for: .contacts)
        store.setRoutePath([.themePicker], for: .settings)

        XCTAssertEqual(store.routePath(for: .contacts), [.addContact])
        XCTAssertEqual(store.routePath(for: .settings), [.themePicker])
        XCTAssertTrue(store.routePath.isEmpty)

        store.selectTab(.contacts)
        XCTAssertEqual(store.routePath, [.addContact])

        store.selectTab(.settings)
        XCTAssertEqual(store.routePath, [.themePicker])
    }

    func test_tutorialConfigurationFactory_settingsConfiguration_disablesRestrictedEntries() {
        let store = TutorialSessionStore()
        let configuration = store.configurationFactory.settingsConfiguration()

        XCTAssertFalse(configuration.isOnboardingEntryEnabled)
        XCTAssertFalse(configuration.isGuidedTutorialEntryEnabled)
        XCTAssertTrue(configuration.isThemePickerEnabled)
        XCTAssertFalse(configuration.isAppIconEntryEnabled)
        XCTAssertNotNil(configuration.navigationEducationFooter)
        XCTAssertNotNil(configuration.appearanceEducationFooter)
    }

    func test_tutorialShellDefinitionsBuilder_regularIOS_matchesFullAppTabSet() {
        let store = TutorialSessionStore()
        let definitions = TutorialShellDefinitionsBuilder(
            store: store,
            sizeClass: .regular
        ).definitions()

        XCTAssertEqual(definitions.map(\.tab), AppShellTab.allCases)
    }

    func test_tutorialSessionStore_returnToOverview_clearsTutorialNavigationState() async {
        let store = TutorialSessionStore()
        await store.openTask(.importBobKey)
        store.setRoutePath([.addContact])
        store.presentImportConfirmation(makeImportConfirmationRequest())

        store.returnToOverview()

        XCTAssertFalse(store.session.isShellPresented)
        XCTAssertEqual(store.selectedTab, .home)
        XCTAssertTrue(store.routePath.isEmpty)
        XCTAssertNil(store.activeModal)
    }

    private func completeTutorialFlow(store: TutorialSessionStore) {
        for task in TutorialTaskID.allCases {
            store.markCompletedForTesting(task)
        }
    }

    private func makeImportConfirmationRequest() -> ImportConfirmationRequest {
        ImportConfirmationRequest(
            keyData: Data("demo".utf8),
            keyInfo: KeyInfo(
                fingerprint: "abcdef1234567890",
                keyVersion: 6,
                userId: "Bob Demo <bob@demo.invalid>",
                hasEncryptionSubkey: true,
                isRevoked: false,
                isExpired: false,
                profile: .advanced,
                primaryAlgo: "Ed448",
                subkeyAlgo: "X448",
                expiryTimestamp: nil
            ),
            profile: .advanced,
            allowsUnverifiedImport: false,
            onImportVerified: { },
            onImportUnverified: { },
            onCancel: { }
        )
    }

    private func makeIdentity(
        fingerprint: String,
        userId: String
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: 6,
            profile: .advanced,
            userId: userId,
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data("demo-public-key".utf8),
            revocationCert: Data(),
            primaryAlgo: "Ed448",
            subkeyAlgo: "X448",
            expiryDate: nil
        )
    }
}
