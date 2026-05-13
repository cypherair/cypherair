import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class TutorialSessionStoreTests: XCTestCase {
    func test_tutorialSandboxContainer_usesSandboxStorageAndMocks() throws {
        let container = try TutorialSandboxContainer()
        defer { container.cleanup() }

        XCTAssertTrue(FileManager.default.fileExists(atPath: container.contactsDirectory.path))
        try assertCompleteFileProtection(at: container.contactsDirectory)
        XCTAssertEqual(
            container.defaultsSuiteName,
            AppTemporaryArtifactStore.tutorialSandboxDefaultsSuiteName
        )
        XCTAssertEqual(container.authManager.currentMode, .standard)
        XCTAssertEqual(container.contactService.availableContacts.count, 0)
        XCTAssertEqual(container.keyManagement.keys.count, 0)
        XCTAssertFalse(container.contactsDirectory.path.contains("/Documents/contacts"))
        XCTAssertNotNil(container.securitySimulationStack.authManager)
    }

    func test_tutorialSandboxContainer_clearsFixedDefaultsSuiteOnCreation() throws {
        let suiteName = AppTemporaryArtifactStore.tutorialSandboxDefaultsSuiteName
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defaults.set("stale", forKey: "marker")
        _ = defaults.synchronize()

        let container = try TutorialSandboxContainer()
        defer { container.cleanup() }

        XCTAssertNil(defaults.string(forKey: "marker"))
    }

    func test_prepareForPresentation_doesNotStartSandboxUntilModuleOpens() {
        let store = TutorialSessionStore()

        store.prepareForPresentation(launchOrigin: .inApp)

        XCTAssertNil(store.container)
        XCTAssertEqual(store.lifecycleState, .notStarted)
        XCTAssertEqual(store.hostSurface, .hub)
    }

    func test_openModule_sandbox_startsSessionAndShowsAcknowledgement() async {
        let store = TutorialSessionStore()

        await store.openModule(.sandbox)

        XCTAssertNotNil(store.container)
        XCTAssertEqual(store.lifecycleState, .inProgress)
        XCTAssertEqual(store.hostSurface, .sandboxAcknowledgement)
        XCTAssertFalse(store.isCompleted(.sandbox))
    }

    func test_confirmSandboxAcknowledgement_completesSandboxAndAdvancesToIdentityModule() async {
        let store = TutorialSessionStore()
        await store.openModule(.sandbox)

        store.confirmSandboxAcknowledgement()
        await Task.yield()

        XCTAssertTrue(store.isCompleted(.sandbox))
        XCTAssertEqual(store.currentModule, .createDemoIdentity)
        XCTAssertEqual(store.hostSurface, .workspace(module: .createDemoIdentity))
    }

    func test_returnToOverview_keepsSandboxArtifactsAndProgressForSameAppRun() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        let container = try XCTUnwrap(store.container)

        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        await store.noteAliceGenerated(alice)

        store.returnToOverview()

        XCTAssertEqual(store.hostSurface, .hub)
        XCTAssertEqual(store.lifecycleState, .inProgress)
        XCTAssertNotNil(store.container)
        XCTAssertEqual(store.session.artifacts.aliceIdentity?.fingerprint, alice.fingerprint)
        XCTAssertTrue(store.isCompleted(.createDemoIdentity))
    }

    func test_returnToOverview_preservesNavigationStateUntilNextModuleLaunch() async {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        await store.openModule(.encryptDemoMessage)
        store.setRoutePath([.encrypt], for: .home)

        store.returnToOverview()

        XCTAssertEqual(store.hostSurface, .hub)
        XCTAssertEqual(store.routePath(for: .home), [.encrypt])
        XCTAssertEqual(store.visibleRoute, .encrypt)
        XCTAssertEqual(store.selectedTab, .home)
    }

    func test_openSandboxAcknowledgement_preservesNavigationStateUntilHostSwitches() async {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        await store.openModule(.encryptDemoMessage)
        store.setRoutePath([.encrypt], for: .home)

        store.openSandboxAcknowledgement()

        XCTAssertEqual(store.hostSurface, .sandboxAcknowledgement)
        XCTAssertEqual(store.routePath(for: .home), [.encrypt])
        XCTAssertEqual(store.visibleRoute, .encrypt)
        XCTAssertEqual(store.selectedTab, .home)
    }

    func test_showCompletionView_preservesNavigationStateUntilHostSwitches() async {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        for module in TutorialModuleID.allCases {
            store.markCompletedForTesting(module)
        }
        await store.openModule(.encryptDemoMessage)
        store.setRoutePath([.encrypt], for: .home)

        store.showCompletionView()

        XCTAssertEqual(store.hostSurface, .completion)
        XCTAssertEqual(store.routePath(for: .home), [.encrypt])
        XCTAssertEqual(store.visibleRoute, .encrypt)
        XCTAssertEqual(store.selectedTab, .home)
    }

    func test_resetTutorial_recreatesSandboxAndClearsProgress() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        let oldContainer = try XCTUnwrap(store.container)
        let oldDirectory = oldContainer.contactsDirectory

        let alice = try await oldContainer.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        await store.noteAliceGenerated(alice)

        store.resetTutorial()

        XCTAssertFalse(FileManager.default.fileExists(atPath: oldDirectory.path))
        XCTAssertFalse(store.isCompleted(.createDemoIdentity))
        XCTAssertNil(store.session.artifacts.aliceIdentity)
        XCTAssertNil(store.container)
        XCTAssertEqual(store.lifecycleState, .notStarted)
    }

    func test_tutorialSessionStore_recordsArtifactsAcrossFullModuleFlow() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        let container = try XCTUnwrap(store.container)

        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        await store.noteAliceGenerated(alice)
        XCTAssertTrue(store.isCompleted(.createDemoIdentity))

        await store.openModule(.addDemoContact)
        let bobArmored = try XCTUnwrap(store.session.artifacts.bobArmoredPublicKey)
        let addResult = try container.contactService.addContact(publicKeyData: Data(bobArmored.utf8))
        guard case .added(let contact) = addResult else {
            return XCTFail("Expected Bob contact to be added")
        }
        store.noteBobImported(contact)
        let contactId = try XCTUnwrap(container.contactService.contactId(forFingerprint: contact.fingerprint))
        XCTAssertTrue(store.isCompleted(.addDemoContact))

        let ciphertext = try await container.encryptionService.encryptText(
            "Hello Bob from the guided tutorial",
            recipientContactIds: [contactId],
            signWithFingerprint: alice.fingerprint,
            encryptToSelf: false
        )
        store.noteEncrypted(ciphertext)
        XCTAssertTrue(store.isCompleted(.encryptDemoMessage))

        let phase1 = try await container.decryptionService.parseRecipients(ciphertext: ciphertext)
        store.noteParsed(phase1)
        XCTAssertFalse(store.isCompleted(.decryptAndVerify))
        XCTAssertEqual(store.session.artifacts.parseResult?.matchedKey?.fingerprint, store.session.artifacts.bobIdentity?.fingerprint)

        let decryptResult = try await container.decryptionService.decryptDetailed(phase1: phase1)
        store.noteDecrypted(
            plaintext: decryptResult.plaintext,
            verification: decryptResult.verification.legacyVerification
        )
        XCTAssertTrue(store.isCompleted(.decryptAndVerify))
        XCTAssertEqual(store.session.artifacts.decryptedVerification?.status, .valid)

        let backup = try await container.keyManagement.exportKey(
            fingerprint: alice.fingerprint,
            passphrase: "demo-backup-passphrase"
        )
        store.noteBackupExported(backup)
        XCTAssertTrue(store.isCompleted(.backupKey))
        XCTAssertTrue(store.session.artifacts.backupArmoredKey?.contains("BEGIN PGP PRIVATE KEY BLOCK") == true)

        try await container.authManager.switchMode(
            to: .highSecurity,
            fingerprints: container.keyManagement.keys.map(\.fingerprint),
            hasBackup: true,
            authenticator: container.mockAuthenticator
        )
        container.config.privateKeyControlState = .unlocked(.highSecurity)
        store.noteHighSecurityEnabled(.highSecurity)
        XCTAssertTrue(store.isCompleted(.enableHighSecurity))
        XCTAssertEqual(store.session.artifacts.authMode, .highSecurity)
        XCTAssertEqual(store.lifecycleState, .stepsCompleted)
    }

    func test_markFinishedTutorial_isTheOnlyPointThatPersistsCompletion() {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.\(UUID().uuidString)")!
        let protectedOrdinarySettings = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        let store = TutorialSessionStore()
        store.configurePersistence(protectedOrdinarySettings: protectedOrdinarySettings)

        for module in TutorialModuleID.allCases {
            store.markCompletedForTesting(module)
        }

        XCTAssertEqual(store.lifecycleState, .stepsCompleted)
        XCTAssertEqual(protectedOrdinarySettings.snapshot?.guidedTutorialCompletedVersion, 0)

        store.markFinishedTutorial()

        XCTAssertEqual(
            protectedOrdinarySettings.snapshot?.guidedTutorialCompletedVersion,
            GuidedTutorialVersion.current
        )
        XCTAssertEqual(store.lifecycleState, .finished)
    }

    func test_prepareForPresentation_afterReopen_returnsHubAndPreservesProgress() async {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)

        store.prepareForPresentation(launchOrigin: .inApp)

        XCTAssertEqual(store.hostSurface, .hub)
        XCTAssertEqual(store.lifecycleState, .inProgress)
        XCTAssertTrue(store.isCompleted(.createDemoIdentity))
        XCTAssertNil(store.pendingCompletionPromptModule)
    }

    func test_prepareForPresentation_afterFinishedReplay_resetsSession() {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.\(UUID().uuidString)")!
        let protectedOrdinarySettings = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        let store = TutorialSessionStore()
        store.configurePersistence(protectedOrdinarySettings: protectedOrdinarySettings)
        for module in TutorialModuleID.allCases {
            store.markCompletedForTesting(module)
        }
        store.markFinishedTutorial()

        store.prepareForPresentation(launchOrigin: .inApp)

        XCTAssertEqual(store.lifecycleState, .notStarted)
        XCTAssertNil(store.container)
        XCTAssertEqual(store.hostSurface, .hub)
    }

    func test_canOpen_unlocksSequentiallyBeforeReplayAndEverythingAfterReplay() {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.\(UUID().uuidString)")!
        let protectedOrdinarySettings = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        let store = TutorialSessionStore()
        store.configurePersistence(protectedOrdinarySettings: protectedOrdinarySettings)

        XCTAssertTrue(store.canOpen(.sandbox))
        XCTAssertFalse(store.canOpen(.addDemoContact))

        store.markCompletedForTesting(.sandbox)
        store.markCompletedForTesting(.createDemoIdentity)

        XCTAssertTrue(store.canOpen(.addDemoContact))
        XCTAssertFalse(store.canOpen(.backupKey))

        protectedOrdinarySettings.markGuidedTutorialCompletedCurrentVersion()

        XCTAssertTrue(store.canOpen(.backupKey))
        XCTAssertTrue(store.canOpen(.enableHighSecurity))
    }

    private func makeLoadedProtectedOrdinarySettings(
        defaults: UserDefaults
    ) -> ProtectedOrdinarySettingsCoordinator {
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: LegacyOrdinarySettingsStore(defaults: defaults)
        )
        coordinator.loadForAuthenticatedTestBypass()
        return coordinator
    }

    func test_presentLeaveConfirmation_installsTutorialOwnedModal() {
        let store = TutorialSessionStore()
        store.presentLeaveConfirmation(onLeave: { })

        guard case .leaveConfirmation? = store.activeModal else {
            return XCTFail("Expected leave confirmation modal")
        }
    }

    func test_tutorialOnboardingHandoff_requestFromOnboarding_clearsSheetAndQueuesTutorial() {
        var state = TutorialOnboardingHandoffState(
            activePresentation: .onboarding(initialPage: 2, context: .firstRun)
        )

        state.requestTutorialLaunchFromOnboarding(.onboardingFirstRun)

        XCTAssertNil(state.activePresentation)
        XCTAssertEqual(state.pendingTutorialLaunchAfterOnboardingDismissal, .onboardingFirstRun)
    }

    func test_tutorialOnboardingHandoff_completeAfterDismissal_launchesTutorial() {
        var state = TutorialOnboardingHandoffState(
            activePresentation: nil,
            pendingTutorialLaunchAfterOnboardingDismissal: .onboardingFirstRun
        )

        state.completePendingTutorialLaunchIfNeeded()

        guard case .tutorial(let presentationContext)? = state.activePresentation else {
            return XCTFail("Expected tutorial presentation after onboarding dismissal")
        }
        XCTAssertEqual(presentationContext, .onboardingFirstRun)
        XCTAssertNil(state.pendingTutorialLaunchAfterOnboardingDismissal)
    }

    func test_tutorialOnboardingHandoff_requestWithoutOnboarding_launchesImmediately() {
        var state = TutorialOnboardingHandoffState(activePresentation: nil)

        state.requestTutorialLaunchFromOnboarding(.onboardingFirstRun)

        guard case .tutorial(let presentationContext)? = state.activePresentation else {
            return XCTFail("Expected tutorial presentation to launch immediately")
        }
        XCTAssertEqual(presentationContext, .onboardingFirstRun)
        XCTAssertNil(state.pendingTutorialLaunchAfterOnboardingDismissal)
    }

    func test_handlePrimaryCompletionPromptAction_finalModuleShowsCompletionSurface() async {
        let store = TutorialSessionStore()
        for module in TutorialModuleID.allCases {
            store.markCompletedForTesting(module)
        }
        await store.openModule(.enableHighSecurity)
        store.markCompletedForTesting(.enableHighSecurity)

        store.handlePrimaryCompletionPromptAction()

        XCTAssertEqual(store.hostSurface, .completion)
        XCTAssertEqual(store.lifecycleState, .stepsCompleted)
    }

    func test_outputInterceptionPolicy_isAvailableOnlyForLiveSessionAndBlocksDangerousEffects() async throws {
        let store = TutorialSessionStore()
        XCTAssertNil(store.outputInterceptionPolicy)

        await startTutorialSession(store)
        let interceptor = try XCTUnwrap(store.outputInterceptionPolicy)
        let config = AppConfiguration(defaults: UserDefaults(suiteName: UUID().uuidString)!)

        XCTAssertTrue(interceptor.interceptClipboardCopy?("ciphertext", config, .ciphertext) == true)
        XCTAssertTrue(try interceptor.interceptDataExport?(Data("demo".utf8), "demo.asc", .ciphertext) == true)
        XCTAssertTrue(interceptor.interceptFileExport?(URL(fileURLWithPath: "/tmp/demo.asc"), "demo.asc", .ciphertext) == true)
    }

    func test_blocklist_blocksUnsafeRoutes_withoutBlockingSignAndVerifyRoots() {
        let blocklist = TutorialUnsafeRouteBlocklist()

        XCTAssertNotNil(blocklist.blockedRoute(for: .importKey))
        XCTAssertNotNil(blocklist.blockedRoute(for: .selfTest))
        XCTAssertNotNil(blocklist.blockedRoute(for: .appIcon))
        XCTAssertNotNil(blocklist.blockedRoute(for: .selectiveRevocation(fingerprint: "test-fingerprint")))
        XCTAssertNotNil(blocklist.blockedRoute(for: .contactCertificateSignatures(fingerprint: "test-fingerprint")))
        XCTAssertNil(blocklist.blockedRoot(for: .sign))
        XCTAssertNil(blocklist.blockedRoot(for: .verify))
        XCTAssertNil(blocklist.blockedRoute(for: .encrypt))
    }

    func test_tutorialConfigurationFactory_unifiesToolPages_withRealModesAndRestrictedFileCapabilities() {
        let store = TutorialSessionStore()
        let factory = store.configurationFactory

        let encryptConfiguration = factory.encryptConfiguration(isActiveModule: false)
        XCTAssertFalse(encryptConfiguration.allowsClipboardWrite)
        XCTAssertFalse(encryptConfiguration.allowsResultExport)
        XCTAssertFalse(encryptConfiguration.allowsFileInput)
        XCTAssertFalse(encryptConfiguration.allowsFileResultExport)
        XCTAssertNotNil(encryptConfiguration.fileRestrictionMessage)

        let decryptConfiguration = factory.decryptConfiguration(isActiveModule: false)
        XCTAssertFalse(decryptConfiguration.allowsTextFileImport)
        XCTAssertFalse(decryptConfiguration.allowsFileInput)
        XCTAssertFalse(decryptConfiguration.allowsFileResultExport)
        XCTAssertNotNil(decryptConfiguration.textFileRestrictionMessage)
        XCTAssertNotNil(decryptConfiguration.fileRestrictionMessage)

        let signConfiguration = factory.signConfiguration()
        XCTAssertFalse(signConfiguration.allowsClipboardWrite)
        XCTAssertFalse(signConfiguration.allowsTextResultExport)
        XCTAssertFalse(signConfiguration.allowsFileInput)
        XCTAssertFalse(signConfiguration.allowsFileResultExport)
        XCTAssertNotNil(signConfiguration.fileRestrictionMessage)
        XCTAssertNotNil(signConfiguration.resultRestrictionMessage)

        let verifyConfiguration = factory.verifyConfiguration()
        XCTAssertFalse(verifyConfiguration.allowsCleartextFileImport)
        XCTAssertFalse(verifyConfiguration.allowsDetachedOriginalImport)
        XCTAssertFalse(verifyConfiguration.allowsDetachedSignatureImport)
        XCTAssertNotNil(verifyConfiguration.cleartextFileRestrictionMessage)
        XCTAssertNotNil(verifyConfiguration.detachedFileRestrictionMessage)
    }

    func test_tutorialConfigurationFactory_addContactConfiguration_restrictsModesAndRoutesCallbacks() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        let container = try XCTUnwrap(store.container)

        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        await store.noteAliceGenerated(alice)

        let inactiveConfiguration = store.configurationFactory.addContactConfiguration(isActiveModule: false)
        XCTAssertEqual(inactiveConfiguration.allowedImportModes, [.paste])
        XCTAssertEqual(inactiveConfiguration.verificationPolicy, .verifiedOnly)
        XCTAssertNil(inactiveConfiguration.prefilledArmoredText)
        XCTAssertNil(inactiveConfiguration.onImported)
        XCTAssertNil(inactiveConfiguration.onImportConfirmationRequested)

        let activeConfiguration = store.configurationFactory.addContactConfiguration(isActiveModule: true)
        XCTAssertEqual(activeConfiguration.allowedImportModes, [.paste])
        XCTAssertEqual(activeConfiguration.verificationPolicy, .verifiedOnly)
        XCTAssertNotNil(activeConfiguration.prefilledArmoredText)
        XCTAssertNotNil(activeConfiguration.onImported)
        XCTAssertNotNil(activeConfiguration.onImportConfirmationRequested)
    }

    func test_tutorialConfigurationFactory_keyDetailConfiguration_disablesNonTutorialOutputs() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)

        let configuration = store.configurationFactory.keyDetailConfiguration()
        let config = AppConfiguration(defaults: UserDefaults(suiteName: UUID().uuidString)!)

        XCTAssertFalse(configuration.allowsPublicKeySave)
        XCTAssertFalse(configuration.allowsPublicKeyCopy)
        XCTAssertFalse(configuration.allowsRevocationExport)
        XCTAssertTrue(configuration.showsSelectiveRevocationEntry)
        XCTAssertFalse(configuration.allowsSelectiveRevocationLaunch)
        XCTAssertNotNil(configuration.selectiveRevocationRestrictionMessage)
        XCTAssertTrue(configuration.outputInterceptionPolicy.interceptClipboardCopy?("public-key", config, .publicKey) == true)
    }

    func test_tutorialConfigurationFactory_contactDetailConfiguration_showsDisabledCertificateSignatureEntry() {
        let store = TutorialSessionStore()
        let configuration = store.configurationFactory.contactDetailConfiguration()

        XCTAssertTrue(configuration.showsCertificateSignatureEntry)
        XCTAssertFalse(configuration.allowsCertificateSignatureLaunch)
        XCTAssertNotNil(configuration.certificateSignatureRestrictionMessage)
    }

    func test_tutorialConfigurationFactory_backupConfiguration_usesInlinePreviewAndActiveExportCallback() {
        let store = TutorialSessionStore()
        let inactiveConfiguration = store.configurationFactory.backupConfiguration(isActiveModule: false)
        let activeConfiguration = store.configurationFactory.backupConfiguration(isActiveModule: true)

        XCTAssertEqual(inactiveConfiguration.resultPresentation, .inlinePreview)
        XCTAssertNil(inactiveConfiguration.onExported)
        XCTAssertEqual(activeConfiguration.resultPresentation, .inlinePreview)
        XCTAssertNotNil(activeConfiguration.onExported)
    }

    func test_tutorialConfigurationFactory_encryptRuntimeSyncKey_changesBetweenInactiveAndActiveStates() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        let container = try XCTUnwrap(store.container)

        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        await store.noteAliceGenerated(alice)

        let bobArmored = try XCTUnwrap(store.session.artifacts.bobArmoredPublicKey)
        let addResult = try container.contactService.addContact(publicKeyData: Data(bobArmored.utf8))
        guard case .added(let contact) = addResult else {
            return XCTFail("Expected Bob contact to be added")
        }
        store.noteBobImported(contact)
        let contactId = try XCTUnwrap(container.contactService.contactId(forFingerprint: contact.fingerprint))

        let inactiveKey = EncryptView.RuntimeSyncKey(
            configuration: store.configurationFactory.encryptConfiguration(isActiveModule: false)
        )
        let activeKey = EncryptView.RuntimeSyncKey(
            configuration: store.configurationFactory.encryptConfiguration(isActiveModule: true)
        )

        XCTAssertNotEqual(inactiveKey, activeKey)
        XCTAssertTrue(inactiveKey.initialRecipientContactIds.isEmpty)
        XCTAssertEqual(activeKey.initialRecipientContactIds, [contactId])
        XCTAssertFalse(inactiveKey.hasOnEncrypted)
        XCTAssertTrue(activeKey.hasOnEncrypted)
    }

    func test_tutorialConfigurationFactory_decryptRuntimeSyncKey_changesBetweenInactiveAndActiveStates() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        let container = try XCTUnwrap(store.container)

        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            profile: .advanced
        )
        await store.noteAliceGenerated(alice)

        let bobArmored = try XCTUnwrap(store.session.artifacts.bobArmoredPublicKey)
        let addResult = try container.contactService.addContact(publicKeyData: Data(bobArmored.utf8))
        guard case .added(let contact) = addResult else {
            return XCTFail("Expected Bob contact to be added")
        }
        store.noteBobImported(contact)
        let contactId = try XCTUnwrap(container.contactService.contactId(forFingerprint: contact.fingerprint))

        let ciphertext = try await container.encryptionService.encryptText(
            "Hello Bob from the guided tutorial",
            recipientContactIds: [contactId],
            signWithFingerprint: alice.fingerprint,
            encryptToSelf: false
        )
        store.noteEncrypted(ciphertext)

        let phase1 = try await container.decryptionService.parseRecipients(ciphertext: ciphertext)
        store.noteParsed(phase1)

        let inactiveKey = DecryptView.RuntimeSyncKey(
            configuration: store.configurationFactory.decryptConfiguration(isActiveModule: false)
        )
        let activeKey = DecryptView.RuntimeSyncKey(
            configuration: store.configurationFactory.decryptConfiguration(isActiveModule: true)
        )

        XCTAssertNotEqual(inactiveKey, activeKey)
        XCTAssertNil(inactiveKey.initialPhase1Result)
        XCTAssertEqual(activeKey.initialPhase1Result?.matchedKeyFingerprint, phase1.matchedKey?.fingerprint)
        XCTAssertFalse(inactiveKey.hasOnParsed)
        XCTAssertTrue(activeKey.hasOnParsed)
        XCTAssertFalse(inactiveKey.hasOnDecrypted)
        XCTAssertTrue(activeKey.hasOnDecrypted)
    }

    func test_tutorialConfigurationFactory_addContactRuntimeSyncKey_changesBetweenInactiveAndActiveStates() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)

        let inactiveKey = AddContactView.RuntimeSyncKey(
            configuration: store.configurationFactory.addContactConfiguration(isActiveModule: false)
        )
        let activeKey = AddContactView.RuntimeSyncKey(
            configuration: store.configurationFactory.addContactConfiguration(isActiveModule: true)
        )

        XCTAssertNotEqual(inactiveKey, activeKey)
        XCTAssertEqual(inactiveKey.allowedImportModes, [.paste])
        XCTAssertEqual(activeKey.allowedImportModes, [.paste])
        XCTAssertEqual(inactiveKey.verificationPolicy, .verifiedOnly)
        XCTAssertEqual(activeKey.verificationPolicy, .verifiedOnly)
        XCTAssertFalse(inactiveKey.hasOnImported)
        XCTAssertTrue(activeKey.hasOnImported)
        XCTAssertFalse(inactiveKey.hasOnImportConfirmationRequested)
        XCTAssertTrue(activeKey.hasOnImportConfirmationRequested)
    }

    func test_tutorialGuidanceResolver_completedModule_returnsCompletionStatePayload() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)

        let payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: .compact,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertEqual(payload.module, .createDemoIdentity)
        XCTAssertEqual(payload.state, .completed)
        XCTAssertNil(payload.target)
        XCTAssertEqual(
            payload.body,
            String(
                localized: "guidedTutorial.task.complete",
                defaultValue: "This task is complete. Return to the tutorial overview to continue."
            )
        )
    }

    func test_tutorialGuidanceResolver_completedFinalModule_returnsFinalCompletionPayload() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        for module in TutorialModuleID.allCases where module != .enableHighSecurity {
            store.markCompletedForTesting(module)
        }
        await store.openModule(.enableHighSecurity)
        store.markCompletedForTesting(.enableHighSecurity)

        let payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: .compact,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertEqual(payload.module, .enableHighSecurity)
        XCTAssertEqual(payload.state, .completed)
        XCTAssertNil(payload.target)
        XCTAssertEqual(
            payload.body,
            String(
                localized: "guidedTutorial.task.complete.final",
                defaultValue: "This task is complete. Return to the tutorial overview to review completion and finish the tutorial."
            )
        )
    }

    func test_tutorialGuidanceResolver_activeModal_returnsNil() async {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.presentLeaveConfirmation(onLeave: { })

        let payload = TutorialGuidanceResolver().guidance(
            session: store.session,
            navigation: store.navigation,
            sizeClass: .compact,
            selectedTab: store.selectedTab
        )

        XCTAssertNil(payload)
    }

    func test_tutorialGuidanceResolver_encryptHomeSurface_pointsAtShortcut() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        await store.openModule(.encryptDemoMessage)

        let payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: nil,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertEqual(payload.module, .encryptDemoMessage)
        XCTAssertEqual(payload.target, .homeEncryptAction)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.home.encrypt", defaultValue: "Use the real Encrypt shortcut to open the message form.")
        )
    }

    func test_tutorialGuidanceResolver_encryptRoute_showsFormGuidance() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        await store.openModule(.encryptDemoMessage)
        store.setRoutePath([.encrypt], for: .home)

        let payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: nil,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertEqual(payload.module, .encryptDemoMessage)
        XCTAssertNil(payload.target)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.encrypt.form", defaultValue: "Bob is preselected. Review the draft and encrypt the message.")
        )
    }

    func test_tutorialGuidanceResolver_decryptHomeSurface_pointsAtShortcut() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        store.markCompletedForTesting(.encryptDemoMessage)
        await store.openModule(.decryptAndVerify)

        let payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: nil,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertEqual(payload.module, .decryptAndVerify)
        XCTAssertEqual(payload.target, .homeDecryptAction)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.home.decrypt", defaultValue: "Use the real Decrypt shortcut to inspect the encrypted message.")
        )
    }

    func test_tutorialGuidanceResolver_decryptRoute_switchesAfterRecipientParse() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        store.markCompletedForTesting(.encryptDemoMessage)
        await store.openModule(.decryptAndVerify)
        store.setRoutePath([.decrypt], for: .home)

        var payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: nil,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertEqual(payload.module, .decryptAndVerify)
        XCTAssertNil(payload.target)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.decrypt.parse", defaultValue: "Check the recipients first and make sure the message matches your sandbox key.")
        )

        store.noteParsed(makePhase1Result())

        payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: nil,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertEqual(payload.module, .decryptAndVerify)
        XCTAssertNil(payload.target)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.decrypt.form", defaultValue: "Decrypt the sandbox message and review the signature result.")
        )
    }

    func test_tutorialGuidanceResolver_importModal_returnsModalGuidance() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        await store.openModule(.addDemoContact)
        store.presentImportConfirmation(makeImportConfirmationRequest())
        let modal = try XCTUnwrap(store.activeModal)

        let payload = TutorialGuidanceResolver().modalGuidance(
            session: store.session,
            navigation: store.navigation,
            sizeClass: .regular,
            selectedTab: store.selectedTab,
            modal: modal
        )

        XCTAssertEqual(payload?.module, .addDemoContact)
        XCTAssertEqual(payload?.title, TutorialModuleID.addDemoContact.title)
        XCTAssertEqual(
            payload?.body,
            String(localized: "guidedTutorial.contacts.form", defaultValue: "Confirm Bob's key details and add the contact.")
        )
        XCTAssertNil(payload?.target)
    }

    func test_tutorialGuidanceResolver_authModal_returnsModalGuidanceWithConfirmTarget() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        for module in TutorialModuleID.allCases where module.rawValue < TutorialModuleID.enableHighSecurity.rawValue {
            store.markCompletedForTesting(module)
        }
        await store.openModule(.enableHighSecurity)
        store.presentAuthModeConfirmation(
            SettingsAuthModeRequestBuilder.makeLaunchPreviewRequest()
        )
        let modal = try XCTUnwrap(store.activeModal)

        let payload = TutorialGuidanceResolver().modalGuidance(
            session: store.session,
            navigation: store.navigation,
            sizeClass: .regular,
            selectedTab: store.selectedTab,
            modal: modal
        )

        XCTAssertEqual(payload?.module, .enableHighSecurity)
        XCTAssertEqual(payload?.title, TutorialModuleID.enableHighSecurity.title)
        XCTAssertEqual(
            payload?.body,
            String(localized: "guidedTutorial.settings.auth", defaultValue: "Switch the authentication mode to High Security and confirm the warning.")
        )
        XCTAssertEqual(payload?.target, .settingsModeConfirmButton)
    }

    func test_tutorialGuidanceResolver_leaveModal_returnsModalGuidance() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.presentLeaveConfirmation(onLeave: { })
        let modal = try XCTUnwrap(store.activeModal)

        let payload = TutorialGuidanceResolver().modalGuidance(
            session: store.session,
            navigation: store.navigation,
            sizeClass: .compact,
            selectedTab: store.selectedTab,
            modal: modal
        )

        XCTAssertEqual(payload?.module, .createDemoIdentity)
        XCTAssertEqual(payload?.title, TutorialModuleID.createDemoIdentity.title)
        XCTAssertEqual(
            payload?.body,
            String(
                localized: "guidedTutorial.leave.body",
                defaultValue: "Leave the guided tutorial now? Your progress will stay available until this app run ends, but the tutorial will close."
            )
        )
        XCTAssertNil(payload?.target)
    }

    func test_toolViews_removeModeAllowlistAndAppearResetPatterns() throws {
        let files = [
            "Sources/App/Encrypt/EncryptView.swift",
            "Sources/App/Decrypt/DecryptView.swift",
            "Sources/App/Sign/SignView.swift",
            "Sources/App/Sign/VerifyView.swift",
        ]

        for path in files {
            let contents = try loadRepositoryAuditSource(path)
            XCTAssertFalse(contents.contains("allowedModes"), "\(path) should not use mode allowlists")
            XCTAssertFalse(contents.contains("= configuration.allowedModes.first"), "\(path) should not reset mode on appear")
        }
    }

    func test_signView_establishesScreenModelHostBaseline() throws {
        let signViewContents = try loadRepositoryAuditSource("Sources/App/Sign/SignView.swift")
        let signScreenModelContents = try loadRepositoryAuditSource("Sources/App/Sign/SignScreenModel.swift")

        XCTAssertFalse(
            signViewContents.contains("@State private var operation = OperationController()"),
            "SignView should not directly own OperationController"
        )
        XCTAssertFalse(
            signViewContents.contains("@State private var exportController = FileExportController()"),
            "SignView should not directly own FileExportController"
        )
        XCTAssertFalse(
            signViewContents.contains("signerFingerprint = keyManagement.defaultKey?.fingerprint"),
            "SignView should not inline default signer preparation"
        )
        XCTAssertTrue(
            signViewContents.contains("SignScreenHostView"),
            "SignView should forward into a private owning host"
        )
        XCTAssertTrue(
            signScreenModelContents.contains("func syncSignerFromDefaultOnAppear()"),
            "SignScreenModel should own default signer synchronization for repeated appearances"
        )
    }

    func test_verifyView_establishesScreenModelHostBaseline() throws {
        let verifyViewContents = try loadRepositoryAuditSource("Sources/App/Sign/VerifyView.swift")
        let verifyScreenModelContents = try loadRepositoryAuditSource("Sources/App/Sign/VerifyScreenModel.swift")

        XCTAssertFalse(
            verifyViewContents.contains("@State private var operation = OperationController()"),
            "VerifyView should not directly own OperationController"
        )
        XCTAssertFalse(
            verifyViewContents.contains("@State private var importedCleartext = ImportedTextInputState()"),
            "VerifyView should not directly own imported cleartext state"
        )
        XCTAssertTrue(
            verifyViewContents.contains("VerifyScreenHostView"),
            "VerifyView should forward into a private owning host"
        )
        XCTAssertTrue(
            verifyScreenModelContents.contains("func handleDisappear()"),
            "VerifyScreenModel should own disappear cleanup"
        )
    }

    func test_addContactView_establishesScreenModelHostBaselineAndRuntimeSyncHook() throws {
        let addContactViewContents = try loadRepositoryAuditSource("Sources/App/Contacts/AddContactView.swift")
        let addContactScreenModelContents = try loadRepositoryAuditSource("Sources/App/Contacts/AddContactScreenModel.swift")

        XCTAssertFalse(
            addContactViewContents.contains("@State private var error: CypherAirError?"),
            "AddContactView should not directly own error state"
        )
        XCTAssertFalse(
            addContactViewContents.contains("@State private var pendingKeyUpdateRequest: ContactKeyUpdateConfirmationRequest?"),
            "AddContactView should not directly own key-update workflow state"
        )
        XCTAssertFalse(
            addContactViewContents.contains("@State private var importedKeyData: Data?"),
            "AddContactView should not directly own imported key payload state"
        )
        XCTAssertTrue(
            addContactViewContents.contains("AddContactScreenHostView"),
            "AddContactView should forward into a private owning host"
        )
        XCTAssertTrue(
            addContactScreenModelContents.contains("func handleAppear()"),
            "AddContactScreenModel should own repeated-appear synchronization"
        )
        XCTAssertTrue(
            addContactViewContents.contains("let configuration: AddContactView.Configuration"),
            "AddContact host should retain the latest incoming configuration"
        )
        XCTAssertTrue(
            addContactViewContents.contains(".onChange(of: runtimeSyncKey)"),
            "AddContact host should watch runtime configuration changes"
        )
        XCTAssertTrue(
            addContactViewContents.contains("model.updateConfiguration(configuration)"),
            "AddContact host should forward runtime configuration updates into the screen model"
        )
        XCTAssertTrue(
            addContactViewContents.contains("ImportConfirmationSheetHost(coordinator: fallbackImportConfirmationCoordinator)"),
            "AddContact host should retain the local fallback confirmation sheet"
        )
        XCTAssertTrue(
            addContactViewContents.contains("configuration.onImportConfirmationRequested == nil"),
            "AddContact fallback host should only install when no external confirmation presenter is supplied"
        )
    }

    func test_encryptAndDecryptViews_keepRuntimeConfigurationSyncHook() throws {
        let encryptViewContents = try loadRepositoryAuditSource("Sources/App/Encrypt/EncryptView.swift")
        let encryptHostContents = try loadRepositoryAuditSource("Sources/App/Encrypt/EncryptScreenHostView.swift")
        let encryptScreenModelContents = try loadRepositoryAuditSource("Sources/App/Encrypt/EncryptScreenModel.swift")
        let decryptViewContents = try loadRepositoryAuditSource("Sources/App/Decrypt/DecryptView.swift")
        let decryptScreenModelContents = try loadRepositoryAuditSource("Sources/App/Decrypt/DecryptScreenModel.swift")

        XCTAssertFalse(
            encryptViewContents.contains("@State private var operation = OperationController()"),
            "EncryptView should not directly own OperationController"
        )
        XCTAssertFalse(
            encryptViewContents.contains("@State private var exportController = FileExportController()"),
            "EncryptView should not directly own FileExportController"
        )
        XCTAssertFalse(
            encryptViewContents.contains("contactService.availableContacts.filter"),
            "EncryptView should bind to screen-model contact state instead of querying contacts inline"
        )
        XCTAssertTrue(
            encryptViewContents.contains("EncryptScreenHostView"),
            "EncryptView should forward into a private owning host"
        )
        XCTAssertTrue(
            encryptScreenModelContents.contains("func handleAppear()"),
            "EncryptScreenModel should own repeated onAppear synchronization"
        )
        XCTAssertTrue(
            encryptHostContents.contains("let configuration: EncryptView.Configuration"),
            "Encrypt host should retain the latest incoming configuration"
        )
        XCTAssertTrue(
            encryptHostContents.contains(".onChange(of: runtimeSyncKey)"),
            "Encrypt host should watch runtime configuration changes"
        )
        XCTAssertTrue(
            encryptHostContents.contains("model.updateConfiguration(configuration)"),
            "Encrypt host should forward runtime configuration updates into the screen model"
        )

        XCTAssertFalse(
            decryptViewContents.contains("@State private var operation = OperationController()"),
            "DecryptView should not directly own OperationController"
        )
        XCTAssertFalse(
            decryptViewContents.contains("@State private var exportController = FileExportController()"),
            "DecryptView should not directly own FileExportController"
        )
        XCTAssertFalse(
            decryptViewContents.contains("try? FileManager.default.removeItem"),
            "DecryptView should not inline temporary-file cleanup"
        )
        XCTAssertFalse(
            decryptViewContents.contains("importedCiphertext.clear()"),
            "DecryptView should not inline imported-text cleanup"
        )
        XCTAssertTrue(
            decryptViewContents.contains("DecryptScreenHostView"),
            "DecryptView should forward into a private owning host"
        )
        XCTAssertTrue(
            decryptScreenModelContents.contains("func handleAppear()"),
            "DecryptScreenModel should own repeated onAppear synchronization"
        )
        XCTAssertTrue(
            decryptScreenModelContents.contains("func handleDisappear()"),
            "DecryptScreenModel should own disappear cleanup"
        )
        XCTAssertTrue(
            decryptScreenModelContents.contains("func handleContentClearGenerationChange()"),
            "DecryptScreenModel should own content-clear invalidation"
        )
        XCTAssertTrue(
            decryptViewContents.contains("let configuration: DecryptView.Configuration"),
            "Decrypt host should retain the latest incoming configuration"
        )
        XCTAssertTrue(
            decryptViewContents.contains(".onChange(of: runtimeSyncKey)"),
            "Decrypt host should watch runtime configuration changes"
        )
        XCTAssertTrue(
            decryptViewContents.contains("model.updateConfiguration(configuration)"),
            "Decrypt host should forward runtime configuration updates into the screen model"
        )
    }

    func test_keyboardInputAPIs_areCentralizedAndPrivacyHardened() throws {
        let allowedDirectInputFiles: Set<String> = [
            "Sources/App/Common/CypherTextInputs.swift",
            "Sources/App/Common/CypherMultilineTextInput.swift",
        ]
        let bannedPatterns: [(pattern: String, label: String)] = [
            ("(?<![A-Za-z0-9_])TextField\\(", "TextField("),
            ("(?<![A-Za-z0-9_])SecureField\\(", "SecureField("),
            ("\\.searchable\\(", ".searchable("),
            ("(?<![A-Za-z0-9_])TextEditor\\(", "TextEditor("),
        ]

        for path in try repositoryAuditSwiftSourcePaths(under: "App") {
            guard !allowedDirectInputFiles.contains(path) else {
                continue
            }
            let contents = try loadRepositoryAuditSource(path)
            for bannedPattern in bannedPatterns {
                XCTAssertNil(
                    contents.range(of: bannedPattern.pattern, options: .regularExpression),
                    "\(path) should use Cypher input wrappers instead of direct \(bannedPattern.label)"
                )
            }
        }

        let inputComponentContents = try loadRepositoryAuditSource("Sources/App/Common/CypherTextInputs.swift")
        XCTAssertTrue(inputComponentContents.contains("enum CypherSingleLineTextInputProfile"))
        XCTAssertTrue(inputComponentContents.contains("enum CypherSecureTextInputProfile"))
        XCTAssertTrue(inputComponentContents.contains("enum CypherSearchTextInputProfile"))
        XCTAssertTrue(inputComponentContents.contains(".privacySensitive()"))
        XCTAssertTrue(inputComponentContents.contains(".autocorrectionDisabled(true)"))
        XCTAssertTrue(inputComponentContents.contains(".applyMacWritingToolsPolicy()"))

        let appContents = try loadRepositoryAuditSource("Sources/App/CypherAirApp.swift")
        XCTAssertTrue(appContents.contains("shouldAllowExtensionPointIdentifier"))
        XCTAssertTrue(appContents.contains("extensionPointIdentifier != .keyboard"))
    }

    func test_keyImportAndBackup_clearSensitiveInputOnSuccessDismissAndContentClear() throws {
        let importContents = try loadRepositoryAuditSource("Sources/App/Keys/ImportKeyView.swift")
        XCTAssertTrue(importContents.contains("FileImportRequestGate"))
        XCTAssertTrue(importContents.contains("handleFileImporterResult(result, token: fileImportRequestToken)"))
        XCTAssertTrue(importContents.contains("fileImportRequestGate.invalidate()"))
        XCTAssertTrue(importContents.contains("clearTransientInput()"))
        XCTAssertTrue(importContents.contains("clearImportedKeyData()"))
        XCTAssertTrue(importContents.contains(".onDisappear"))
        XCTAssertTrue(importContents.contains(".onChange(of: appSessionOrchestrator.contentClearGeneration)"))
        XCTAssertTrue(importContents.contains("dismiss()"))

        let backupContents = try loadRepositoryAuditSource("Sources/App/Keys/BackupKeyView.swift")
        XCTAssertTrue(backupContents.contains("clearTransientInput()"))
        XCTAssertTrue(backupContents.contains("clearExportedData()"))
        XCTAssertTrue(backupContents.contains(".onDisappear"))
        XCTAssertTrue(backupContents.contains(".onChange(of: appSessionOrchestrator.contentClearGeneration)"))
        XCTAssertTrue(backupContents.contains("passphrase = \"\""))
        XCTAssertTrue(backupContents.contains("passphraseConfirm = \"\""))
    }

    func test_backupFileExporter_confirmsOnlyAfterSuccessfulSave() throws {
        let backupContents = try loadRepositoryAuditSource("Sources/App/Keys/BackupKeyView.swift")
        let fileExporterStart = try XCTUnwrap(
            backupContents.range(of: ".fileExporter(")?.lowerBound
        )
        let fileExporterEnd = try XCTUnwrap(
            backupContents.range(of: ".onDisappear", range: fileExporterStart..<backupContents.endIndex)?.lowerBound
        )
        let fileExporterBody = String(backupContents[fileExporterStart..<fileExporterEnd])
        let successStart = try XCTUnwrap(fileExporterBody.range(of: "case .success:")?.lowerBound)
        let failureStart = try XCTUnwrap(fileExporterBody.range(of: "case .failure")?.lowerBound)
        let successBody = String(fileExporterBody[successStart..<failureStart])
        let failureBody = String(fileExporterBody[failureStart...])

        XCTAssertTrue(fileExporterBody.contains("exportedDataToken == exportToken"))
        XCTAssertTrue(successBody.contains("configuration.onExported?(exportedData)"))
        XCTAssertTrue(successBody.contains("keyManagement.confirmKeyBackupExported(fingerprint: fingerprint)"))
        XCTAssertFalse(failureBody.contains("confirmKeyBackupExported"))

        let exportBackupStart = try XCTUnwrap(
            backupContents.range(of: "private func exportBackup()")?.lowerBound
        )
        let exportBackupEnd = try XCTUnwrap(
            backupContents.range(
                of: "private func cancelExportAndClearTransientInput()",
                range: exportBackupStart..<backupContents.endIndex
            )?.lowerBound
        )
        let exportBackupBody = String(backupContents[exportBackupStart..<exportBackupEnd])

        XCTAssertTrue(exportBackupBody.contains("exportedDataToken = token"))
        XCTAssertTrue(exportBackupBody.contains("if configuration.resultPresentation == .inlinePreview"))
        XCTAssertTrue(exportBackupBody.contains("configuration.onExported?(data)"))
        XCTAssertTrue(exportBackupBody.contains("service.confirmKeyBackupExported(fingerprint: fp)"))
    }

    func test_outputPages_removeTutorialOutputCouplingFromPageImplementations() throws {
        let files = [
            "Sources/App/Encrypt/EncryptView.swift",
            "Sources/App/Sign/SignView.swift",
            "Sources/App/Decrypt/DecryptView.swift",
            "Sources/App/Keys/KeyDetailView.swift",
            "Sources/App/Keys/BackupKeyView.swift",
        ]

        for path in files {
            let contents = try loadRepositoryAuditSource(path)
            XCTAssertFalse(contents.contains("tutorialSideEffectInterceptor"), "\(path) should not reference tutorial-specific output interception")
        }

        let backupContents = try loadRepositoryAuditSource("Sources/App/Keys/BackupKeyView.swift")
        XCTAssertFalse(backupContents.contains("tutorialArtifact"), "BackupKeyView should not expose tutorial-specific result presentation")
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
        switch configuration.localDataResetAvailability {
        case .enabled:
            XCTFail("Tutorial settings should disable real local data reset")
        case .disabled(let footer):
            XCTAssertFalse(footer.isEmpty)
        }
    }

    func test_tutorialShellDefinitionsBuilder_regularIOS_matchesFullAppTabSet() {
        let store = TutorialSessionStore()
        let definitions = TutorialShellDefinitionsBuilder(
            store: store,
            sizeClass: .regular
        ).definitions()

        XCTAssertEqual(definitions.map(\.tab), AppShellTab.allCases)
    }

    func test_iOSVisionTutorialPresentation_injectsAppSessionOrchestrator() throws {
        let appContents = try loadRepositoryAuditSource("Sources/App/CypherAirApp.swift")
        let presentationBlock = try sourceBlock(
            in: appContents,
            from: "private func tutorialPresentationView(for presentation: IOSPresentation) -> some View {",
            to: "private var iosPresentationControllerValue: IOSPresentationController"
        )

        XCTAssertTrue(
            presentationBlock.contains("TutorialView("),
            "iOS/visionOS tutorial presentation should build TutorialView explicitly"
        )
        XCTAssertTrue(
            presentationBlock.contains(".environment(container.appSessionOrchestrator)"),
            "iOS/visionOS tutorial presentation must inject AppSessionOrchestrator for routed tool pages"
        )
    }

    func test_finishAndCleanupTutorial_clearsSandboxArtifacts() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        let container = try XCTUnwrap(store.container)
        let oldSuite = container.defaultsSuiteName
        let oldContactsDirectory = container.contactsDirectory
        UserDefaults(suiteName: oldSuite)?.set("temporary", forKey: "marker")
        XCTAssertEqual(UserDefaults(suiteName: oldSuite)?.string(forKey: "marker"), "temporary")

        store.finishAndCleanupTutorial()

        XCTAssertNil(store.container)
        XCTAssertEqual(store.lifecycleState, .notStarted)
        XCTAssertNil(UserDefaults(suiteName: oldSuite)?.string(forKey: "marker"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: oldContactsDirectory.path))

        await startTutorialSession(store)
        let newContainer = try XCTUnwrap(store.container)
        defer { newContainer.cleanup() }
        XCTAssertEqual(newContainer.defaultsSuiteName, oldSuite)
        XCTAssertNotEqual(newContainer.contactsDirectory, oldContactsDirectory)
        XCTAssertNil(UserDefaults(suiteName: oldSuite)?.string(forKey: "marker"))
    }

    private func assertCompleteFileProtection(
        at url: URL,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual(
            attributes[.protectionKey] as? FileProtectionType,
            .complete,
            file: file,
            line: line
        )
    }

    private func startTutorialSession(_ store: TutorialSessionStore) async {
        await store.openModule(.sandbox)
        store.confirmSandboxAcknowledgement()
        await Task.yield()
    }

    private func makeImportConfirmationRequest() -> ImportConfirmationRequest {
        ImportConfirmationRequest(
            keyData: Data("demo-key".utf8),
            keyInfo: KeyInfo(
                fingerprint: String(repeating: "a", count: 40),
                keyVersion: 4,
                userId: "Bob Demo <bob@example.invalid>",
                hasEncryptionSubkey: true,
                isRevoked: false,
                isExpired: false,
                profile: .universal,
                primaryAlgo: "Ed25519",
                subkeyAlgo: "X25519",
                expiryTimestamp: nil
            ),
            profile: .universal,
            allowsUnverifiedImport: true,
            onImportVerified: {},
            onImportUnverified: {},
            onCancel: {}
        )
    }

    private func makePhase1Result() -> DecryptionService.Phase1Result {
        DecryptionService.Phase1Result(
            recipientKeyIds: ["ABCD1234"],
            matchedKey: nil,
            ciphertext: Data("ciphertext".utf8)
        )
    }

    private func loadRepositoryAuditSource(_ relativePath: String) throws -> String {
        try RepositoryAuditLoader.loadString(relativePath: relativePath)
    }

    private func repositoryAuditSwiftSourcePaths(under relativeDirectory: String) throws -> [String] {
        let sourcesRootURL = try RepositoryAuditLoader.sourcesRootURL()
        let rootURL = sourcesRootURL.appending(path: relativeDirectory, directoryHint: .isDirectory)
        let fileManager = FileManager.default
        guard let enumerator = fileManager.enumerator(
            at: rootURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        var paths: [String] = []
        for case let fileURL as URL in enumerator {
            guard fileURL.pathExtension == "swift" else {
                continue
            }
            let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else {
                continue
            }
            let relativePath = String(fileURL.path.dropFirst(sourcesRootURL.path.count + 1))
            paths.append("Sources/\(relativePath)")
        }
        return paths.sorted()
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

}
