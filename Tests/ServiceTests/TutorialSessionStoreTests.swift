import Foundation
import XCTest
@testable import CypherAir

@MainActor
private final class TutorialContactsOpenGate {
    private(set) var openCallCount = 0
    private var isReleased = false
    private var startContinuations: [(count: Int, continuation: CheckedContinuation<Void, Never>)] = []
    private var releaseContinuations: [CheckedContinuation<Void, Never>] = []

    func open(_ container: TutorialSandboxContainer) async throws {
        openCallCount += 1
        resumeSatisfiedStartContinuations()

        guard !isReleased else { return }
        await withCheckedContinuation { continuation in
            releaseContinuations.append(continuation)
        }
    }

    func waitUntilStarted() async {
        await waitUntilOpenCallCount(1)
    }

    func waitUntilOpenCallCount(_ count: Int) async {
        guard openCallCount < count else { return }
        await withCheckedContinuation { continuation in
            startContinuations.append((count, continuation))
        }
    }

    func release() {
        isReleased = true
        releaseContinuations.forEach { $0.resume() }
        releaseContinuations.removeAll()
    }

    private func resumeSatisfiedStartContinuations() {
        let continuationsToResume = startContinuations.filter { $0.count <= openCallCount }
        startContinuations.removeAll { $0.count <= openCallCount }
        continuationsToResume.forEach { $0.continuation.resume() }
    }
}

@MainActor
final class TutorialSessionStoreTests: TutorialSandboxDefaultsSerializedTestCase {
    func test_tutorialSandboxContainer_usesSandboxStorageAndMocks() async throws {
        let container = try TutorialSandboxContainer()
        defer { container.cleanup() }

        try await container.openContactsIfNeeded()

        XCTAssertTrue(FileManager.default.fileExists(atPath: container.contactsDirectory.path))
        try assertCompleteFileProtection(at: container.contactsDirectory)
        XCTAssertEqual(
            container.defaultsSuiteName,
            AppTemporaryArtifactStore.tutorialSandboxDefaultsSuiteName
        )
        XCTAssertEqual(container.authManager.currentMode, .standard)
        XCTAssertEqual(container.contactService.contactsAvailability, .availableProtectedDomain)
        XCTAssertEqual(container.contactService.testContactKeyRecords.count, 0)
        XCTAssertEqual(container.keyManagement.keys.count, 0)
        XCTAssertFalse(container.contactsDirectory.path.contains("/Documents/contacts"))
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

    func test_openModule_sandboxSerializesConcurrentContactsOpen() async {
        let gate = TutorialContactsOpenGate()
        let store = TutorialSessionStore(openTutorialContacts: { container in
            try await gate.open(container)
        })
        let firstTask = Task { @MainActor in
            await store.openModule(.sandbox)
        }

        await gate.waitUntilStarted()
        XCTAssertEqual(gate.openCallCount, 1)
        XCTAssertEqual(store.openingModule, .sandbox)
        XCTAssertTrue(store.isOpeningModule)

        let secondOpenAttempted = expectation(description: "second module open attempted")
        let secondTask = Task { @MainActor in
            secondOpenAttempted.fulfill()
            await store.openModule(.sandbox)
        }
        await fulfillment(of: [secondOpenAttempted], timeout: 1)
        await Task.yield()

        XCTAssertEqual(gate.openCallCount, 1)
        XCTAssertTrue(store.isOpeningModule)

        gate.release()
        await firstTask.value
        await secondTask.value

        XCTAssertEqual(gate.openCallCount, 1)
        XCTAssertNil(store.openingModule)
        XCTAssertFalse(store.isOpeningModule)
        XCTAssertEqual(store.hostSurface, .sandboxAcknowledgement)
    }

    func test_openModule_sandboxIgnoresContactsOpenAfterReset() async {
        let gate = TutorialContactsOpenGate()
        let store = TutorialSessionStore(openTutorialContacts: { container in
            try await gate.open(container)
        })
        let task = Task { @MainActor in
            await store.openModule(.sandbox)
        }

        await gate.waitUntilStarted()
        XCTAssertNotNil(store.container)

        store.resetTutorial()
        XCTAssertFalse(store.isOpeningModule)
        gate.release()
        await task.value

        XCTAssertNil(store.container)
        XCTAssertEqual(store.lifecycleState, .notStarted)
        XCTAssertEqual(store.hostSurface, .hub)
        XCTAssertFalse(store.isOpeningModule)
    }

    func test_openModule_sandboxIgnoresContactsOpenAfterFinishAndCleanup() async {
        let gate = TutorialContactsOpenGate()
        let store = TutorialSessionStore(openTutorialContacts: { container in
            try await gate.open(container)
        })
        let task = Task { @MainActor in
            await store.openModule(.sandbox)
        }

        await gate.waitUntilStarted()
        XCTAssertNotNil(store.container)

        store.finishAndCleanupTutorial()
        XCTAssertFalse(store.isOpeningModule)
        gate.release()
        await task.value

        XCTAssertNil(store.container)
        XCTAssertEqual(store.lifecycleState, .notStarted)
        XCTAssertEqual(store.hostSurface, .hub)
        XCTAssertFalse(store.isOpeningModule)
    }

    func test_openModule_sandboxIgnoresContactsOpenAfterTaskCancellation() async {
        let gate = TutorialContactsOpenGate()
        let store = TutorialSessionStore(openTutorialContacts: { container in
            try await gate.open(container)
        })
        let task = Task { @MainActor in
            await store.openModule(.sandbox)
        }

        await gate.waitUntilStarted()
        task.cancel()
        gate.release()
        await task.value

        XCTAssertNotNil(store.container)
        XCTAssertEqual(store.lifecycleState, .inProgress)
        XCTAssertEqual(store.hostSurface, .hub)
        XCTAssertFalse(store.isOpeningModule)
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
        let addResult = try container.contactService.importContact(publicKeyData: Data(bobArmored.utf8))
        guard case .added(let contact, let key) = addResult else {
            return XCTFail("Expected Bob contact to be added")
        }
        store.noteBobImported(contact)
        let contactId = try XCTUnwrap(container.contactService.contactId(forFingerprint: key.fingerprint))
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
            verification: decryptResult.verification
        )
        XCTAssertTrue(store.isCompleted(.decryptAndVerify))

        let backup = try await container.keyManagement.exportKey(
            fingerprint: alice.fingerprint,
            passphrase: "demo-backup-passphrase"
        )
        store.noteBackupExported(backup)
        XCTAssertTrue(store.isCompleted(.backupKey))

        try await container.authManager.switchMode(
            to: .highSecurity,
            fingerprints: container.keyManagement.keys.map(\.fingerprint),
            hasBackup: true,
            authenticator: container.mockAuthenticator
        )
        container.config.privateKeyControlState = .unlocked(.highSecurity)
        store.noteHighSecurityEnabled(.highSecurity)
        XCTAssertTrue(store.isCompleted(.enableHighSecurity))
        XCTAssertEqual(store.lifecycleState, .stepsCompleted)
    }

    func test_markFinishedTutorial_isTheOnlyPointThatPersistsCompletion() {
        let protectedOrdinarySettings = makeLoadedProtectedOrdinarySettings()
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
        let protectedOrdinarySettings = makeLoadedProtectedOrdinarySettings()
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
        let protectedOrdinarySettings = makeLoadedProtectedOrdinarySettings()
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

    private func makeLoadedProtectedOrdinarySettings() -> ProtectedOrdinarySettingsCoordinator {
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: InMemoryOrdinarySettingsStore()
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
        let addResult = try container.contactService.importContact(publicKeyData: Data(bobArmored.utf8))
        guard case .added(let contact, let key) = addResult else {
            return XCTFail("Expected Bob contact to be added")
        }
        store.noteBobImported(contact)
        let contactId = try XCTUnwrap(container.contactService.contactId(forFingerprint: key.fingerprint))

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
        let addResult = try container.contactService.importContact(publicKeyData: Data(bobArmored.utf8))
        guard case .added(let contact, let key) = addResult else {
            return XCTFail("Expected Bob contact to be added")
        }
        store.noteBobImported(contact)
        let contactId = try XCTUnwrap(container.contactService.contactId(forFingerprint: key.fingerprint))

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

        XCTAssertEqual(payload.target, .homeEncryptAction)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.home.encrypt", defaultValue: "Use the real Encrypt shortcut to open the message form.")
        )
    }

    func test_tutorialGuidanceResolver_encryptRegularNonHomeSurface_pointsAtHomeShortcut() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        await store.openModule(.encryptDemoMessage)
        store.selectTab(.keys)

        let payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: .regular,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertNil(payload.target)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.nav.homeEncrypt", defaultValue: "Open the Home tab to reach the Encrypt shortcut.")
        )
    }

    func test_tutorialGuidanceResolver_encryptSidebarToolSurface_showsFormGuidance() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        await store.openModule(.encryptDemoMessage)
        store.selectTab(.encrypt)

        let payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: .regular,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertNil(payload.target)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.encrypt.form", defaultValue: "Bob is preselected. Review the draft and encrypt the message.")
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

        XCTAssertEqual(payload.target, .homeDecryptAction)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.home.decrypt", defaultValue: "Use the real Decrypt shortcut to inspect the encrypted message.")
        )
    }

    func test_tutorialGuidanceResolver_decryptRegularNonHomeSurface_pointsAtHomeShortcut() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        store.markCompletedForTesting(.encryptDemoMessage)
        await store.openModule(.decryptAndVerify)
        store.selectTab(.contacts)

        let payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: .regular,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertNil(payload.target)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.nav.homeDecrypt", defaultValue: "Open the Home tab to reach the Decrypt shortcut.")
        )
    }

    func test_tutorialGuidanceResolver_decryptSidebarToolSurface_showsParseGuidance() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)
        store.markCompletedForTesting(.createDemoIdentity)
        store.markCompletedForTesting(.addDemoContact)
        store.markCompletedForTesting(.encryptDemoMessage)
        await store.openModule(.decryptAndVerify)
        store.selectTab(.decrypt)

        let payload = try XCTUnwrap(
            TutorialGuidanceResolver().guidance(
                session: store.session,
                navigation: store.navigation,
                sizeClass: .regular,
                selectedTab: store.selectedTab
            )
        )

        XCTAssertNil(payload.target)
        XCTAssertEqual(
            payload.body,
            String(localized: "guidedTutorial.decrypt.parse", defaultValue: "Check the recipients first and make sure the message matches your sandbox key.")
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

    func test_tutorialConfigurationFactory_settingsConfiguration_disablesRestrictedEntries() {
        let store = TutorialSessionStore()
        let configuration = store.configurationFactory.settingsConfiguration()

        XCTAssertFalse(configuration.isOnboardingEntryEnabled)
        XCTAssertFalse(configuration.isGuidedTutorialEntryEnabled)
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
            metadata: PGPKeyMetadata(
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
            allowsUnverifiedImport: true,
            onImportVerified: {},
            onImportUnverified: {},
            onCancel: {}
        )
    }

    private func makePhase1Result() -> DecryptionPhase1Result {
        DecryptionPhase1Result(
            recipientKeyIds: ["ABCD1234"],
            matchedKey: nil,
            ciphertext: Data("ciphertext".utf8)
        )
    }

}
