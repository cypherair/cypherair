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
        XCTAssertNotNil(container.securitySimulationStack.authManager)
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
            profile: .advanced,
            authMode: .standard
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
            profile: .advanced,
            authMode: .standard
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
            profile: .advanced,
            authMode: .standard
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
        XCTAssertTrue(store.isCompleted(.addDemoContact))

        let ciphertext = try await container.encryptionService.encryptText(
            "Hello Bob from the guided tutorial",
            recipientFingerprints: [contact.fingerprint],
            signWithFingerprint: alice.fingerprint,
            encryptToSelf: false
        )
        store.noteEncrypted(ciphertext)
        XCTAssertTrue(store.isCompleted(.encryptDemoMessage))

        let phase1 = try await container.decryptionService.parseRecipients(ciphertext: ciphertext)
        store.noteParsed(phase1)
        XCTAssertFalse(store.isCompleted(.decryptAndVerify))
        XCTAssertEqual(store.session.artifacts.parseResult?.matchedKey?.fingerprint, store.session.artifacts.bobIdentity?.fingerprint)

        let decryptResult = try await container.decryptionService.decrypt(phase1: phase1)
        store.noteDecrypted(plaintext: decryptResult.plaintext, verification: decryptResult.signature)
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
        container.config.authMode = .highSecurity
        store.noteHighSecurityEnabled(.highSecurity)
        XCTAssertTrue(store.isCompleted(.enableHighSecurity))
        XCTAssertEqual(store.session.artifacts.authMode, .highSecurity)
        XCTAssertEqual(store.lifecycleState, .stepsCompleted)
    }

    func test_markFinishedTutorial_isTheOnlyPointThatPersistsCompletion() {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.\(UUID().uuidString)")!
        let config = AppConfiguration(defaults: defaults)
        let store = TutorialSessionStore()
        store.configurePersistence(appConfiguration: config)

        for module in TutorialModuleID.allCases {
            store.markCompletedForTesting(module)
        }

        XCTAssertEqual(store.lifecycleState, .stepsCompleted)
        XCTAssertEqual(config.guidedTutorialCompletedVersion, 0)

        store.markFinishedTutorial()

        XCTAssertEqual(config.guidedTutorialCompletedVersion, GuidedTutorialVersion.current)
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
        let config = AppConfiguration(defaults: defaults)
        let store = TutorialSessionStore()
        store.configurePersistence(appConfiguration: config)
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
        let config = AppConfiguration(defaults: defaults)
        let store = TutorialSessionStore()
        store.configurePersistence(appConfiguration: config)

        XCTAssertTrue(store.canOpen(.sandbox))
        XCTAssertFalse(store.canOpen(.addDemoContact))

        store.markCompletedForTesting(.sandbox)
        store.markCompletedForTesting(.createDemoIdentity)

        XCTAssertTrue(store.canOpen(.addDemoContact))
        XCTAssertFalse(store.canOpen(.backupKey))

        config.markGuidedTutorialCompletedCurrentVersion()

        XCTAssertTrue(store.canOpen(.backupKey))
        XCTAssertTrue(store.canOpen(.enableHighSecurity))
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
        XCTAssertNotNil(blocklist.blockedRoute(for: .qrPhotoImport))
        XCTAssertNotNil(blocklist.blockedRoute(for: .selfTest))
        XCTAssertNotNil(blocklist.blockedRoute(for: .appIcon))
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

    func test_tutorialConfigurationFactory_keyDetailConfiguration_disablesNonTutorialOutputs() async throws {
        let store = TutorialSessionStore()
        await startTutorialSession(store)

        let configuration = store.configurationFactory.keyDetailConfiguration()
        let config = AppConfiguration(defaults: UserDefaults(suiteName: UUID().uuidString)!)

        XCTAssertFalse(configuration.allowsPublicKeySave)
        XCTAssertFalse(configuration.allowsPublicKeyCopy)
        XCTAssertFalse(configuration.allowsRevocationExport)
        XCTAssertTrue(configuration.outputInterceptionPolicy.interceptClipboardCopy?("public-key", config, .publicKey) == true)
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

    func test_toolViews_removeModeAllowlistAndAppearResetPatterns() throws {
        let rootURL = repositoryRootURL()
        let files = [
            "Sources/App/Encrypt/EncryptView.swift",
            "Sources/App/Decrypt/DecryptView.swift",
            "Sources/App/Sign/SignView.swift",
            "Sources/App/Sign/VerifyView.swift",
        ]

        for path in files {
            let contents = try String(contentsOf: rootURL.appending(path: path), encoding: .utf8)
            XCTAssertFalse(contents.contains("allowedModes"), "\(path) should not use mode allowlists")
            XCTAssertFalse(contents.contains("= configuration.allowedModes.first"), "\(path) should not reset mode on appear")
        }
    }

    func test_signView_establishesScreenModelHostBaseline() throws {
        let rootURL = repositoryRootURL()
        let signViewContents = try String(
            contentsOf: rootURL.appending(path: "Sources/App/Sign/SignView.swift"),
            encoding: .utf8
        )
        let signScreenModelContents = try String(
            contentsOf: rootURL.appending(path: "Sources/App/Sign/SignScreenModel.swift"),
            encoding: .utf8
        )

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

    func test_outputPages_removeTutorialOutputCouplingFromPageImplementations() throws {
        let rootURL = repositoryRootURL()
        let files = [
            "Sources/App/Encrypt/EncryptView.swift",
            "Sources/App/Sign/SignView.swift",
            "Sources/App/Decrypt/DecryptView.swift",
            "Sources/App/Keys/KeyDetailView.swift",
            "Sources/App/Keys/BackupKeyView.swift",
        ]

        for path in files {
            let contents = try String(contentsOf: rootURL.appending(path: path), encoding: .utf8)
            XCTAssertFalse(contents.contains("tutorialSideEffectInterceptor"), "\(path) should not reference tutorial-specific output interception")
        }

        let backupContents = try String(
            contentsOf: rootURL.appending(path: "Sources/App/Keys/BackupKeyView.swift"),
            encoding: .utf8
        )
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

        store.finishAndCleanupTutorial()

        XCTAssertNil(store.container)
        XCTAssertEqual(store.lifecycleState, .notStarted)

        await startTutorialSession(store)
        XCTAssertNotEqual(store.container?.defaultsSuiteName, oldSuite)
    }

    func test_onboardingLocalizedKeys_existInCatalogAndAreFullyTranslated() throws {
        let rootURL = repositoryRootURL()
        let catalogURL = rootURL.appending(path: "Sources/Resources/Localizable.xcstrings")
        let sourceURL = rootURL.appending(path: "Sources/App/Onboarding", directoryHint: .isDirectory)

        let catalogData = try Data(contentsOf: catalogURL)
        let catalog = try JSONDecoder().decode(StringCatalog.self, from: catalogData)
        let keys = try localizedKeys(in: sourceURL)

        XCTAssertFalse(keys.isEmpty)

        for key in keys.sorted() {
            let entry = try XCTUnwrap(catalog.strings[key], "Missing catalog entry for \(key)")

            guard key.hasPrefix("guidedTutorial.") || key.hasPrefix("onboarding.") || key.hasPrefix("tutorial.") else {
                continue
            }

            let locales = Set(entry.localizations.keys)
            XCTAssertTrue(
                locales.isSuperset(of: ["en", "zh-Hans"]),
                "\(key) is missing required tutorial locales"
            )
            XCTAssertNotEqual(entry.extractionState, "stale", "\(key) should not be stale")
        }
    }

    private func startTutorialSession(_ store: TutorialSessionStore) async {
        await store.openModule(.sandbox)
        store.confirmSandboxAcknowledgement()
        await Task.yield()
    }

    private func repositoryRootURL() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func localizedKeys(in directoryURL: URL) throws -> Set<String> {
        let expression = try NSRegularExpression(pattern: #"localized:\s*"([^"]+)""#)
        var keys = Set<String>()

        let enumerator = FileManager.default.enumerator(
            at: directoryURL,
            includingPropertiesForKeys: nil
        )

        while let fileURL = enumerator?.nextObject() as? URL {
            guard fileURL.pathExtension == "swift" else { continue }

            let contents = try String(contentsOf: fileURL, encoding: .utf8)
            let range = NSRange(contents.startIndex..<contents.endIndex, in: contents)
            let matches = expression.matches(in: contents, range: range)

            for match in matches {
                guard
                    let keyRange = Range(match.range(at: 1), in: contents)
                else {
                    continue
                }

                keys.insert(String(contents[keyRange]))
            }
        }

        return keys
    }
}

private struct StringCatalog: Decodable {
    let strings: [String: StringCatalogEntry]
}

private struct StringCatalogEntry: Decodable {
    let extractionState: String?
    let localizations: [String: StringCatalogLocalization]
}

private struct StringCatalogLocalization: Decodable {
    let stringUnit: StringCatalogStringUnit?
}

private struct StringCatalogStringUnit: Decodable {
    let state: String
    let value: String
}
