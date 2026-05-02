import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

private struct SettingsScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

final class SettingsScreenModelTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!
    private var config: AppConfiguration!
    private var protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator!
    private var authManager: AuthenticationManager!
    private var privateKeyControlStore: InMemoryPrivateKeyControlStore!
    private var defaultsSuiteName: String!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
        defaultsSuiteName = "com.cypherair.tests.settingsscreen.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        config = AppConfiguration(defaults: defaults)
        protectedOrdinarySettings = ProtectedOrdinarySettingsCoordinator(
            persistence: LegacyOrdinarySettingsStore(defaults: defaults)
        )
        protectedOrdinarySettings.loadForAuthenticatedTestBypass()
        config.privateKeyControlState = .unlocked(.standard)
        authManager = AuthenticationManager(
            secureEnclave: stack.mockSE,
            keychain: stack.mockKC,
            defaults: defaults
        )
        privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        authManager.configurePrivateKeyControlStore(privateKeyControlStore)
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
        authManager = nil
        privateKeyControlStore = nil
        defaultsSuiteName = nil
        super.tearDown()
    }

    @MainActor
    func test_handleAuthModeSelection_withoutBackup_routesCallbackRequestWithRiskAcknowledgement() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        var capturedRequest: AuthModeChangeConfirmationRequest?
        var configuration = SettingsView.Configuration()
        configuration.onAuthModeConfirmationRequested = { request in
            capturedRequest = request
        }

        let model = makeModel(configuration: configuration)
        model.handleAuthModeSelection(.highSecurity)

        let request = try XCTUnwrap(capturedRequest)
        XCTAssertEqual(model.pendingMode, .highSecurity)
        XCTAssertNil(model.presentedAuthModeRequest)
        XCTAssertEqual(request.pendingMode, .highSecurity)
        XCTAssertTrue(request.requiresRiskAcknowledgement)
        XCTAssertFalse(request.title.isEmpty)
        XCTAssertFalse(request.message.isEmpty)
    }

    @MainActor
    func test_handleAuthModeSelection_withoutExternalPresenter_usesLocalSheetRequest() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        let model = makeModel()
        model.handleAuthModeSelection(.highSecurity)

        XCTAssertEqual(model.pendingMode, .highSecurity)
        XCTAssertNotNil(model.presentedAuthModeRequest)
        XCTAssertTrue(model.usesLocalModeSheet)
    }

    @MainActor
    func test_handleAuthModeSelection_withMacPresentationController_routesThroughMacHost() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        var capturedPresentation: MacPresentation?
        let macPresentationController = MacPresentationController(
            present: { presentation in
                capturedPresentation = presentation
            },
            dismiss: {}
        )

        let model = makeModel(macPresentationController: macPresentationController)
        model.handleAuthModeSelection(.highSecurity)

        guard case .authModeConfirmation(let request) = capturedPresentation else {
            return XCTFail("Expected auth-mode confirmation presentation")
        }

        XCTAssertEqual(model.pendingMode, .highSecurity)
        XCTAssertNil(model.presentedAuthModeRequest)
        XCTAssertEqual(request.pendingMode, .highSecurity)
        XCTAssertTrue(request.requiresRiskAcknowledgement)
    }

    @MainActor
    func test_confirmedModeSwitch_updatesConfigAndClearsPendingState() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        config.privateKeyControlState = .unlocked(.highSecurity)

        var receivedMode: AuthenticationMode?
        var receivedFingerprints: [String] = []
        var receivedHasBackup = false

        let model = makeModel(authModeSwitchAction: { newMode, fingerprints, hasBackup in
            receivedMode = newMode
            receivedFingerprints = fingerprints
            receivedHasBackup = hasBackup
        })

        model.handleAuthModeSelection(.standard)
        let request = try XCTUnwrap(model.presentedAuthModeRequest)
        request.onConfirm()

        await waitUntil("mode switch to finish") {
            model.isSwitching == false
        }

        XCTAssertEqual(receivedMode, .standard)
        XCTAssertEqual(receivedFingerprints, stack.keyManagement.keys.map(\.fingerprint))
        XCTAssertFalse(receivedHasBackup)
        XCTAssertEqual(config.authModeIfUnlocked, .standard)
        XCTAssertNil(model.pendingMode)
        XCTAssertNil(model.presentedAuthModeRequest)
    }

    @MainActor
    func test_modeSwitchFailure_surfacesErrorState() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        let model = makeModel(authModeSwitchAction: { _, _, _ in
            throw SettingsScreenModelTestError(message: "Switch failed")
        })

        model.handleAuthModeSelection(.highSecurity)
        let request = try XCTUnwrap(model.presentedAuthModeRequest)
        request.onConfirm()

        await waitUntil("failed mode switch to finish") {
            model.isSwitching == false
        }

        XCTAssertTrue(model.showSwitchError)
        XCTAssertEqual(model.switchError, "Switch failed")
        XCTAssertEqual(config.authModeIfUnlocked, .standard)
        XCTAssertNil(model.pendingMode)
    }

    @MainActor
    func test_modeSwitchFailureMarksRecoveryWhenCurrentModeUnavailable() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        let model = makeModel(authModeSwitchAction: { [self] newMode, _, _ in
            try privateKeyControlStore.beginRewrap(targetMode: newMode)
            try privateKeyControlStore.markRewrapCommitRequired()
            throw SettingsScreenModelTestError(message: "Switch failed after commit")
        })

        model.handleAuthModeSelection(.highSecurity)
        let request = try XCTUnwrap(model.presentedAuthModeRequest)
        request.onConfirm()

        await waitUntil("failed committed mode switch to finish") {
            model.isSwitching == false
        }

        XCTAssertTrue(model.showSwitchError)
        XCTAssertEqual(model.switchError, "Switch failed after commit")
        XCTAssertEqual(config.privateKeyControlState, .recoveryNeeded)
        XCTAssertNil(model.pendingMode)
    }

    @MainActor
    func test_appAccessPolicySelection_updatesConfigAfterSwitchAction() async {
        var receivedPolicy: AppSessionAuthenticationPolicy?
        let model = makeModel(appAccessPolicySwitchAction: { policy in
            receivedPolicy = policy
        })

        model.handleAppAccessPolicySelection(.biometricsOnly)

        await waitUntil("app access policy switch to finish") {
            model.isSwitchingAppAccessPolicy == false
        }

        XCTAssertEqual(receivedPolicy, .biometricsOnly)
        XCTAssertEqual(config.appSessionAuthenticationPolicy, .biometricsOnly)
    }

    @MainActor
    func test_appAccessPolicySelection_failureSurfacesErrorAndKeepsConfig() async {
        let model = makeModel(appAccessPolicySwitchAction: { _ in
            throw SettingsScreenModelTestError(message: "App access switch failed")
        })

        model.handleAppAccessPolicySelection(.biometricsOnly)

        await waitUntil("failed app access policy switch to finish") {
            model.isSwitchingAppAccessPolicy == false
        }

        XCTAssertTrue(model.showSwitchError)
        XCTAssertEqual(model.switchError, "App access switch failed")
        XCTAssertEqual(config.appSessionAuthenticationPolicy, .userPresence)
    }

    @MainActor
    func test_staleRequestConfirm_executesItsCapturedMode() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        var capturedRequests: [AuthModeChangeConfirmationRequest] = []
        var receivedModes: [AuthenticationMode] = []
        var configuration = SettingsView.Configuration()
        configuration.onAuthModeConfirmationRequested = { request in
            capturedRequests.append(request)
        }

        let model = makeModel(configuration: configuration, authModeSwitchAction: { newMode, _, _ in
            receivedModes.append(newMode)
        })

        model.handleAuthModeSelection(.highSecurity)
        let firstRequest = try XCTUnwrap(capturedRequests.first)

        config.privateKeyControlState = .unlocked(.highSecurity)
        model.handleAuthModeSelection(.standard)

        XCTAssertEqual(capturedRequests.count, 2)
        XCTAssertEqual(model.pendingMode, .standard)

        firstRequest.onConfirm()

        await waitUntil("stale request confirm to finish") {
            model.isSwitching == false
        }

        XCTAssertEqual(receivedModes, [.highSecurity])
        XCTAssertEqual(config.authModeIfUnlocked, .highSecurity)
        XCTAssertEqual(model.pendingMode, .standard)
    }

    @MainActor
    func test_staleRequestCancel_doesNotClearNewerPendingRequest() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        var capturedRequests: [AuthModeChangeConfirmationRequest] = []
        var receivedModes: [AuthenticationMode] = []
        var configuration = SettingsView.Configuration()
        configuration.onAuthModeConfirmationRequested = { request in
            capturedRequests.append(request)
        }

        let model = makeModel(configuration: configuration, authModeSwitchAction: { newMode, _, _ in
            receivedModes.append(newMode)
        })

        model.handleAuthModeSelection(.highSecurity)
        let firstRequest = try XCTUnwrap(capturedRequests.first)

        config.privateKeyControlState = .unlocked(.highSecurity)
        model.handleAuthModeSelection(.standard)
        let secondRequest = try XCTUnwrap(capturedRequests.last)

        firstRequest.onCancel()

        XCTAssertEqual(model.pendingMode, .standard)

        secondRequest.onConfirm()

        await waitUntil("newer request confirm to finish") {
            model.isSwitching == false
        }

        XCTAssertEqual(receivedModes, [.standard])
        XCTAssertEqual(config.authModeIfUnlocked, .standard)
        XCTAssertNil(model.pendingMode)
    }

    @MainActor
    func test_tutorialConfiguration_routesRequestToTutorialStore() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        let store = TutorialSessionStore()

        let model = makeModel(configuration: store.configurationFactory.settingsConfiguration())
        model.handleAuthModeSelection(.highSecurity)

        guard case .authModeConfirmation(let request)? = store.activeModal else {
            return XCTFail("Expected tutorial auth-mode modal")
        }

        XCTAssertEqual(request.pendingMode, .highSecurity)
        XCTAssertTrue(request.requiresRiskAcknowledgement)
    }

    @MainActor
    func test_presentTutorial_withIOSPresentationController_routesThroughAppRootTutorialHost() {
        var capturedPresentation: IOSPresentation?
        let iosPresentationController = IOSPresentationController(
            present: { presentation in
                capturedPresentation = presentation
            },
            dismiss: {},
            handoffToTutorialAfterOnboardingDismiss: { _ in }
        )

        let model = makeModel(iosPresentationController: iosPresentationController)
        model.presentTutorial()

        guard case .tutorial(let presentationContext)? = capturedPresentation else {
            return XCTFail("Expected tutorial presentation through the iOS app-root host")
        }

        XCTAssertEqual(presentationContext, .inApp)
        XCTAssertFalse(model.showTutorialOnboarding)
    }

    @MainActor
    func test_presentTutorial_withMacPresentationController_routesThroughLocalMacHost() {
        var capturedPresentation: MacPresentation?
        let macPresentationController = MacPresentationController(
            present: { presentation in
                capturedPresentation = presentation
            },
            dismiss: {}
        )

        let model = makeModel(macPresentationController: macPresentationController)
        model.presentTutorial()

        guard case .tutorial(let presentationContext)? = capturedPresentation else {
            return XCTFail("Expected tutorial presentation through the macOS host")
        }

        XCTAssertEqual(presentationContext, .inApp)
        XCTAssertFalse(model.showTutorialOnboarding)
    }

    @MainActor
    func test_launchPreviewRequest_usesSharedHighSecurityWarningWithoutRiskAcknowledgement() {
        let request = SettingsAuthModeRequestBuilder.makeLaunchPreviewRequest()

        XCTAssertEqual(request.pendingMode, .highSecurity)
        XCTAssertFalse(request.requiresRiskAcknowledgement)
        XCTAssertFalse(request.title.isEmpty)
        XCTAssertFalse(request.message.isEmpty)
    }

    @MainActor
    func test_settingsSceneProxy_configuration_exposesProxyProtectedSettingsStateAndAction() {
        var didOpenMainWindow = false
        var configuration = SettingsView.Configuration.default
        configuration.protectedSettingsHostMode = .settingsSceneProxy
        configuration.protectedSettingsHost = CypherAir.ProtectedSettingsHost(
            mode: .settingsSceneProxy,
            openMainWindowAction: {
                didOpenMainWindow = true
            }
        )

        let model = makeModel(configuration: configuration)

        XCTAssertEqual(model.protectedSettingsSectionState, .settingsSceneProxy)
        model.openProtectedSettingsInMainWindow()
        XCTAssertTrue(didOpenMainWindow)
    }

    @MainActor
    func test_tutorialSettings_configuration_usesTutorialProtectedSettingsState() {
        let store = TutorialSessionStore()
        let model = makeModel(configuration: store.configurationFactory.settingsConfiguration())

        XCTAssertEqual(model.protectedSettingsSectionState, .tutorialSandbox)
    }

    @MainActor
    func test_localDataReset_defaultConfigurationWithService_showsEnabledSectionAndRequestWarning() {
        let resetContainer = AppContainer.makeUITest()
        defer { cleanup(resetContainer) }

        let model = makeModel(localDataResetService: resetContainer.localDataResetService)

        XCTAssertTrue(model.shouldShowLocalDataResetSection)
        XCTAssertTrue(model.isLocalDataResetControlEnabled)
        XCTAssertEqual(
            model.localDataResetFooter,
            String(
                localized: "settings.resetAll.footer",
                defaultValue: "Use this only when you want this device to behave like a fresh CypherAir install."
            )
        )

        model.requestLocalDataReset()

        XCTAssertTrue(model.showLocalDataResetWarning)
    }

    @MainActor
    func test_localDataReset_defaultConfigurationWithoutService_hidesSection() {
        let model = makeModel()

        XCTAssertFalse(model.shouldShowLocalDataResetSection)
        XCTAssertFalse(model.isLocalDataResetControlEnabled)
    }

    @MainActor
    func test_localDataReset_tutorialConfigurationWithService_showsDisabledSectionAndBlocksRequest() {
        let resetContainer = AppContainer.makeUITest()
        defer { cleanup(resetContainer) }
        let store = TutorialSessionStore()
        let model = makeModel(
            configuration: store.configurationFactory.settingsConfiguration(),
            localDataResetService: resetContainer.localDataResetService
        )

        XCTAssertTrue(model.shouldShowLocalDataResetSection)
        XCTAssertFalse(model.isLocalDataResetControlEnabled)
        XCTAssertEqual(
            model.localDataResetFooter,
            String(
                localized: "guidedTutorial.settings.restricted.localDataReset",
                defaultValue: "The tutorial sandbox cannot reset real CypherAir data."
            )
        )

        model.requestLocalDataReset()

        XCTAssertFalse(model.showLocalDataResetWarning)
    }

    @MainActor
    func test_localDataReset_successMarksRestartRequiredWithoutResultAlert() async {
        let resetContainer = AppContainer.makeUITest()
        defer { cleanup(resetContainer) }
        let restartCoordinator = LocalDataResetRestartCoordinator()
        let model = makeModel(
            localDataResetService: resetContainer.localDataResetService,
            localDataResetRestartCoordinator: restartCoordinator
        )

        model.requestLocalDataReset()
        model.continueLocalDataReset()
        model.localDataResetConfirmationPhrase = "RESET"
        model.confirmLocalDataReset()

        await waitUntil("reset restart gate", timeout: 30) {
            restartCoordinator.restartRequiredAfterLocalDataReset
        }
        XCTAssertFalse(model.showLocalDataResetResultAlert)
        XCTAssertNotNil(restartCoordinator.resetSummary)
    }

    @MainActor
    func test_liveProtectedSettingsHost_authorizationRequired_preservesRecoveryNeededOnRefresh() async {
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .recoveryNeeded
        var authorizeCallCount = 0
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data() },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()

        XCTAssertEqual(host.sectionState, .recoveryNeeded)
        XCTAssertEqual(authorizeCallCount, 0)
        _ = domainState
    }

    @MainActor
    func test_liveProtectedSettingsHost_authorizationRequired_refreshLeavesLockedState() async {
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { .locked },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()

        XCTAssertEqual(authorizeCallCount, 0)
        XCTAssertEqual(openDomainCallCount, 0)
        XCTAssertEqual(host.sectionState, .locked)
    }

    @MainActor
    func test_liveProtectedSettingsHost_authorizationRequired_refreshAutoOpensWithHandoff() async {
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .locked
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            hasAuthorizationHandoffContext: { true },
            authorizeSharedRight: { _, interactionMode in
                authorizeCallCount += 1
                XCTAssertEqual(interactionMode, .handoffOnly)
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? false : nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()

        XCTAssertEqual(authorizeCallCount, 1)
        XCTAssertEqual(openDomainCallCount, 1)
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))
    }

    @MainActor
    func test_liveProtectedSettingsHost_authorizationRequired_handoffMissingBeforeAuthorizationStaysLocked() async {
        var handoffCheckCount = 0
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            hasAuthorizationHandoffContext: {
                handoffCheckCount += 1
                return handoffCheckCount == 1
            },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { .locked },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()

        XCTAssertEqual(handoffCheckCount, 2)
        XCTAssertEqual(authorizeCallCount, 0)
        XCTAssertEqual(openDomainCallCount, 0)
        XCTAssertEqual(host.sectionState, .locked)
    }

    @MainActor
    func test_liveProtectedSettingsHost_noProtectedDomainPresent_refreshLeavesLockedState() async {
        var authorizeCallCount = 0
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .noProtectedDomainPresent },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data() },
            syncPreAuthorizationState: {},
            currentDomainState: { .locked },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                XCTFail("Refresh should not open protected settings when no domain is present")
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()

        XCTAssertEqual(host.sectionState, .locked)
        XCTAssertEqual(authorizeCallCount, 0)
    }

    @MainActor
    func test_liveProtectedSettingsHost_noProtectedDomainPresent_unlockMigratesAndOpens() async {
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .locked
        var migrateCallCount = 0
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .noProtectedDomainPresent },
            authorizeSharedRight: { _, interactionMode in
                authorizeCallCount += 1
                XCTAssertEqual(interactionMode, .allowInteraction)
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? false : nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {
                migrateCallCount += 1
                domainState = .locked
            },
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.unlockForSettings()

        XCTAssertEqual(migrateCallCount, 1)
        XCTAssertEqual(authorizeCallCount, 1)
        XCTAssertEqual(openDomainCallCount, 1)
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))
    }

    @MainActor
    func test_liveProtectedSettingsHost_noProtectedDomainPresent_authorizesBeforeSecondDomainMigration() async {
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .locked
        var events: [String] = []
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .noProtectedDomainPresent },
            authorizeSharedRight: { _, interactionMode in
                events.append("authorize")
                XCTAssertEqual(interactionMode, .allowInteraction)
                return .authorized
            },
            currentWrappingRootKey: {
                events.append("wrappingRootKey")
                return Data(repeating: 0xAA, count: 32)
            },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? true : nil },
            migrationAuthorizationRequirement: { .wrappingRootKeyRequired },
            ensureCommittedAndMigrateSettingsIfNeeded: {
                events.append("migrate")
                domainState = .locked
            },
            openDomainIfNeeded: { _ in
                events.append("open")
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.unlockForSettings()

        XCTAssertEqual(
            events,
            ["authorize", "wrappingRootKey", "migrate", "wrappingRootKey", "open"]
        )
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: true))
    }

    @MainActor
    func test_liveProtectedSettingsHost_authorizationRequired_createsSettingsDomainBeforeOpening() async {
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .locked
        var didAuthorize = false
        var events: [String] = []
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _, interactionMode in
                events.append("authorize")
                didAuthorize = true
                XCTAssertEqual(interactionMode, .allowInteraction)
                return .authorized
            },
            currentWrappingRootKey: {
                events.append("wrappingRootKey")
                return Data(repeating: 0xAA, count: 32)
            },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? false : nil },
            migrationAuthorizationRequirement: { .wrappingRootKeyRequired },
            ensureCommittedAndMigrateSettingsIfNeeded: {
                XCTAssertTrue(didAuthorize)
                events.append("migrate")
                domainState = .locked
            },
            openDomainIfNeeded: { _ in
                events.append("open")
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.unlockForSettings()

        XCTAssertEqual(events, ["authorize", "migrate", "wrappingRootKey", "open"])
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))
    }

    @MainActor
    func test_liveProtectedSettingsHost_noProtectedDomainPresent_migrationFailureDoesNotReturnLocked() async {
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .noProtectedDomainPresent },
            authorizeSharedRight: { _, _ in
                XCTFail("Migration failure should happen before authorization")
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { .locked },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {
                throw ProtectedDataError.invalidRegistry("test")
            },
            openDomainIfNeeded: { _ in
                XCTFail("Migration failure should not open protected settings")
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.unlockForSettings()

        XCTAssertEqual(host.sectionState, .frameworkUnavailable)
    }

    @MainActor
    func test_liveProtectedSettingsHost_alreadyAuthorized_refreshAutoOpensAvailableState() async {
        var openDomainCallCount = 0
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .locked
        var clipboardNotice = false
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .alreadyAuthorized },
            authorizeSharedRight: { _, _ in
                XCTFail("Already-authorized refresh should not prompt again")
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? clipboardNotice : nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()

        XCTAssertEqual(openDomainCallCount, 1)
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))
    }

    @MainActor
    func test_liveProtectedSettingsHost_authorizationRequired_refreshCancellationLeavesLocked() async {
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _, _ in .cancelledOrDenied },
            currentWrappingRootKey: { Data(repeating: 0xBB, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { .locked },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                XCTFail("Protected settings should not open after cancelled authorization")
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()

        XCTAssertEqual(host.sectionState, .locked)
    }

    @MainActor
    func test_liveProtectedSettingsHost_unlockForSettings_shortCircuitsRecoveryNeededWithoutAuthorization() async {
        var authorizeCallCount = 0
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data() },
            syncPreAuthorizationState: {},
            currentDomainState: { .recoveryNeeded },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                XCTFail("Protected settings should not open while recovery is required")
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.unlockForSettings()

        XCTAssertEqual(host.sectionState, .recoveryNeeded)
        XCTAssertEqual(authorizeCallCount, 0)
    }

    @MainActor
    func test_liveProtectedSettingsHost_unlockForSettings_authorizesAndOpensAvailableState() async {
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .locked
        var clipboardNotice = false
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? clipboardNotice : nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.unlockForSettings()

        XCTAssertEqual(authorizeCallCount, 1)
        XCTAssertEqual(openDomainCallCount, 1)
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))
    }

    @MainActor
    func test_liveProtectedSettingsHost_clipboardNoticeDecision_lockedReturnsDefaultWithoutAuthorization() async {
        var authorizeCallCount = 0
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { .locked },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                XCTFail("Clipboard preference reads should not unlock protected settings when locked")
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        let shouldShowNotice = await host.clipboardNoticeDecision()

        XCTAssertTrue(shouldShowNotice)
        XCTAssertEqual(authorizeCallCount, 0)
        XCTAssertEqual(host.sectionState, .locked)
    }

    @MainActor
    func test_liveProtectedSettingsHost_clipboardNoticeDecision_alreadyAuthorizedReturnsStoredPreference() async {
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .alreadyAuthorized },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { .unlocked },
            currentClipboardNotice: { false },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        let shouldShowNotice = await host.clipboardNoticeDecision()

        XCTAssertFalse(shouldShowNotice)
        XCTAssertEqual(authorizeCallCount, 0)
        XCTAssertEqual(openDomainCallCount, 1)
    }

    @MainActor
    func test_liveProtectedSettingsHost_disableClipboardNotice_authorizesAndPersistsPreference() async {
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        var updateClipboardNoticeCallCount = 0
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .locked
        var clipboardNotice = true
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? clipboardNotice : nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
                domainState = .unlocked
            },
            updateClipboardNotice: { isEnabled, _ in
                updateClipboardNoticeCallCount += 1
                clipboardNotice = isEnabled
            },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.disableClipboardNotice()

        XCTAssertEqual(authorizeCallCount, 1)
        XCTAssertEqual(openDomainCallCount, 1)
        XCTAssertEqual(updateClipboardNoticeCallCount, 1)
        XCTAssertFalse(clipboardNotice)
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))
    }

    @MainActor
    func test_liveProtectedSettingsHost_refreshShortCircuitsPendingStateWithoutAuthorization() async {
        var authorizeCallCount = 0
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data() },
            syncPreAuthorizationState: {},
            currentDomainState: { .pendingRetryRequired },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                XCTFail("Warm-up should not open protected settings while pending recovery is required")
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()

        XCTAssertEqual(host.sectionState, .pendingRetryRequired)
        XCTAssertEqual(authorizeCallCount, 0)
    }

    @MainActor
    func test_liveProtectedSettingsHost_resetAuthorizesBeforeResetWhenWrappingKeyRequired() async {
        var events: [String] = []
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .pendingResetRequired
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .pendingMutationRecoveryRequired },
            authorizeSharedRight: { _, interactionMode in
                events.append("authorize")
                XCTAssertEqual(interactionMode, .allowInteraction)
                return .authorized
            },
            currentWrappingRootKey: {
                events.append("wrappingKey")
                return Data(repeating: 0xAA, count: 32)
            },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetAuthorizationRequirement: {
                events.append("requirement")
                return .wrappingRootKeyRequired
            },
            resetDomain: {
                events.append("reset")
                domainState = .pendingResetRequired
            }
        )

        await host.resetProtectedSettingsDomain()

        XCTAssertEqual(events, ["requirement", "authorize", "wrappingKey", "reset"])
        XCTAssertEqual(host.sectionState, .pendingResetRequired)
    }

    @MainActor
    func test_liveProtectedSettingsHost_resetCancellationDoesNotReset() async {
        var events: [String] = []
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .pendingMutationRecoveryRequired },
            authorizeSharedRight: { _, _ in
                events.append("authorize")
                return .cancelledOrDenied
            },
            currentWrappingRootKey: {
                XCTFail("Cancelled reset should not read the wrapping key.")
                return Data(repeating: 0xAA, count: 32)
            },
            syncPreAuthorizationState: {},
            currentDomainState: { .pendingResetRequired },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetAuthorizationRequirement: {
                events.append("requirement")
                return .wrappingRootKeyRequired
            },
            resetDomain: {
                XCTFail("Cancelled reset must not delete protected settings.")
            }
        )

        await host.resetProtectedSettingsDomain()

        XCTAssertEqual(events, ["requirement", "authorize"])
        XCTAssertEqual(host.sectionState, .pendingResetRequired)
    }

    @MainActor
    func test_liveProtectedSettingsHost_firstDomainResetDoesNotRequireAuthorization() async {
        var events: [String] = []
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .pendingResetRequired
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .pendingMutationRecoveryRequired },
            authorizeSharedRight: { _, _ in
                XCTFail("First-domain reset should not force protected-data authorization.")
                return .authorized
            },
            currentWrappingRootKey: {
                XCTFail("First-domain reset should not read the wrapping key.")
                return Data(repeating: 0xAA, count: 32)
            },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetAuthorizationRequirement: {
                events.append("requirement")
                return .notRequired
            },
            resetDomain: {
                events.append("reset")
                domainState = .pendingResetRequired
            }
        )

        await host.resetProtectedSettingsDomain()

        XCTAssertEqual(events, ["requirement", "reset"])
        XCTAssertEqual(host.sectionState, .pendingResetRequired)
    }

    @MainActor
    func test_liveProtectedSettingsHost_retryAuthorizesBeforeRecoveringWhenWrappingKeyRequired() async {
        var events: [String] = []
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .pendingMutationRecoveryRequired },
            authorizeSharedRight: { _, interactionMode in
                events.append("authorize")
                XCTAssertEqual(interactionMode, .requireReusableContext)
                return .authorized
            },
            currentWrappingRootKey: {
                events.append("wrappingKey")
                return Data(repeating: 0xAA, count: 32)
            },
            syncPreAuthorizationState: {},
            currentDomainState: { .pendingRetryRequired },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in },
            updateClipboardNotice: { _, _ in },
            pendingRecoveryAuthorizationRequirement: {
                events.append("requirement")
                return .wrappingRootKeyRequired
            },
            recoverPendingMutation: {
                events.append("recover")
                return .retryablePending
            },
            resetDomain: {}
        )

        await host.retryPendingRecovery()

        XCTAssertEqual(events, ["requirement", "authorize", "wrappingKey", "recover"])
        XCTAssertEqual(host.sectionState, .pendingRetryRequired)
    }

    @MainActor
    func test_liveProtectedSettingsHost_retryPassesAuthorizationContextToRecovery() async {
        var events: [String] = []
        let authenticationContext = LAContext()
        var recoveredContext: LAContext?
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .pendingMutationRecoveryRequired },
            authorizeSharedRight: { _, interactionMode in
                events.append("authorize")
                XCTAssertEqual(interactionMode, .requireReusableContext)
                return .authorizedWithContext(authenticationContext)
            },
            currentWrappingRootKey: {
                events.append("wrappingKey")
                return Data(repeating: 0xAA, count: 32)
            },
            syncPreAuthorizationState: {},
            currentDomainState: { .pendingRetryRequired },
            currentClipboardNotice: { nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in },
            updateClipboardNotice: { _, _ in },
            pendingRecoveryAuthorizationRequirement: {
                events.append("requirement")
                return .wrappingRootKeyRequired
            },
            recoverPendingMutation: {
                XCTFail("Retry recovery should use the context-aware dependency.")
                return .retryablePending
            },
            recoverPendingMutationWithContext: { context in
                events.append("recover")
                recoveredContext = context
                XCTAssertTrue(context === authenticationContext)
                return .retryablePending
            },
            resetDomain: {}
        )

        await host.retryPendingRecovery()

        XCTAssertEqual(events, ["requirement", "authorize", "wrappingKey", "recover"])
        XCTAssertTrue(recoveredContext === authenticationContext)
        XCTAssertEqual(host.sectionState, .pendingRetryRequired)
    }

    @MainActor
    func test_liveProtectedSettingsHost_invalidateForContentClearGeneration_alreadyAuthorizedAutoOpens() async {
        var openDomainCallCount = 0
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .unlocked
        var clipboardNotice = false
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .alreadyAuthorized },
            authorizeSharedRight: { _, _ in
                XCTFail("Already-authorized invalidation should not prompt again")
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? clipboardNotice : nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))

        domainState = .locked
        clipboardNotice = true
        await host.invalidateForContentClearGeneration(1)

        XCTAssertEqual(openDomainCallCount, 1)
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: true))
    }

    @MainActor
    func test_liveProtectedSettingsHost_invalidateForContentClearGeneration_autoOpensWithHandoff() async {
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .unlocked
        var clipboardNotice = false
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            hasAuthorizationHandoffContext: { true },
            authorizeSharedRight: { _, interactionMode in
                authorizeCallCount += 1
                XCTAssertEqual(interactionMode, .handoffOnly)
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? clipboardNotice : nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))

        domainState = .locked
        clipboardNotice = true
        await host.invalidateForContentClearGeneration(1)

        XCTAssertEqual(authorizeCallCount, 1)
        XCTAssertEqual(openDomainCallCount, 1)
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: true))
    }

    @MainActor
    func test_liveProtectedSettingsHost_invalidateForContentClearGeneration_handoffMissingStaysLocked() async {
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .unlocked
        var clipboardNotice = false
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            hasAuthorizationHandoffContext: { false },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? clipboardNotice : nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))

        domainState = .locked
        clipboardNotice = true
        await host.invalidateForContentClearGeneration(1)

        // Content clear can be an intermediate state before post-auth refresh
        // re-syncs the section with the reopened protected settings domain.
        XCTAssertEqual(authorizeCallCount, 0)
        XCTAssertEqual(openDomainCallCount, 0)
        XCTAssertEqual(host.sectionState, .locked)
    }

    @MainActor
    func test_liveProtectedSettingsHost_postAuthenticationRefreshClearsStaleLockedSectionState() async {
        var authorizeCallCount = 0
        var openDomainCallCount = 0
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .unlocked
        var clipboardNotice = false
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            hasAuthorizationHandoffContext: { false },
            authorizeSharedRight: { _, _ in
                authorizeCallCount += 1
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0xAA, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { domainState == .unlocked ? clipboardNotice : nil },
            ensureCommittedAndMigrateSettingsIfNeeded: {},
            openDomainIfNeeded: { _ in
                openDomainCallCount += 1
                domainState = .unlocked
            },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: false))

        domainState = .locked
        clipboardNotice = true
        await host.invalidateForContentClearGeneration(1)

        XCTAssertEqual(host.sectionState, .locked)

        domainState = .unlocked
        await host.refreshAfterAppAuthenticationGeneration(1)

        XCTAssertEqual(authorizeCallCount, 0)
        XCTAssertEqual(openDomainCallCount, 0)
        XCTAssertEqual(host.sectionState, .available(clipboardNoticeEnabled: true))
    }

    @MainActor
    private func makeModel(
        configuration: SettingsView.Configuration = .default,
        iosPresentationController: IOSPresentationController? = nil,
        macPresentationController: MacPresentationController? = nil,
        localDataResetService: LocalDataResetService? = nil,
        localDataResetRestartCoordinator: LocalDataResetRestartCoordinator? = nil,
        authModeSwitchAction: SettingsScreenModel.AuthModeSwitchAction? = nil,
        appAccessPolicySwitchAction: SettingsScreenModel.AppAccessPolicySwitchAction? = nil
    ) -> SettingsScreenModel {
        SettingsScreenModel(
            config: config,
            protectedOrdinarySettings: protectedOrdinarySettings,
            authManager: authManager,
            keyManagement: stack.keyManagement,
            iosPresentationController: iosPresentationController,
            macPresentationController: macPresentationController,
            configuration: configuration,
            localDataResetService: localDataResetService,
            localDataResetRestartCoordinator: localDataResetRestartCoordinator,
            authModeSwitchAction: authModeSwitchAction,
            appAccessPolicySwitchAction: appAccessPolicySwitchAction
        )
    }

    private func cleanup(_ container: AppContainer) {
        try? FileManager.default.removeItem(
            at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
        )
        if let contactsDirectory = container.contactsDirectory {
            try? FileManager.default.removeItem(at: contactsDirectory)
        }
        if let defaultsSuiteName = container.defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
        }
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
