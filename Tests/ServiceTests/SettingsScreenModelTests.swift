import Foundation
import XCTest
@testable import CypherAir

private struct SettingsScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

final class SettingsScreenModelTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!
    private var config: AppConfiguration!
    private var authManager: AuthenticationManager!
    private var defaultsSuiteName: String!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
        defaultsSuiteName = "com.cypherair.tests.settingsscreen.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        config = AppConfiguration(defaults: defaults)
        authManager = AuthenticationManager(
            secureEnclave: stack.mockSE,
            keychain: stack.mockKC,
            defaults: defaults
        )
    }

    override func tearDown() {
        if let defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?
                .removePersistentDomain(forName: defaultsSuiteName)
        }
        stack.cleanup()
        stack = nil
        config = nil
        authManager = nil
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
        config.authMode = .highSecurity

        var receivedMode: AuthenticationMode?
        var receivedFingerprints: [String] = []
        var receivedHasBackup = false

        let model = makeModel { newMode, fingerprints, hasBackup in
            receivedMode = newMode
            receivedFingerprints = fingerprints
            receivedHasBackup = hasBackup
        }

        model.handleAuthModeSelection(.standard)
        let request = try XCTUnwrap(model.presentedAuthModeRequest)
        request.onConfirm()

        await waitUntil("mode switch to finish") {
            model.isSwitching == false
        }

        XCTAssertEqual(receivedMode, .standard)
        XCTAssertEqual(receivedFingerprints, stack.keyManagement.keys.map(\.fingerprint))
        XCTAssertFalse(receivedHasBackup)
        XCTAssertEqual(config.authMode, .standard)
        XCTAssertNil(model.pendingMode)
        XCTAssertNil(model.presentedAuthModeRequest)
    }

    @MainActor
    func test_modeSwitchFailure_surfacesErrorState() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        let model = makeModel { _, _, _ in
            throw SettingsScreenModelTestError(message: "Switch failed")
        }

        model.handleAuthModeSelection(.highSecurity)
        let request = try XCTUnwrap(model.presentedAuthModeRequest)
        request.onConfirm()

        await waitUntil("failed mode switch to finish") {
            model.isSwitching == false
        }

        XCTAssertTrue(model.showSwitchError)
        XCTAssertEqual(model.switchError, "Switch failed")
        XCTAssertEqual(config.authMode, .standard)
        XCTAssertNil(model.pendingMode)
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

        let model = makeModel(configuration: configuration) { newMode, _, _ in
            receivedModes.append(newMode)
        }

        model.handleAuthModeSelection(.highSecurity)
        let firstRequest = try XCTUnwrap(capturedRequests.first)

        config.authMode = .highSecurity
        model.handleAuthModeSelection(.standard)

        XCTAssertEqual(capturedRequests.count, 2)
        XCTAssertEqual(model.pendingMode, .standard)

        firstRequest.onConfirm()

        await waitUntil("stale request confirm to finish") {
            model.isSwitching == false
        }

        XCTAssertEqual(receivedModes, [.highSecurity])
        XCTAssertEqual(config.authMode, .highSecurity)
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

        let model = makeModel(configuration: configuration) { newMode, _, _ in
            receivedModes.append(newMode)
        }

        model.handleAuthModeSelection(.highSecurity)
        let firstRequest = try XCTUnwrap(capturedRequests.first)

        config.authMode = .highSecurity
        model.handleAuthModeSelection(.standard)
        let secondRequest = try XCTUnwrap(capturedRequests.last)

        firstRequest.onCancel()

        XCTAssertEqual(model.pendingMode, .standard)

        secondRequest.onConfirm()

        await waitUntil("newer request confirm to finish") {
            model.isSwitching == false
        }

        XCTAssertEqual(receivedModes, [.standard])
        XCTAssertEqual(config.authMode, .standard)
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
    func test_liveProtectedSettingsHost_authorizationRequired_preservesRecoveryNeededOnRefresh() async {
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .recoveryNeeded
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .authorizationRequired },
            authorizeSharedRight: { _ in .authorized },
            currentWrappingRootKey: { Data() },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { nil },
            migrateLegacyClipboardNoticeIfNeeded: {},
            openDomainIfNeeded: { _ in },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {}
        )

        await host.refreshSettingsSection()

        XCTAssertEqual(host.sectionState, .recoveryNeeded)
        _ = domainState
    }

    @MainActor
    func test_liveProtectedSettingsHost_invalidateForContentClearGeneration_reloadsLockedState() async {
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .unlocked
        var clipboardNotice = false
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .alreadyAuthorized },
            authorizeSharedRight: { _ in .authorized },
            currentWrappingRootKey: { Data() },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { clipboardNotice },
            migrateLegacyClipboardNoticeIfNeeded: {},
            openDomainIfNeeded: { _ in },
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
    }

    @MainActor
    private func makeModel(
        configuration: SettingsView.Configuration = .default,
        iosPresentationController: IOSPresentationController? = nil,
        macPresentationController: MacPresentationController? = nil,
        authModeSwitchAction: SettingsScreenModel.AuthModeSwitchAction? = nil
    ) -> SettingsScreenModel {
        SettingsScreenModel(
            config: config,
            authManager: authManager,
            keyManagement: stack.keyManagement,
            iosPresentationController: iosPresentationController,
            macPresentationController: macPresentationController,
            configuration: configuration,
            authModeSwitchAction: authModeSwitchAction
        )
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
