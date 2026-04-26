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
        XCTAssertEqual(config.authMode, .standard)
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
        XCTAssertEqual(config.authMode, .standard)
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

        let model = makeModel(configuration: configuration, authModeSwitchAction: { newMode, _, _ in
            receivedModes.append(newMode)
        })

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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
            migrateLegacyClipboardNoticeIfNeeded: {},
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
    func test_liveProtectedSettingsHost_invalidateForContentClearGeneration_reloadsLockedState() async {
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .unlocked
        var clipboardNotice = false
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .alreadyAuthorized },
            authorizeSharedRight: { _, _ in .authorized },
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
        authModeSwitchAction: SettingsScreenModel.AuthModeSwitchAction? = nil,
        appAccessPolicySwitchAction: SettingsScreenModel.AppAccessPolicySwitchAction? = nil
    ) -> SettingsScreenModel {
        SettingsScreenModel(
            config: config,
            authManager: authManager,
            keyManagement: stack.keyManagement,
            iosPresentationController: iosPresentationController,
            macPresentationController: macPresentationController,
            configuration: configuration,
            authModeSwitchAction: authModeSwitchAction,
            appAccessPolicySwitchAction: appAccessPolicySwitchAction
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
