import Foundation

@MainActor
@Observable
final class SettingsScreenModel {
    typealias AuthModeSwitchAction = @MainActor (AuthenticationMode, [String], Bool) async throws -> Void

    let configuration: SettingsView.Configuration
    let appConfiguration: AppConfiguration
    let protectedSettingsHost: ProtectedSettingsHost?

    private let authManager: AuthenticationManager
    private let keyManagement: KeyManagementService
    private let iosPresentationController: IOSPresentationController?
    private let macPresentationController: MacPresentationController?
    private let authModeSwitchAction: AuthModeSwitchAction

    var pendingMode: AuthenticationMode?
    private var pendingModeRequestID: UUID?
    var presentedAuthModeRequest: AuthModeChangeConfirmationRequest?
    var isSwitching = false
    var switchError: String?
    var showSwitchError = false
    var showOnboarding = false
    var showTutorialOnboarding = false
    var showProtectedSettingsResetConfirmation = false

    init(
        config: AppConfiguration,
        authManager: AuthenticationManager,
        keyManagement: KeyManagementService,
        iosPresentationController: IOSPresentationController?,
        macPresentationController: MacPresentationController?,
        configuration: SettingsView.Configuration,
        authModeSwitchAction: AuthModeSwitchAction? = nil
    ) {
        self.configuration = configuration
        self.appConfiguration = config
        self.protectedSettingsHost = configuration.protectedSettingsHost
        self.authManager = authManager
        self.keyManagement = keyManagement
        self.iosPresentationController = iosPresentationController
        self.macPresentationController = macPresentationController
        self.authModeSwitchAction = authModeSwitchAction ?? { newMode, fingerprints, hasBackup in
            try await authManager.switchMode(
                to: newMode,
                fingerprints: fingerprints,
                hasBackup: hasBackup,
                authenticator: authManager
            )
        }
    }

    var guidedTutorialEntryTitle: String {
        switch appConfiguration.guidedTutorialCompletionState {
        case .neverCompleted:
            String(localized: "guidedTutorial.settings.entry", defaultValue: "Guided Tutorial")
        case .completedCurrentVersion:
            String(localized: "guidedTutorial.replay", defaultValue: "Replay Guided Tutorial")
        case .completedPreviousVersion:
            String(localized: "guidedTutorial.updated.entry", defaultValue: "Updated Guided Tutorial Available")
        }
    }

    var protectedSettingsSectionState: ProtectedSettingsHost.SectionState {
        protectedSettingsHost?.sectionState ?? fallbackProtectedSettingsSectionState
    }

    var isProtectedClipboardNoticeEnabled: Bool {
        if case .available(let clipboardNoticeEnabled) = protectedSettingsSectionState {
            return clipboardNoticeEnabled
        }
        return true
    }

    var shouldShowProtectedSettingsSection: Bool {
        switch configuration.protectedSettingsHostMode {
        case .mainWindowLive, .settingsSceneProxy, .tutorialSandbox:
            true
        }
    }

    var usesLocalModeSheet: Bool {
        presentedAuthModeRequest?.requiresRiskAcknowledgement == true
    }

    var localModeTitle: String {
        presentedAuthModeRequest?.title ?? ""
    }

    var localModeMessage: String {
        presentedAuthModeRequest?.message ?? ""
    }

    func handleAuthModeSelection(_ newMode: AuthenticationMode) {
        guard newMode != appConfiguration.authMode else {
            return
        }

        let requestID = UUID()
        pendingMode = newMode
        pendingModeRequestID = requestID
        presentedAuthModeRequest = nil

        let request = SettingsAuthModeRequestBuilder.makeRequest(
            id: requestID,
            for: newMode,
            hasBackup: hasBackup
        ) { [weak self] in
            self?.confirmPendingModeChange(requestID: requestID, mode: newMode)
        } onCancel: { [weak self] in
            self?.cancelPendingModeChange(requestID: requestID)
        }

        if let onAuthModeConfirmationRequested = configuration.onAuthModeConfirmationRequested {
            onAuthModeConfirmationRequested(request)
        } else if let macPresentationController {
            macPresentationController.present(.authModeConfirmation(request))
        } else {
            presentedAuthModeRequest = request
        }
    }

    func dismissLocalModeRequest() {
        guard let request = presentedAuthModeRequest else { return }
        cancelPendingModeChange(requestID: request.id)
    }

    func dismissSwitchError() {
        switchError = nil
        showSwitchError = false
    }

    func presentOnboarding() {
        guard configuration.isOnboardingEntryEnabled else { return }

        #if !os(iOS)
        if let macPresentationController {
            macPresentationController.present(.onboarding(initialPage: 0))
        } else if let iosPresentationController {
            iosPresentationController.present(.onboarding(initialPage: 0, context: .inApp))
        } else {
            showOnboarding = true
        }
        #else
        if let macPresentationController {
            macPresentationController.present(.onboarding(initialPage: 0))
        } else if let iosPresentationController {
            iosPresentationController.present(.onboarding(initialPage: 0, context: .inApp))
        }
        #endif
    }

    func presentTutorial() {
        guard configuration.isGuidedTutorialEntryEnabled else { return }

        #if !os(iOS)
        if let macPresentationController {
            macPresentationController.present(.tutorial(presentationContext: .inApp))
        } else if let iosPresentationController {
            iosPresentationController.present(.tutorial(presentationContext: .inApp))
        } else {
            showTutorialOnboarding = true
        }
        #else
        if let macPresentationController {
            macPresentationController.present(.tutorial(presentationContext: .inApp))
        } else if let iosPresentationController {
            iosPresentationController.present(.tutorial(presentationContext: .inApp))
        }
        #endif
    }

    func prepareProtectedSettingsSection() async {
        await protectedSettingsHost?.refreshSettingsSection()
    }

    func requestProtectedSettingsUnlock() {
        Task {
            await protectedSettingsHost?.unlockForSettings()
        }
    }

    func setProtectedClipboardNoticeEnabled(_ isEnabled: Bool) {
        Task {
            await protectedSettingsHost?.setClipboardNoticeEnabled(isEnabled)
        }
    }

    func requestProtectedSettingsReset() {
        showProtectedSettingsResetConfirmation = true
    }

    func confirmProtectedSettingsReset() {
        showProtectedSettingsResetConfirmation = false
        Task {
            await protectedSettingsHost?.resetProtectedSettingsDomain()
        }
    }

    func dismissProtectedSettingsResetConfirmation() {
        showProtectedSettingsResetConfirmation = false
    }

    func openProtectedSettingsInMainWindow() {
        protectedSettingsHost?.openMainWindow()
    }

    private var hasBackup: Bool {
        keyManagement.keys.contains(where: \.isBackedUp)
    }

    private var fallbackProtectedSettingsSectionState: ProtectedSettingsHost.SectionState {
        switch configuration.protectedSettingsHostMode {
        case .mainWindowLive:
            .locked
        case .settingsSceneProxy:
            .settingsSceneProxy
        case .tutorialSandbox:
            .tutorialSandbox
        }
    }

    private func confirmPendingModeChange(
        requestID: UUID,
        mode: AuthenticationMode
    ) {
        if presentedAuthModeRequest?.id == requestID {
            presentedAuthModeRequest = nil
        }
        performModeSwitch(to: mode, requestID: requestID)
    }

    private func cancelPendingModeChange(requestID: UUID) {
        guard pendingModeRequestID == requestID else { return }

        pendingMode = nil
        pendingModeRequestID = nil
        presentedAuthModeRequest = nil
    }

    private func performModeSwitch(
        to newMode: AuthenticationMode,
        requestID: UUID
    ) {
        isSwitching = true
        let fingerprints = keyManagement.keys.map(\.fingerprint)
        let hasBackup = hasBackup

        Task {
            do {
                try await authModeSwitchAction(newMode, fingerprints, hasBackup)
                appConfiguration.authMode = newMode
            } catch {
                switchError = error.localizedDescription
                showSwitchError = true
            }

            if pendingModeRequestID == requestID {
                pendingMode = nil
                pendingModeRequestID = nil
                presentedAuthModeRequest = nil
            }
            isSwitching = false
        }
    }
}
