import Foundation
import LocalAuthentication
import SwiftUI

@MainActor
@Observable
final class SettingsScreenModel {
    typealias AuthModeSwitchAction = @MainActor (AuthenticationMode, [String], Bool) async throws -> Void
    typealias AppAccessPolicySwitchAction = @MainActor (AppSessionAuthenticationPolicy) async throws -> Void

    let configuration: SettingsView.Configuration
    let appConfiguration: AppConfiguration
    let protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator
    let protectedSettingsHost: ProtectedSettingsHost?

    private let authManager: AuthenticationManager
    private let keyManagement: KeyManagementService
    private let iosPresentationController: IOSPresentationController?
    private let macPresentationController: MacPresentationController?
    private let authModeSwitchAction: AuthModeSwitchAction
    private let appAccessPolicySwitchAction: AppAccessPolicySwitchAction
    private let localDataResetService: LocalDataResetService?
    private let localDataResetRestartCoordinator: LocalDataResetRestartCoordinator?

    var pendingMode: AuthenticationMode?
    private var pendingModeRequestID: UUID?
    var presentedAuthModeRequest: AuthModeChangeConfirmationRequest?
    var isSwitching = false
    var isSwitchingAppAccessPolicy = false
    var switchError: String?
    var showSwitchError = false
    var showOnboarding = false
    var showTutorialOnboarding = false
    var showProtectedSettingsResetConfirmation = false
    var showLocalDataResetWarning = false
    var showLocalDataResetPhraseSheet = false
    var showLocalDataResetResultAlert = false
    var localDataResetConfirmationPhrase = ""
    var isResettingLocalData = false
    private var localDataResetSucceeded = false
    private var localDataResetErrorMessage: String?

    init(
        config: AppConfiguration,
        protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator,
        authManager: AuthenticationManager,
        keyManagement: KeyManagementService,
        iosPresentationController: IOSPresentationController?,
        macPresentationController: MacPresentationController?,
        configuration: SettingsView.Configuration,
        localDataResetService: LocalDataResetService? = nil,
        localDataResetRestartCoordinator: LocalDataResetRestartCoordinator? = nil,
        authModeSwitchAction: AuthModeSwitchAction? = nil,
        appAccessPolicySwitchAction: AppAccessPolicySwitchAction? = nil
    ) {
        self.configuration = configuration
        self.appConfiguration = config
        self.protectedOrdinarySettings = protectedOrdinarySettings
        self.protectedSettingsHost = configuration.protectedSettingsHost
        self.authManager = authManager
        self.keyManagement = keyManagement
        self.iosPresentationController = iosPresentationController
        self.macPresentationController = macPresentationController
        self.localDataResetService = localDataResetService
        self.localDataResetRestartCoordinator = localDataResetRestartCoordinator
        self.authModeSwitchAction = authModeSwitchAction ?? { newMode, fingerprints, hasBackup in
            try await authManager.switchMode(
                to: newMode,
                fingerprints: fingerprints,
                hasBackup: hasBackup,
                authenticator: authManager
            )
        }
        self.appAccessPolicySwitchAction = appAccessPolicySwitchAction ?? { newPolicy in
            guard authManager.canEvaluate(appSessionPolicy: newPolicy) else {
                throw AuthenticationError.appAccessBiometricsUnavailable
            }
        }
    }

    var guidedTutorialEntryTitle: String {
        switch protectedOrdinarySettings.guidedTutorialCompletionState ?? .neverCompleted {
        case .neverCompleted:
            String(localized: "guidedTutorial.settings.entry", defaultValue: "Guided Tutorial")
        case .completedCurrentVersion:
            String(localized: "guidedTutorial.replay", defaultValue: "Replay Guided Tutorial")
        case .completedPreviousVersion:
            String(localized: "guidedTutorial.updated.entry", defaultValue: "Updated Guided Tutorial Available")
        }
    }

    var isProtectedOrdinarySettingsEditable: Bool {
        protectedOrdinarySettings.isLoaded
    }

    var gracePeriodSelection: Int {
        protectedOrdinarySettings.snapshot?.gracePeriod ?? AuthPreferences.defaultGracePeriod
    }

    var encryptToSelfSelection: Bool {
        protectedOrdinarySettings.snapshot?.encryptToSelf ?? true
    }

    func setGracePeriod(_ gracePeriod: Int) {
        protectedOrdinarySettings.setGracePeriod(gracePeriod)
    }

    func setEncryptToSelf(_ encryptToSelf: Bool) {
        protectedOrdinarySettings.setEncryptToSelf(encryptToSelf)
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

    var shouldShowLocalDataResetSection: Bool {
        switch configuration.localDataResetAvailability {
        case .enabled:
            localDataResetService != nil
        case .disabled:
            true
        }
    }

    var isLocalDataResetControlEnabled: Bool {
        isLocalDataResetAvailable && localDataResetService != nil && !isResettingLocalData
    }

    var localDataResetFooter: String {
        switch configuration.localDataResetAvailability {
        case .enabled:
            String(
                localized: "settings.resetAll.footer",
                defaultValue: "Use this only when you want this device to behave like a fresh CypherAir install."
            )
        case .disabled(let footer):
            footer
        }
    }

    var canConfirmLocalDataReset: Bool {
        localDataResetConfirmationPhrase == "RESET"
    }

    var localDataResetAlertTitle: String {
        if localDataResetSucceeded {
            return String(localized: "settings.resetAll.success.title", defaultValue: "Reset Complete")
        }
        return String(localized: "settings.resetAll.error.title", defaultValue: "Reset Failed")
    }

    var localDataResetAlertMessage: String {
        if localDataResetSucceeded {
            return String(
                localized: "settings.resetAll.success.message",
                defaultValue: "CypherAir local data was reset. Restart the app to complete the fresh-start state."
            )
        }
        return localDataResetErrorMessage ?? String(
            localized: "settings.resetAll.error.message",
            defaultValue: "CypherAir could not reset all local data."
        )
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
        guard let currentMode = appConfiguration.authModeIfUnlocked else {
            switchError = PrivateKeyControlError.locked.localizedDescription
            showSwitchError = true
            return
        }
        guard newMode != currentMode else {
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

    func handleAppAccessPolicySelection(_ newPolicy: AppSessionAuthenticationPolicy) {
        guard newPolicy != appConfiguration.appSessionAuthenticationPolicy else {
            return
        }

        isSwitchingAppAccessPolicy = true
        Task {
            do {
                try await appAccessPolicySwitchAction(newPolicy)
                appConfiguration.appSessionAuthenticationPolicy = newPolicy
            } catch {
                switchError = error.localizedDescription
                showSwitchError = true
            }
            isSwitchingAppAccessPolicy = false
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

    func requestProtectedSettingsRetry() {
        Task {
            await protectedSettingsHost?.retryPendingRecovery()
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

    func requestLocalDataReset() {
        guard isLocalDataResetControlEnabled else { return }
        showLocalDataResetWarning = true
    }

    func dismissLocalDataResetWarning() {
        showLocalDataResetWarning = false
    }

    func continueLocalDataReset() {
        guard isLocalDataResetControlEnabled else { return }
        showLocalDataResetWarning = false
        localDataResetConfirmationPhrase = ""
        showLocalDataResetPhraseSheet = true
    }

    func dismissLocalDataResetPhraseSheet() {
        guard !isResettingLocalData else { return }
        showLocalDataResetPhraseSheet = false
        localDataResetConfirmationPhrase = ""
    }

    func confirmLocalDataReset() {
        guard isLocalDataResetControlEnabled,
              canConfirmLocalDataReset,
              let localDataResetService else { return }
        showLocalDataResetPhraseSheet = false
        isResettingLocalData = true
        localDataResetSucceeded = false
        localDataResetErrorMessage = nil

        Task {
            do {
                var resetAuthenticationContext: LAContext?
                defer {
                    resetAuthenticationContext?.invalidate()
                }
                if authManager.canEvaluate(appSessionPolicy: appConfiguration.appSessionAuthenticationPolicy) {
                    let result = try await authManager.evaluateAppSession(
                        policy: appConfiguration.appSessionAuthenticationPolicy,
                        reason: String(
                            localized: "settings.resetAll.authReason",
                            defaultValue: "Authenticate to reset all CypherAir data on this device."
                        ),
                        source: "localDataReset"
                    )
                    guard result.isAuthenticated else {
                        throw AuthenticationError.failed
                    }
                    resetAuthenticationContext = result.context
                }

                let summary = try await localDataResetService.resetAllLocalData(
                    authenticationContext: resetAuthenticationContext
                )
                localDataResetSucceeded = true
                localDataResetRestartCoordinator?.markRestartRequired(summary: summary)
            } catch {
                localDataResetErrorMessage = error.localizedDescription
            }

            isResettingLocalData = false
            showLocalDataResetResultAlert = localDataResetErrorMessage != nil
                || localDataResetRestartCoordinator == nil
            localDataResetConfirmationPhrase = ""
        }
    }

    func dismissLocalDataResetResultAlert() {
        showLocalDataResetResultAlert = false
        localDataResetErrorMessage = nil
        localDataResetSucceeded = false
    }

    func openProtectedSettingsInMainWindow() {
        protectedSettingsHost?.openMainWindow()
    }

    private var hasBackup: Bool {
        keyManagement.keys.contains(where: \.isBackedUp)
    }

    private var isLocalDataResetAvailable: Bool {
        switch configuration.localDataResetAvailability {
        case .enabled:
            true
        case .disabled:
            false
        }
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
                appConfiguration.privateKeyControlState = .unlocked(newMode)
            } catch {
                if let currentMode = authManager.currentMode {
                    appConfiguration.privateKeyControlState = .unlocked(currentMode)
                } else {
                    appConfiguration.privateKeyControlState = .recoveryNeeded
                }
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

private struct AppAccessPolicySwitchActionKey: EnvironmentKey {
    static let defaultValue: SettingsScreenModel.AppAccessPolicySwitchAction? = nil
}

extension EnvironmentValues {
    var appAccessPolicySwitchAction: SettingsScreenModel.AppAccessPolicySwitchAction? {
        get { self[AppAccessPolicySwitchActionKey.self] }
        set { self[AppAccessPolicySwitchActionKey.self] = newValue }
    }
}
