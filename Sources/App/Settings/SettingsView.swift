import SwiftUI

/// Settings screen with auth mode, grace period, and other preferences.
struct SettingsView: View {
    struct Configuration {
        enum ProtectedSettingsHostMode {
            case mainWindowLive
            case tutorialSandbox
        }

        enum LocalDataResetAvailability {
            case enabled
            case disabled(footer: String)
        }

        var onAuthModeConfirmationRequested: (@MainActor (AuthModeChangeConfirmationRequest) -> Void)?
        var isOnboardingEntryEnabled = true
        var isGuidedTutorialEntryEnabled = true
        var isAppIconEntryEnabled = true
        var navigationEducationFooter: String?
        var appearanceEducationFooter: String?
        var localDataResetAvailability: LocalDataResetAvailability = .enabled
        var protectedSettingsHostMode: ProtectedSettingsHostMode = .mainWindowLive
        var protectedSettingsHost: ProtectedSettingsHost?

        static let `default` = Configuration()
    }

    @Environment(AppConfiguration.self) private var config
    @Environment(ProtectedOrdinarySettingsCoordinator.self) private var protectedOrdinarySettings
    @Environment(AuthenticationManager.self) private var authManager
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(ContentClearSignal.self) private var contentClear
    @Environment(\.iosPresentationController) private var iosPresentationController
    @Environment(\.macPresentationController) private var macPresentationController
    @Environment(\.realWorkspace) private var realWorkspace

    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        SettingsScreenHostView(
            config: config,
            protectedOrdinarySettings: protectedOrdinarySettings,
            authManager: authManager,
            keyManagement: keyManagement,
            contentClear: contentClear,
            iosPresentationController: iosPresentationController,
            macPresentationController: macPresentationController,
            appAccessPolicySwitchAction: realWorkspace?.appAccessPolicySwitchAction,
            localDataResetService: realWorkspace?.localDataResetService,
            localDataResetRestartCoordinator: realWorkspace?.localDataResetRestartCoordinator,
            configuration: configuration
        )
    }
}
