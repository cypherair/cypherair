import SwiftUI

struct SettingsView: View {
    struct Configuration {
        enum LocalDataResetAvailability {
            case enabled
            case disabled(footer: String)
        }

        /// The tutorial sandbox: no passphrase to change, no real clipboard
        /// notice to edit.
        var isSandbox = false
        var isOnboardingEntryEnabled = true
        var isGuidedTutorialEntryEnabled = true
        var isAppIconEntryEnabled = true
        var navigationEducationFooter: String?
        var appearanceEducationFooter: String?
        var localDataResetAvailability: LocalDataResetAvailability = .enabled

        static let `default` = Configuration()
    }

    @Environment(AppSettingsCoordinator.self) private var appSettings
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
    @Environment(\.iosPresentationController) private var iosPresentationController
    @Environment(\.macPresentationController) private var macPresentationController
    @Environment(\.localDataResetService) private var localDataResetService
    @Environment(\.localDataResetRestartCoordinator) private var localDataResetRestartCoordinator

    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        SettingsScreenHostView(
            appSettings: appSettings,
            appSessionOrchestrator: appSessionOrchestrator,
            iosPresentationController: iosPresentationController,
            macPresentationController: macPresentationController,
            localDataResetService: localDataResetService,
            localDataResetRestartCoordinator: localDataResetRestartCoordinator,
            configuration: configuration
        )
    }
}
