import SwiftUI

struct MainWindowSettingsRootView: View {
    @Environment(\.protectedSettingsHost) private var protectedSettingsHost
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator

    var body: some View {
        var configuration = SettingsView.Configuration.default
        configuration.protectedSettingsHostMode = .mainWindowLive
        configuration.protectedSettingsHost = protectedSettingsHost
        return SettingsView(configuration: configuration)
            .onChange(of: appSessionOrchestrator.contentClearGeneration) { _, generation in
                Task {
                    await protectedSettingsHost?.invalidateForContentClearGeneration(generation)
                }
            }
            .onChange(of: appSessionOrchestrator.postAuthenticationGeneration) { _, generation in
                Task {
                    await protectedSettingsHost?.refreshAfterAppAuthenticationGeneration(generation)
                }
            }
    }
}
