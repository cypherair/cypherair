import SwiftUI

struct MainWindowSettingsRootView: View {
    @Environment(\.realWorkspace) private var realWorkspace
    @Environment(ContentClearSignal.self) private var contentClear

    var body: some View {
        var configuration = SettingsView.Configuration.default
        configuration.protectedSettingsHostMode = .mainWindowLive
        configuration.protectedSettingsHost = realWorkspace?.protectedSettingsHost
        return SettingsView(configuration: configuration)
            .onChange(of: contentClear.generation) { _, generation in
                Task {
                    await realWorkspace?.protectedSettingsHost.invalidateForContentClearGeneration(generation)
                }
            }
            .onChange(of: realWorkspace?.sessionOrchestrator.postAuthenticationGeneration) { _, generation in
                guard let generation else { return }
                Task {
                    await realWorkspace?.protectedSettingsHost.refreshAfterAppAuthenticationGeneration(generation)
                }
            }
    }
}
