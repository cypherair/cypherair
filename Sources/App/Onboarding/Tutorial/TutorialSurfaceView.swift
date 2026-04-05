import SwiftUI

@MainActor
struct TutorialSurfaceView<Content: View>: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    let tab: AppShellTab
    let route: AppRoute?
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .onAppear {
                tutorialStore.noteVisibleSurface(tab: tab, route: route)
            }
    }
}

@MainActor
struct TutorialSettingsTaskView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(AppConfiguration.self) private var config

    var body: some View {
        TutorialTaskHostView(task: .enableHighSecurity) {
            SettingsView(configuration: tutorialStore.configurationFactory.settingsConfiguration())
                .onChange(of: config.authMode) { _, newMode in
                    if newMode == .highSecurity {
                        tutorialStore.noteHighSecurityEnabled(newMode)
                    }
                }
        }
    }
}
