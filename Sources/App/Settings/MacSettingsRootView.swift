import SwiftUI

#if os(macOS)
@MainActor
private struct TutorialLaunchBlockedNotice: Identifiable {
    let id = UUID()
    let reason: MacTutorialHostBlocker
}

struct MacSettingsRootView: View {
    let launchConfiguration: AppLaunchConfiguration?
    let tutorialLaunchRelay: MacTutorialLaunchRelay
    let tutorialHostAvailability: MacTutorialHostAvailability
    let presentationHostMode: MacPresentationHostMode

    @Environment(\.openWindow) private var openWindow
    @Environment(\.protectedSettingsHost) private var protectedSettingsHost

    @State private var path: [AppRoute] = []
    @State private var activePresentation: MacPresentation?
    @State private var tutorialLaunchBlockedNotice: TutorialLaunchBlockedNotice?

    init(
        launchConfiguration: AppLaunchConfiguration? = nil,
        tutorialLaunchRelay: MacTutorialLaunchRelay,
        tutorialHostAvailability: MacTutorialHostAvailability,
        presentationHostMode: MacPresentationHostMode = .settingsScene
    ) {
        self.launchConfiguration = launchConfiguration
        self.tutorialLaunchRelay = tutorialLaunchRelay
        self.tutorialHostAvailability = tutorialHostAvailability
        self.presentationHostMode = presentationHostMode
    }

    var body: some View {
        let configuration = settingsViewConfiguration

        AppRouteHost(
            resolver: .production,
            path: $path
        ) {
            SettingsView(configuration: configuration)
        }
        .environment(\.macPresentationController, macPresentationController)
        .task {
            if launchConfiguration?.opensAuthModeConfirmation == true,
               activePresentation == nil {
                activePresentation = .authModeConfirmation(
                    SettingsAuthModeRequestBuilder.makeLaunchPreviewRequest()
                )
            }
        }
        .macPresentationHost(
            $activePresentation,
            hostMode: presentationHostMode,
            tutorialLaunchRelay: tutorialLaunchRelay,
            tutorialHostAvailability: tutorialHostAvailability,
            onTutorialLaunchBlocked: { reason in
                tutorialLaunchBlockedNotice = TutorialLaunchBlockedNotice(reason: reason)
            }
        )
        .alert(
            tutorialLaunchBlockedTitle,
            isPresented: Binding(
                get: { tutorialLaunchBlockedNotice != nil },
                set: { if !$0 { tutorialLaunchBlockedNotice = nil } }
            )
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                tutorialLaunchBlockedNotice = nil
            }
        } message: {
            Text(
                tutorialLaunchBlockedMessage
            )
        }
    }

    private var macPresentationController: MacPresentationController {
        switch presentationHostMode {
        case .mainWindow:
            MacPresentationController.mainWindow(activePresentation: $activePresentation)
        case .settingsScene:
            MacPresentationController.settingsScene(
                activePresentation: $activePresentation,
                tutorialLaunchRelay: tutorialLaunchRelay,
                tutorialHostAvailability: tutorialHostAvailability,
                onTutorialLaunchBlocked: { reason in
                    tutorialLaunchBlockedNotice = TutorialLaunchBlockedNotice(reason: reason)
                },
                openMainWindow: {
                    openWindow(id: mainWindowID)
                }
            )
        }
    }

    private var tutorialLaunchBlockedTitle: String {
        switch tutorialLaunchBlockedNotice?.reason {
        case .tutorialAlreadyOpen:
            String(
                localized: "guidedTutorial.alreadyOpen.title",
                defaultValue: "Tutorial Already Open"
            )
        case .none,
             .some:
            String(
                localized: "guidedTutorial.launchBlocked.title",
                defaultValue: "Finish Current Dialog First"
            )
        }
    }

    private var tutorialLaunchBlockedMessage: String {
        switch tutorialLaunchBlockedNotice?.reason {
        case .tutorialAlreadyOpen:
            String(
                localized: "guidedTutorial.alreadyOpen.message",
                defaultValue: "The Guided Tutorial is already open in the main window. Return to that window to continue."
            )
        case .none,
             .some:
            String(
                localized: "guidedTutorial.launchBlocked.message",
                defaultValue: "The main window is busy with another dialog. Finish or dismiss it, then start the Guided Tutorial again."
            )
        }
    }

    private var settingsViewConfiguration: SettingsView.Configuration {
        var configuration = SettingsView.Configuration.default
        switch presentationHostMode {
        case .mainWindow:
            configuration.protectedSettingsHostMode = .mainWindowLive
            configuration.protectedSettingsHost = protectedSettingsHost
        case .settingsScene:
            configuration.protectedSettingsHostMode = .settingsSceneProxy
            configuration.protectedSettingsHost = ProtectedSettingsHost(
                mode: .settingsSceneProxy,
                openMainWindowAction: {
                    openWindow(id: mainWindowID)
                }
            )
        }
        return configuration
    }
}
#endif
