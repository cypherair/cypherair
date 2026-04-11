import SwiftUI

/// Settings screen with auth mode, grace period, and other preferences.
struct SettingsView: View {
    struct Configuration {
        var onAuthModeConfirmationRequested: (@MainActor (AuthModeChangeConfirmationRequest) -> Void)?
        var isOnboardingEntryEnabled = true
        var isGuidedTutorialEntryEnabled = true
        var isThemePickerEnabled = true
        var isAppIconEntryEnabled = true
        var navigationEducationFooter: String?
        var appearanceEducationFooter: String?

        static let `default` = Configuration()
    }

    @Environment(AppConfiguration.self) private var config
    @Environment(AuthenticationManager.self) private var authManager
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.iosPresentationController) private var iosPresentationController
    @Environment(\.macPresentationController) private var macPresentationController

    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        SettingsScreenHostView(
            config: config,
            authManager: authManager,
            keyManagement: keyManagement,
            iosPresentationController: iosPresentationController,
            macPresentationController: macPresentationController,
            configuration: configuration
        )
    }
}

private struct SettingsScreenHostView: View {
    @State private var model: SettingsScreenModel

    init(
        config: AppConfiguration,
        authManager: AuthenticationManager,
        keyManagement: KeyManagementService,
        iosPresentationController: IOSPresentationController?,
        macPresentationController: MacPresentationController?,
        configuration: SettingsView.Configuration
    ) {
        _model = State(
            initialValue: SettingsScreenModel(
                config: config,
                authManager: authManager,
                keyManagement: keyManagement,
                iosPresentationController: iosPresentationController,
                macPresentationController: macPresentationController,
                configuration: configuration
            )
        )
    }

    var body: some View {
        @Bindable var model = model
        @Bindable var appConfiguration = model.appConfiguration

        Form {
            Section {
                Picker(
                    String(localized: "settings.authMode", defaultValue: "Authentication Mode"),
                    selection: Binding(
                        get: { appConfiguration.authMode },
                        set: { newMode in
                            guard newMode != appConfiguration.authMode else { return }
                            model.handleAuthModeSelection(newMode)
                        }
                    )
                ) {
                    Text(String(localized: "settings.authMode.standard", defaultValue: "Standard"))
                        .tag(AuthenticationMode.standard)
                    Text(String(localized: "settings.authMode.high", defaultValue: "High Security"))
                        .tag(AuthenticationMode.highSecurity)
                }
                .accessibilityIdentifier("settings.authMode")
                .tutorialAnchor(.settingsAuthModePicker)
                .disabled(model.isSwitching)

                Picker(
                    String(localized: "settings.gracePeriod", defaultValue: "Re-authentication"),
                    selection: $appConfiguration.gracePeriod
                ) {
                    ForEach(AppConfiguration.gracePeriodOptions, id: \.value) { option in
                        Text(option.label).tag(option.value)
                    }
                }
            } header: {
                Text(String(localized: "settings.security", defaultValue: "Security"))
            }

            Section {
                Toggle(
                    String(localized: "settings.encryptToSelf", defaultValue: "Encrypt to Self"),
                    isOn: $appConfiguration.encryptToSelf
                )
                Toggle(
                    String(localized: "settings.clipboardNotice", defaultValue: "Clipboard Safety Notice"),
                    isOn: $appConfiguration.clipboardNotice
                )
            } header: {
                Text(String(localized: "settings.encryption", defaultValue: "Encryption"))
            }

            Section {
                NavigationLink(value: AppRoute.themePicker) {
                    Label(
                        String(localized: "settings.theme", defaultValue: "Color Theme"),
                        systemImage: "paintpalette"
                    )
                }
                .accessibilityIdentifier("settings.theme")
                .disabled(!model.configuration.isThemePickerEnabled)

                #if canImport(UIKit)
                NavigationLink(value: AppRoute.appIcon) {
                    Label(
                        String(localized: "settings.appIcon", defaultValue: "App Icon"),
                        systemImage: "app"
                    )
                }
                .disabled(!model.configuration.isAppIconEntryEnabled)
                #endif
            } header: {
                Text(String(localized: "settings.appearance", defaultValue: "Appearance"))
            } footer: {
                if let appearanceEducationFooter = model.configuration.appearanceEducationFooter {
                    Text(appearanceEducationFooter)
                }
            }

            Section {
                NavigationLink(value: AppRoute.selfTest) {
                    Label(
                        String(localized: "settings.selfTest", defaultValue: "Self-Test"),
                        systemImage: "checkmark.circle"
                    )
                }
                .accessibilityIdentifier("settings.selfTest")

                Button {
                    model.presentOnboarding()
                } label: {
                    settingsActionRow(
                        String(localized: "settings.viewOnboarding", defaultValue: "View Onboarding"),
                        systemImage: "book"
                    )
                }
                .accessibilityIdentifier("settings.onboarding")
                .buttonStyle(.plain)
                .disabled(!model.configuration.isOnboardingEntryEnabled)

                Button {
                    model.presentTutorial()
                } label: {
                    settingsActionRow(
                        model.guidedTutorialEntryTitle,
                        systemImage: "testtube.2"
                    )
                }
                .accessibilityIdentifier("settings.tutorial")
                .buttonStyle(.plain)
                .disabled(!model.configuration.isGuidedTutorialEntryEnabled)

                NavigationLink(value: AppRoute.license) {
                    Label(
                        String(localized: "settings.license", defaultValue: "Licenses"),
                        systemImage: "doc.text"
                    )
                }
                .accessibilityIdentifier("settings.license")

                NavigationLink(value: AppRoute.about) {
                    Label(
                        String(localized: "settings.about", defaultValue: "About"),
                        systemImage: "info.circle"
                    )
                }
                .accessibilityIdentifier("settings.about")
            } footer: {
                if let navigationEducationFooter = model.configuration.navigationEducationFooter {
                    Text(navigationEducationFooter)
                }
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .accessibilityIdentifier("settings.root")
        .screenReady("settings.ready")
        .navigationTitle(String(localized: "settings.title", defaultValue: "Settings"))
        .confirmationDialog(
            model.localModeTitle,
            isPresented: Binding(
                get: { model.presentedAuthModeRequest != nil && !model.usesLocalModeSheet },
                set: { if !$0 { model.dismissLocalModeRequest() } }
            ),
            titleVisibility: .visible
        ) {
            if let request = model.presentedAuthModeRequest {
                Button(String(localized: "settings.mode.confirm", defaultValue: "Switch Mode"), role: .destructive) {
                    request.onConfirm()
                }
                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {
                    request.onCancel()
                }
            }
        } message: {
            Text(model.localModeMessage)
        }
        .sheet(isPresented: Binding(
            get: { model.presentedAuthModeRequest != nil && model.usesLocalModeSheet },
            set: { if !$0 { model.dismissLocalModeRequest() } }
        )) {
            if let request = model.presentedAuthModeRequest {
                NavigationStack {
                    SettingsAuthModeConfirmationSheetView(request: request)
                }
                #if os(macOS)
                .frame(minWidth: 500, idealWidth: 540, minHeight: 360, idealHeight: 420)
                #endif
                #if canImport(UIKit)
                .presentationDetents([.medium, .large])
                #endif
            }
        }
        .alert(
            String(localized: "settings.mode.error.title", defaultValue: "Mode Switch Failed"),
            isPresented: Binding(
                get: { model.showSwitchError },
                set: { if !$0 { model.dismissSwitchError() } }
            )
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                model.dismissSwitchError()
            }
        } message: {
            if let switchError = model.switchError {
                Text(switchError)
            }
        }
        #if !os(iOS)
        .sheet(isPresented: $model.showOnboarding) {
            OnboardingView(presentationContext: .inApp)
        }
        .sheet(isPresented: $model.showTutorialOnboarding) {
            TutorialView(presentationContext: .inApp)
        }
        #endif
    }

    private func settingsActionRow(
        _ title: String,
        systemImage: String
    ) -> some View {
        HStack {
            Label(title, systemImage: systemImage)
            Spacer()
            Image(systemName: "chevron.right")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.tertiary)
        }
        .contentShape(Rectangle())
    }
}

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
        AppRouteHost(
            resolver: .production,
            path: $path
        ) {
            SettingsView()
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
                    openWindow(id: macMainWindowID)
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
}
#endif
