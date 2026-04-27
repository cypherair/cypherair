import SwiftUI

/// Settings screen with auth mode, grace period, and other preferences.
struct SettingsView: View {
    struct Configuration {
        enum ProtectedSettingsHostMode {
            case mainWindowLive
            case settingsSceneProxy
            case tutorialSandbox
        }

        enum LocalDataResetAvailability {
            case enabled
            case disabled(footer: String)
        }

        var onAuthModeConfirmationRequested: (@MainActor (AuthModeChangeConfirmationRequest) -> Void)?
        var isOnboardingEntryEnabled = true
        var isGuidedTutorialEntryEnabled = true
        var isThemePickerEnabled = true
        var isAppIconEntryEnabled = true
        var navigationEducationFooter: String?
        var appearanceEducationFooter: String?
        var localDataResetAvailability: LocalDataResetAvailability = .enabled
        var protectedSettingsHostMode: ProtectedSettingsHostMode = .mainWindowLive
        var protectedSettingsHost: ProtectedSettingsHost?

        static let `default` = Configuration()
    }

    @Environment(AppConfiguration.self) private var config
    @Environment(AuthenticationManager.self) private var authManager
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.iosPresentationController) private var iosPresentationController
    @Environment(\.macPresentationController) private var macPresentationController
    @Environment(\.appAccessPolicySwitchAction) private var appAccessPolicySwitchAction
    @Environment(\.localDataResetService) private var localDataResetService

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
            appAccessPolicySwitchAction: appAccessPolicySwitchAction,
            localDataResetService: localDataResetService,
            configuration: configuration
        )
    }
}

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
        appAccessPolicySwitchAction: SettingsScreenModel.AppAccessPolicySwitchAction?,
        localDataResetService: LocalDataResetService?,
        configuration: SettingsView.Configuration
    ) {
        _model = State(
            initialValue: SettingsScreenModel(
                config: config,
                authManager: authManager,
                keyManagement: keyManagement,
                iosPresentationController: iosPresentationController,
                macPresentationController: macPresentationController,
                configuration: configuration,
                localDataResetService: localDataResetService,
                appAccessPolicySwitchAction: appAccessPolicySwitchAction
            )
        )
    }

    var body: some View {
        @Bindable var model = model
        @Bindable var appConfiguration = model.appConfiguration

        Form {
            Section {
                Picker(
                    String(localized: "settings.appAccessPolicy", defaultValue: "App Access Protection"),
                    selection: Binding(
                        get: { appConfiguration.appSessionAuthenticationPolicy },
                        set: { newPolicy in
                            guard newPolicy != appConfiguration.appSessionAuthenticationPolicy else { return }
                            model.handleAppAccessPolicySelection(newPolicy)
                        }
                    )
                ) {
                    Text(String(localized: "settings.appAccessPolicy.userPresence", defaultValue: "User Presence"))
                        .tag(AppSessionAuthenticationPolicy.userPresence)
                    Text(String(localized: "settings.appAccessPolicy.biometricsOnly", defaultValue: "Biometrics Only"))
                        .tag(AppSessionAuthenticationPolicy.biometricsOnly)
                }
                .accessibilityIdentifier("settings.appAccessPolicy")
                .disabled(model.isSwitchingAppAccessPolicy)

                Picker(
                    String(localized: "settings.authMode", defaultValue: "Private Key Protection"),
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
            } header: {
                Text(String(localized: "settings.encryption", defaultValue: "Encryption"))
            }

            if model.shouldShowProtectedSettingsSection {
                protectedSettingsSection(model: model)
            }

            if model.shouldShowLocalDataResetSection {
                localDataResetSection(model: model)
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

                #if os(iOS)
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
            String(localized: "settings.mode.error.title", defaultValue: "Protection Change Failed"),
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
        .confirmationDialog(
            String(
                localized: "protectedSettings.reset.title",
                defaultValue: "Reset Protected Preferences?"
            ),
            isPresented: Binding(
                get: { model.showProtectedSettingsResetConfirmation },
                set: { if !$0 { model.dismissProtectedSettingsResetConfirmation() } }
            ),
            titleVisibility: .visible
        ) {
            Button(
                String(
                    localized: "protectedSettings.reset.confirm",
                    defaultValue: "Reset Preferences"
                ),
                role: .destructive
            ) {
                model.confirmProtectedSettingsReset()
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) { }
        } message: {
            Text(
                String(
                    localized: "protectedSettings.reset.message",
                    defaultValue: "This will delete and rebuild the protected preferences domain. Only protected preferences will be reset."
                )
            )
        }
        .confirmationDialog(
            String(localized: "settings.resetAll.title", defaultValue: "Reset All Local Data?"),
            isPresented: Binding(
                get: { model.showLocalDataResetWarning },
                set: { if !$0 { model.dismissLocalDataResetWarning() } }
            ),
            titleVisibility: .visible
        ) {
            Button(
                String(localized: "settings.resetAll.continue", defaultValue: "Continue"),
                role: .destructive
            ) {
                model.continueLocalDataReset()
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) { }
        } message: {
            Text(
                String(
                    localized: "settings.resetAll.warning",
                    defaultValue: "This permanently deletes CypherAir keys, contacts, protected preferences, app settings, and temporary files on this device."
                )
            )
        }
        .sheet(isPresented: Binding(
            get: { model.showLocalDataResetPhraseSheet },
            set: { if !$0 { model.dismissLocalDataResetPhraseSheet() } }
        )) {
            NavigationStack {
                localDataResetPhraseView(model: model)
            }
            #if os(macOS)
            .frame(minWidth: 500, idealWidth: 540, minHeight: 320, idealHeight: 360)
            #endif
        }
        .alert(
            model.localDataResetAlertTitle,
            isPresented: Binding(
                get: { model.showLocalDataResetResultAlert },
                set: { if !$0 { model.dismissLocalDataResetResultAlert() } }
            )
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                model.dismissLocalDataResetResultAlert()
            }
        } message: {
            Text(model.localDataResetAlertMessage)
        }
        #if !os(iOS)
        .sheet(isPresented: $model.showOnboarding) {
            OnboardingView(presentationContext: .inApp)
        }
        .sheet(isPresented: $model.showTutorialOnboarding) {
            TutorialView(presentationContext: .inApp)
        }
        #endif
        .task {
            await model.prepareProtectedSettingsSection()
        }
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

    @ViewBuilder
    private func localDataResetSection(model: SettingsScreenModel) -> some View {
        Section {
            Button(role: .destructive) {
                model.requestLocalDataReset()
            } label: {
                Label(
                    String(localized: "settings.resetAll.action", defaultValue: "Reset All Local Data"),
                    systemImage: "trash"
                )
            }
            .disabled(!model.isLocalDataResetControlEnabled)
            .accessibilityIdentifier("settings.resetAll")
        } header: {
            Text(String(localized: "settings.dangerZone", defaultValue: "Danger Zone"))
        } footer: {
            Text(model.localDataResetFooter)
        }
    }

    private func localDataResetPhraseView(model: SettingsScreenModel) -> some View {
        @Bindable var model = model

        return Form {
            Section {
                Text(
                    String(
                        localized: "settings.resetAll.phraseInstructions",
                        defaultValue: "Type RESET to permanently delete all CypherAir data on this device."
                    )
                )
                TextField(
                    String(localized: "settings.resetAll.phrasePlaceholder", defaultValue: "Confirmation phrase"),
                    text: $model.localDataResetConfirmationPhrase
                )
                .accessibilityIdentifier("settings.resetAll.phrase")
            }
        }
        .navigationTitle(String(localized: "settings.resetAll.title", defaultValue: "Reset All Local Data?"))
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    model.dismissLocalDataResetPhraseSheet()
                }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(
                    String(localized: "settings.resetAll.confirm", defaultValue: "Reset"),
                    role: .destructive
                ) {
                    model.confirmLocalDataReset()
                }
                .disabled(!model.canConfirmLocalDataReset || model.isResettingLocalData)
            }
        }
    }

    @ViewBuilder
    private func protectedSettingsSection(model: SettingsScreenModel) -> some View {
        Section {
            switch model.protectedSettingsSectionState {
            case .loading:
                HStack {
                    ProgressView()
                    Text(
                        String(
                            localized: "protectedSettings.loading",
                            defaultValue: "Loading protected preferences..."
                        )
                    )
                    .foregroundStyle(.secondary)
                }
            case .locked:
                LabeledContent {
                    Button(
                        String(
                            localized: "protectedSettings.unlock",
                            defaultValue: "Unlock"
                        )
                    ) {
                        model.requestProtectedSettingsUnlock()
                    }
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(
                            String(
                                localized: "settings.clipboardNotice",
                                defaultValue: "Clipboard Safety Notice"
                            )
                        )
                        Text(
                            String(
                                localized: "protectedSettings.locked.message",
                                defaultValue: "Authenticate to view and change this protected preference."
                            )
                        )
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    }
                }
            case .available:
                Toggle(
                    String(
                        localized: "settings.clipboardNotice",
                        defaultValue: "Clipboard Safety Notice"
                    ),
                    isOn: Binding(
                        get: { model.isProtectedClipboardNoticeEnabled },
                        set: { model.setProtectedClipboardNoticeEnabled($0) }
                    )
                )
            case .recoveryNeeded:
                VStack(alignment: .leading, spacing: 10) {
                    Text(
                        String(
                            localized: "protectedSettings.recovery.message",
                            defaultValue: "Protected preferences could not be opened safely and may need recovery."
                        )
                    )
                    .foregroundStyle(.secondary)

                    Button(
                        String(
                            localized: "protectedSettings.reset.action",
                            defaultValue: "Reset Protected Preferences"
                        ),
                        role: .destructive
                    ) {
                        model.requestProtectedSettingsReset()
                    }
                }
            case .pendingRetryRequired:
                Text(
                    String(
                        localized: "protectedSettings.pending.message",
                        defaultValue: "Protected preferences have pending recovery work and are temporarily unavailable."
                    )
                )
                .foregroundStyle(.secondary)
                Button(
                    String(
                        localized: "protectedSettings.retry.action",
                        defaultValue: "Retry Recovery"
                    )
                ) {
                    model.requestProtectedSettingsRetry()
                }
            case .pendingResetRequired:
                VStack(alignment: .leading, spacing: 10) {
                    Text(
                        String(
                            localized: "protectedSettings.pendingReset.message",
                            defaultValue: "Protected preferences have unfinished setup work that cannot continue automatically."
                        )
                    )
                    .foregroundStyle(.secondary)

                    Button(
                        String(
                            localized: "protectedSettings.reset.action",
                            defaultValue: "Reset Protected Preferences"
                        ),
                        role: .destructive
                    ) {
                        model.requestProtectedSettingsReset()
                    }
                }
            case .frameworkUnavailable:
                Text(
                    String(
                        localized: "protectedSettings.frameworkUnavailable.message",
                        defaultValue: "Protected preferences are unavailable because the protected-data framework is not ready."
                    )
                )
                .foregroundStyle(.secondary)
            case .settingsSceneProxy:
                VStack(alignment: .leading, spacing: 10) {
                    Text(
                        String(
                            localized: "protectedSettings.proxy.message",
                            defaultValue: "Protected preferences can only be viewed and changed from the main window."
                        )
                    )
                    .foregroundStyle(.secondary)

                    Button(
                        String(
                            localized: "protectedSettings.proxy.openMainWindow",
                            defaultValue: "Open Main Window"
                        )
                    ) {
                        model.openProtectedSettingsInMainWindow()
                    }
                }
            case .tutorialSandbox:
                Text(
                    String(
                        localized: "protectedSettings.tutorial.message",
                        defaultValue: "The tutorial sandbox never reads or writes your real protected preferences."
                    )
                )
                .foregroundStyle(.secondary)
            }
        } header: {
            Text(
                String(
                    localized: "protectedSettings.section",
                    defaultValue: "Protected Preferences"
                )
            )
        }
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
