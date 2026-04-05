import SwiftUI

@MainActor
struct AuthModeChangeConfirmationRequest: Identifiable {
    let id = UUID()
    let pendingMode: AuthenticationMode
    let title: String
    let message: String
    let requiresRiskAcknowledgement: Bool
    let onConfirm: @MainActor () -> Void
    let onCancel: @MainActor () -> Void
}

/// Settings screen with auth mode, grace period, and other preferences.
struct SettingsView: View {
    struct Configuration {
        var onAuthModeConfirmationRequested: (@MainActor (AuthModeChangeConfirmationRequest) -> Void)?

        static let `default` = Configuration()
    }

    @Environment(AppConfiguration.self) private var config
    @Environment(AuthenticationManager.self) private var authManager
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.macPresentationController) private var macPresentationController
    #if canImport(UIKit)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    @State private var pendingMode: AuthenticationMode?
    @State private var showModeWarning = false
    @State private var isSwitching = false
    @State private var switchError: String?
    @State private var showSwitchError = false
    @State private var showOnboarding = false
    @State private var showTutorialOnboarding = false
    @State private var riskAcknowledged = false

    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        @Bindable var config = config

        Form {
            Section {
                Picker(
                    String(localized: "settings.authMode", defaultValue: "Authentication Mode"),
                    selection: Binding(
                        get: { config.authMode },
                        set: { newMode in
                            guard newMode != config.authMode else { return }
                            handleAuthModeSelection(newMode)
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
                .disabled(isSwitching)

                Picker(
                    String(localized: "settings.gracePeriod", defaultValue: "Re-authentication"),
                    selection: $config.gracePeriod
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
                    isOn: $config.encryptToSelf
                )
                Toggle(
                    String(localized: "settings.clipboardNotice", defaultValue: "Clipboard Safety Notice"),
                    isOn: $config.clipboardNotice
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
                #if canImport(UIKit)
                NavigationLink(value: AppRoute.appIcon) {
                    Label(
                        String(localized: "settings.appIcon", defaultValue: "App Icon"),
                        systemImage: "app"
                    )
                }
                #endif
            } header: {
                Text(String(localized: "settings.appearance", defaultValue: "Appearance"))
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
                    presentOnboarding()
                } label: {
                    Label(
                        String(localized: "settings.viewOnboarding", defaultValue: "View Onboarding"),
                        systemImage: "book"
                    )
                }
                .accessibilityIdentifier("settings.onboarding")
                Button {
                    presentTutorial()
                } label: {
                    Label(
                        guidedTutorialEntryTitle,
                        systemImage: "testtube.2"
                    )
                }
                .accessibilityIdentifier("settings.tutorial")
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
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .accessibilityIdentifier("settings.root")
        .screenReady("settings.ready")
        .navigationTitle(String(localized: "settings.title", defaultValue: "Settings"))
        .confirmationDialog(
            modeWarningTitle,
            isPresented: Binding(
                get: { showModeWarning && !shouldUseModeSheet },
                set: { showModeWarning = $0 }
            ),
            titleVisibility: .visible
        ) {
            if pendingMode == .highSecurity && !hasBackup {
                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {
                    pendingMode = nil
                }
            } else {
                Button(String(localized: "settings.mode.confirm", defaultValue: "Switch Mode"), role: .destructive) {
                    performModeSwitch()
                }
                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {
                    pendingMode = nil
                }
            }
        } message: {
            if pendingMode == .highSecurity && !hasBackup {
                Text(String(localized: "settings.mode.highWarning.noBackup.useSheet", defaultValue: "You have not backed up any keys. A separate confirmation is required."))
            } else {
                Text(modeWarningMessage)
            }
        }
        .sheet(isPresented: Binding(
            get: { shouldUseModeSheet && showModeWarning },
            set: { if !$0 { pendingMode = nil; riskAcknowledged = false } }
        )) {
            NavigationStack {
                Form {
                    Section {
                        Text(modeWarningMessage)
                            .font(.callout)
                    }

                    if pendingMode == .highSecurity && !hasBackup {
                        Section {
                            Toggle(isOn: $riskAcknowledged) {
                                Text(String(localized: "settings.mode.riskAck", defaultValue: "I understand that if biometrics become unavailable, I will lose access to my private keys"))
                                    .font(.callout)
                            }
                        }
                    }

                    Section {
                        Button(String(localized: "settings.mode.confirm", defaultValue: "Switch Mode"), role: .destructive) {
                            showModeWarning = false
                            performModeSwitch()
                        }
                        .tutorialAnchor(.settingsModeConfirmButton)
                        .disabled((pendingMode == .highSecurity && !hasBackup) && !riskAcknowledged)
                        .frame(maxWidth: .infinity)
                    }
                }
                .navigationTitle(String(localized: "settings.mode.highWarning.title", defaultValue: "Enable High Security Mode"))
                #if canImport(UIKit)
                .navigationBarTitleDisplayMode(.inline)
                #endif
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                            pendingMode = nil
                            riskAcknowledged = false
                        }
                    }
                }
            }
            #if os(macOS)
            .frame(minWidth: 500, idealWidth: 540, minHeight: 360, idealHeight: 420)
            #endif
            #if canImport(UIKit)
            .presentationDetents([.medium, .large])
            #endif
        }
        .alert(
            String(localized: "settings.mode.error.title", defaultValue: "Mode Switch Failed"),
            isPresented: $showSwitchError
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: {
            if let switchError {
                Text(switchError)
            }
        }
        .sheet(isPresented: $showOnboarding) {
            OnboardingView()
        }
        .sheet(isPresented: $showTutorialOnboarding) {
            OnboardingView(initialPage: 2)
        }
    }

    private var hasBackup: Bool {
        keyManagement.keys.contains(where: \.isBackedUp)
    }

    private var guidedTutorialEntryTitle: String {
        switch config.guidedTutorialCompletionState {
        case .neverCompleted:
            String(localized: "guidedTutorial.settings.entry", defaultValue: "Guided Tutorial")
        case .completedCurrentVersion:
            String(localized: "guidedTutorial.replay", defaultValue: "Replay Guided Tutorial")
        case .completedPreviousVersion:
            String(localized: "guidedTutorial.updated.entry", defaultValue: "Updated Guided Tutorial Available")
        }
    }

    private var shouldUseModeSheet: Bool {
        pendingMode == .highSecurity && !hasBackup
    }

    private var modeWarningTitle: String {
        warningTitle(for: pendingMode ?? config.authMode)
    }

    private var modeWarningMessage: String {
        warningMessage(for: pendingMode ?? config.authMode, hasBackup: hasBackup)
    }

    private func performModeSwitch() {
        guard let newMode = pendingMode else { return }
        performModeSwitch(to: newMode)
    }

    private func performModeSwitch(to newMode: AuthenticationMode) {
        isSwitching = true
        let fingerprints = keyManagement.keys.map(\.fingerprint)
        let backed = hasBackup
        let manager = authManager

        Task {
            do {
                try await manager.switchMode(
                    to: newMode,
                    fingerprints: fingerprints,
                    hasBackup: backed,
                    authenticator: manager
                )
                config.authMode = newMode
            } catch {
                switchError = error.localizedDescription
                showSwitchError = true
            }
            pendingMode = nil
            isSwitching = false
        }
    }

    private func handleAuthModeSelection(_ newMode: AuthenticationMode) {
        if let onAuthModeConfirmationRequested = configuration.onAuthModeConfirmationRequested {
            onAuthModeConfirmationRequested(makeAuthModeChangeRequest(for: newMode))
        } else if let macPresentationController {
            macPresentationController.present(
                .authModeConfirmation(makeAuthModeChangeRequest(for: newMode))
            )
        } else {
            pendingMode = newMode
            showModeWarning = true
        }
    }

    private func presentOnboarding() {
        if let macPresentationController {
            macPresentationController.present(.onboarding(initialPage: 0))
        } else {
            showOnboarding = true
        }
    }

    private func presentTutorial() {
        if let macPresentationController {
            macPresentationController.present(.tutorial(presentationContext: .inApp))
        } else {
            showTutorialOnboarding = true
        }
    }

    private func makeAuthModeChangeRequest(for newMode: AuthenticationMode) -> AuthModeChangeConfirmationRequest {
        AuthModeChangeConfirmationRequest(
            pendingMode: newMode,
            title: warningTitle(for: newMode),
            message: warningMessage(for: newMode, hasBackup: hasBackup),
            requiresRiskAcknowledgement: newMode == .highSecurity && !hasBackup,
            onConfirm: {
                pendingMode = newMode
                performModeSwitch(to: newMode)
            },
            onCancel: {
                pendingMode = nil
                riskAcknowledged = false
            }
        )
    }

    private func warningTitle(for mode: AuthenticationMode) -> String {
        if mode == .highSecurity {
            return String(localized: "settings.mode.highWarning.title", defaultValue: "Enable High Security Mode")
        }
        return String(localized: "settings.mode.standardWarning.title", defaultValue: "Switch to Standard Mode")
    }

    private func warningMessage(for mode: AuthenticationMode, hasBackup: Bool) -> String {
        if mode == .highSecurity {
            if !hasBackup {
                #if os(macOS)
                return String(localized: "settings.mode.highWarning.noBackup.mac", defaultValue: "WARNING: In High Security mode, if Touch ID becomes unavailable, you will be unable to access your private keys. You have NOT backed up any keys. If biometrics fail, your keys will be permanently inaccessible. Back up your keys first, or proceed at your own risk.")
                #else
                return String(localized: "settings.mode.highWarning.noBackup", defaultValue: "WARNING: In High Security mode, if Face ID / Touch ID becomes unavailable, you will be unable to access your private keys. You have NOT backed up any keys. If biometrics fail, your keys will be permanently inaccessible. Back up your keys first, or proceed at your own risk.")
                #endif
            }
            #if os(macOS)
            return String(localized: "settings.mode.highWarning.message.mac", defaultValue: "In High Security mode, if Touch ID becomes unavailable, you will be unable to access your private keys. Ensure you have a current backup. Biometric authentication is required to confirm this change.")
            #else
            return String(localized: "settings.mode.highWarning.message", defaultValue: "In High Security mode, if Face ID / Touch ID becomes unavailable, you will be unable to access your private keys. Ensure you have a current backup. Biometric authentication is required to confirm this change.")
            #endif
        }
        return String(localized: "settings.mode.standardWarning.message", defaultValue: "Switching to Standard Mode will allow device passcode as a fallback for authentication. Biometric authentication is required to confirm this change.")
    }
}

#if os(macOS)
struct MacSettingsRootView: View {
    let launchConfiguration: AppLaunchConfiguration?

    @State private var path: [AppRoute] = []
    @State private var activePresentation: MacPresentation?

    init(launchConfiguration: AppLaunchConfiguration? = nil) {
        self.launchConfiguration = launchConfiguration
    }

    var body: some View {
        AppRouteHost(
            resolver: .production,
            path: $path
        ) {
            SettingsView()
        }
        .environment(
            \.macPresentationController,
            MacPresentationController { presentation in
                activePresentation = presentation
            }
        )
        .task {
            if launchConfiguration?.opensAuthModeConfirmation == true,
               activePresentation == nil {
                activePresentation = .authModeConfirmation(
                    AuthModeChangeConfirmationRequest(
                        pendingMode: .highSecurity,
                        title: String(localized: "settings.mode.highWarning.title", defaultValue: "Enable High Security Mode"),
                        message: String(localized: "settings.mode.highWarning.message.mac", defaultValue: "In High Security mode, if Touch ID becomes unavailable, you will be unable to access your private keys. Ensure you have a current backup. Biometric authentication is required to confirm this change."),
                        requiresRiskAcknowledgement: false,
                        onConfirm: { },
                        onCancel: { }
                    )
                )
            }
        }
        .macPresentationHost($activePresentation)
    }
}
#endif

struct SettingsAuthModeConfirmationSheetView: View {
    let request: AuthModeChangeConfirmationRequest

    @State private var riskAcknowledged = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section {
                Text(request.message)
                    .font(.callout)
            }

            if request.requiresRiskAcknowledgement {
                Section {
                    Toggle(isOn: $riskAcknowledged) {
                        Text(String(localized: "settings.mode.riskAck", defaultValue: "I understand that if biometrics become unavailable, I will lose access to my private keys"))
                            .font(.callout)
                    }
                }
            }

            Section {
                Button(String(localized: "settings.mode.confirm", defaultValue: "Switch Mode"), role: .destructive) {
                    dismiss()
                    request.onConfirm()
                }
                .accessibilityIdentifier("settings.mode.confirm")
                .disabled(request.requiresRiskAcknowledgement && !riskAcknowledged)
                .frame(maxWidth: .infinity)
            }
        }
        .screenReady("settings.authmode.ready")
        .navigationTitle(request.title)
        #if canImport(UIKit)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    dismiss()
                    request.onCancel()
                }
            }
        }
    }
}

private extension View {
    @ViewBuilder
    func `if`<Content: View>(
        _ condition: Bool,
        transform: (Self) -> Content
    ) -> some View {
        if condition {
            transform(self)
        } else {
            self
        }
    }
}
