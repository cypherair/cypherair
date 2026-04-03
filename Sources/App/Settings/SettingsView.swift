import SwiftUI

/// Settings screen with auth mode, grace period, and other preferences.
struct SettingsView: View {
    @Environment(AppConfiguration.self) private var config
    @Environment(AuthenticationManager.self) private var authManager
    @Environment(KeyManagementService.self) private var keyManagement

    @State private var pendingMode: AuthenticationMode?
    @State private var showModeWarning = false
    @State private var isSwitching = false
    @State private var switchError: String?
    @State private var showSwitchError = false
    @State private var showOnboarding = false
    @State private var showTutorial = false
    @State private var riskAcknowledged = false
    #if os(macOS)
    @State private var showThemePicker = false
    @State private var showSelfTest = false
    @State private var showAbout = false
    @State private var showLicense = false
    #endif

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
                            pendingMode = newMode
                            showModeWarning = true
                        }
                    )
                ) {
                    Text(String(localized: "settings.authMode.standard", defaultValue: "Standard"))
                        .tag(AuthenticationMode.standard)
                    Text(String(localized: "settings.authMode.high", defaultValue: "High Security"))
                        .tag(AuthenticationMode.highSecurity)
                }
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
                #if os(macOS)
                Button {
                    showThemePicker = true
                } label: {
                    Label(
                        String(localized: "settings.theme", defaultValue: "Color Theme"),
                        systemImage: "paintpalette"
                    )
                }
                #else
                NavigationLink(value: AppRoute.themePicker) {
                    Label(
                        String(localized: "settings.theme", defaultValue: "Color Theme"),
                        systemImage: "paintpalette"
                    )
                }
                #endif
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
                #if os(macOS)
                Button {
                    showSelfTest = true
                } label: {
                    Label(
                        String(localized: "settings.selfTest", defaultValue: "Self-Test"),
                        systemImage: "checkmark.circle"
                    )
                }
                #else
                NavigationLink(value: AppRoute.selfTest) {
                    Label(
                        String(localized: "settings.selfTest", defaultValue: "Self-Test"),
                        systemImage: "checkmark.circle"
                    )
                }
                #endif
                Button {
                    showOnboarding = true
                } label: {
                    Label(
                        String(localized: "settings.viewOnboarding", defaultValue: "View Onboarding"),
                        systemImage: "book"
                    )
                }
                Button {
                    showTutorial = true
                } label: {
                    Label(
                        String(localized: "settings.viewTutorial", defaultValue: "Usage Tutorial"),
                        systemImage: "list.number"
                    )
                }
                #if os(macOS)
                Button {
                    showLicense = true
                } label: {
                    Label(
                        String(localized: "settings.license", defaultValue: "Licenses"),
                        systemImage: "doc.text"
                    )
                }
                #else
                NavigationLink(value: AppRoute.license) {
                    Label(
                        String(localized: "settings.license", defaultValue: "Licenses"),
                        systemImage: "doc.text"
                    )
                }
                #endif
                #if os(macOS)
                Button {
                    showAbout = true
                } label: {
                    Label(
                        String(localized: "settings.about", defaultValue: "About"),
                        systemImage: "info.circle"
                    )
                }
                #else
                NavigationLink(value: AppRoute.about) {
                    Label(
                        String(localized: "settings.about", defaultValue: "About"),
                        systemImage: "info.circle"
                    )
                }
                #endif
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .navigationTitle(String(localized: "settings.title", defaultValue: "Settings"))
        .navigationDestination(for: AppRoute.self) { route in
            switch route {
            case .selfTest: SelfTestView()
            case .about: AboutView()
            case .license: LicenseListView()
            case .themePicker: ThemePickerView()
            case .appIcon:
                #if canImport(UIKit)
                AppIconPickerView()
                    #else
                Text(String(localized: "common.comingSoon", defaultValue: "Coming soon"))
                #endif
            default:
                Text(String(localized: "common.comingSoon", defaultValue: "Coming soon"))
            }
        }
        .confirmationDialog(
            modeWarningTitle,
            isPresented: $showModeWarning,
            titleVisibility: .visible
        ) {
            if pendingMode == .highSecurity && !hasBackup {
                // Risk acknowledgment required — handled by the sheet below instead
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
            get: { pendingMode == .highSecurity && !hasBackup && showModeWarning },
            set: { if !$0 { pendingMode = nil; riskAcknowledged = false } }
        )) {
            NavigationStack {
                Form {
                    Section {
                        Text(modeWarningMessage)
                            .font(.callout)
                    }

                    Section {
                        Toggle(isOn: $riskAcknowledged) {
                            Text(String(localized: "settings.mode.riskAck", defaultValue: "I understand that if biometrics become unavailable, I will lose access to my private keys"))
                                .font(.callout)
                        }
                    }

                    Section {
                        Button(String(localized: "settings.mode.confirm", defaultValue: "Switch Mode"), role: .destructive) {
                            showModeWarning = false
                            performModeSwitch()
                        }
                        .disabled(!riskAcknowledged)
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
        .sheet(isPresented: $showTutorial) {
            TutorialView()
        }
        #if os(macOS)
        .sheet(isPresented: $showThemePicker) {
            NavigationStack {
                ThemePickerView()
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                                showThemePicker = false
                            }
                        }
                    }
            }
            .frame(minWidth: 500, minHeight: 420)
        }
        .sheet(isPresented: $showSelfTest) {
            NavigationStack {
                SelfTestView()
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                                showSelfTest = false
                            }
                        }
                    }
            }
            .frame(minWidth: 500, minHeight: 450)
        }
        .sheet(isPresented: $showAbout) {
            NavigationStack {
                AboutView()
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) {
                            Button(String(localized: "common.done", defaultValue: "Done")) {
                                showAbout = false
                            }
                        }
                    }
            }
            .frame(minWidth: 400, minHeight: 350)
        }
        .sheet(isPresented: $showLicense) {
            NavigationStack {
                LicenseListView()
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) {
                            Button(String(localized: "common.done", defaultValue: "Done")) {
                                showLicense = false
                            }
                        }
                    }
            }
            .frame(minWidth: 700, minHeight: 600)
        }
        #endif
    }

    // MARK: - Mode Switch Warnings

    private var hasBackup: Bool {
        keyManagement.keys.contains(where: \.isBackedUp)
    }

    private var modeWarningTitle: String {
        if pendingMode == .highSecurity {
            return String(localized: "settings.mode.highWarning.title", defaultValue: "Enable High Security Mode")
        }
        return String(localized: "settings.mode.standardWarning.title", defaultValue: "Switch to Standard Mode")
    }

    private var modeWarningMessage: String {
        if pendingMode == .highSecurity {
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

    // MARK: - Mode Switch

    private func performModeSwitch() {
        guard let newMode = pendingMode else { return }
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
}
