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
    @State private var riskAcknowledged = false

    var body: some View {
        @Bindable var config = config

        List {
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

                Toggle(
                    String(localized: "settings.requireAuthOnLaunch", defaultValue: "Require Authentication on Launch"),
                    isOn: $config.requireAuthOnLaunch
                )
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

            #if canImport(UIKit)
            Section {
                NavigationLink(value: AppRoute.appIcon) {
                    Label(
                        String(localized: "settings.appIcon", defaultValue: "App Icon"),
                        systemImage: "app"
                    )
                }
            } header: {
                Text(String(localized: "settings.appearance", defaultValue: "Appearance"))
            }
            #endif

            Section {
                NavigationLink(value: AppRoute.selfTest) {
                    Label(
                        String(localized: "settings.selfTest", defaultValue: "Self-Test"),
                        systemImage: "checkmark.circle"
                    )
                }
                Button {
                    showOnboarding = true
                } label: {
                    Label(
                        String(localized: "settings.viewOnboarding", defaultValue: "View Onboarding"),
                        systemImage: "book"
                    )
                }
                NavigationLink(value: AppRoute.about) {
                    Label(
                        String(localized: "settings.about", defaultValue: "About"),
                        systemImage: "info.circle"
                    )
                }
            }
        }
        .navigationTitle(String(localized: "settings.title", defaultValue: "Settings"))
        .navigationDestination(for: AppRoute.self) { route in
            switch route {
            case .selfTest: SelfTestView()
            case .about: AboutView()
            case .appIcon: AppIconPickerView()
            case .keyGeneration, .keyDetail, .backupKey, .importKey,
                 .contactDetail, .addContact, .qrDisplay, .qrPhotoImport,
                 .encrypt, .decrypt,
                 .sign, .verify:
                let _ = assertionFailure("Unexpected route \(route) in SettingsView")
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
            .presentationDetents([.medium, .large])
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
                return String(localized: "settings.mode.highWarning.noBackup", defaultValue: "WARNING: In High Security mode, if Face ID / Touch ID becomes unavailable, you will be unable to access your private keys. You have NOT backed up any keys. If biometrics fail, your keys will be permanently inaccessible. Back up your keys first, or proceed at your own risk.")
            }
            return String(localized: "settings.mode.highWarning.message", defaultValue: "In High Security mode, if Face ID / Touch ID becomes unavailable, you will be unable to access your private keys. Ensure you have a current backup. Biometric authentication is required to confirm this change.")
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
