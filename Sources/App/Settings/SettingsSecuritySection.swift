import SwiftUI

struct SettingsSecuritySection: View {
    let model: SettingsScreenModel

    var body: some View {
        @Bindable var appConfiguration = model.appConfiguration

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
                    get: { appConfiguration.authModeIfUnlocked ?? .standard },
                    set: { newMode in
                        guard let currentMode = appConfiguration.authModeIfUnlocked,
                              newMode != currentMode else { return }
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
            .disabled(model.isSwitching || appConfiguration.authModeIfUnlocked == nil)

            Picker(
                String(localized: "settings.gracePeriod", defaultValue: "Re-authentication"),
                selection: Binding(
                    get: { model.gracePeriodSelection },
                    set: { model.setGracePeriod($0) }
                )
            ) {
                ForEach(AppConfiguration.gracePeriodOptions, id: \.value) { option in
                    Text(option.label).tag(option.value)
                }
            }
            .disabled(!model.isProtectedOrdinarySettingsEditable)

            if model.shouldShowClipboardNoticeRow {
                SettingsProtectedClipboardNoticeRow(model: model)
            }
        } header: {
            Text(String(localized: "settings.security", defaultValue: "Security"))
        }
    }
}
