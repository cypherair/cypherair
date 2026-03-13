import SwiftUI

/// Settings screen with auth mode, grace period, and other preferences.
struct SettingsView: View {
    @Environment(AppConfiguration.self) private var config

    var body: some View {
        @Bindable var config = config

        List {
            Section {
                Picker(
                    String(localized: "settings.authMode", defaultValue: "Authentication Mode"),
                    selection: $config.authMode
                ) {
                    Text(String(localized: "settings.authMode.standard", defaultValue: "Standard"))
                        .tag(AuthenticationMode.standard)
                    Text(String(localized: "settings.authMode.high", defaultValue: "High Security"))
                        .tag(AuthenticationMode.highSecurity)
                }

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
                NavigationLink(value: AppRoute.selfTest) {
                    Label(
                        String(localized: "settings.selfTest", defaultValue: "Self-Test"),
                        systemImage: "checkmark.circle"
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
            default: Text("Coming soon")
            }
        }
    }
}
