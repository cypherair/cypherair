import SwiftUI

struct SettingsAppearanceSection: View {
    let model: SettingsScreenModel

    var body: some View {
        Section {
            NavigationLink(value: AppRoute.themePicker) {
                Label(
                    String(localized: "settings.theme", defaultValue: "Color Theme"),
                    systemImage: "paintpalette"
                )
            }
            .accessibilityIdentifier("settings.theme")
            .disabled(
                !model.configuration.isThemePickerEnabled
                    || !model.isProtectedOrdinarySettingsEditable
            )

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
    }
}
