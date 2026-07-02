import SwiftUI

struct SettingsAppearanceSection: View {
    let model: SettingsScreenModel

    var body: some View {
        // The App Icon picker is a UIKit alternate-icon feature, so the whole
        // Appearance section exists only on iOS.
        #if os(iOS)
        Section {
            NavigationLink(value: AppRoute.appIcon) {
                Label(
                    String(localized: "settings.appIcon", defaultValue: "App Icon"),
                    systemImage: "app"
                )
            }
            .disabled(!model.configuration.isAppIconEntryEnabled)
        } header: {
            Text(String(localized: "settings.appearance", defaultValue: "Appearance"))
        } footer: {
            if let appearanceEducationFooter = model.configuration.appearanceEducationFooter {
                Text(appearanceEducationFooter)
            }
        }
        #endif
    }
}
