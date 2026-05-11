import SwiftUI

struct SettingsFormView: View {
    let model: SettingsScreenModel

    var body: some View {
        Form {
            SettingsSecuritySection(model: model)
            SettingsEncryptionSection(model: model)

            if model.shouldShowLocalDataResetSection {
                SettingsLocalDataResetSection(model: model)
            }

            SettingsAppearanceSection(model: model)
            SettingsNavigationSection(model: model)
        }
    }
}
