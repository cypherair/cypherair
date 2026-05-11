import SwiftUI

struct SettingsEncryptionSection: View {
    let model: SettingsScreenModel

    var body: some View {
        Section {
            Toggle(
                String(localized: "settings.encryptToSelf", defaultValue: "Encrypt to Self"),
                isOn: Binding(
                    get: { model.encryptToSelfSelection },
                    set: { model.setEncryptToSelf($0) }
                )
            )
            .disabled(!model.isProtectedOrdinarySettingsEditable)
        } header: {
            Text(String(localized: "settings.encryption", defaultValue: "Encryption"))
        }
    }
}
