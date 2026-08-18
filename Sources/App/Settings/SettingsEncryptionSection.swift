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

            Toggle(
                String(localized: "settings.signMessages", defaultValue: "Sign Messages"),
                isOn: Binding(
                    get: { model.signMessagesSelection },
                    set: { model.setSignMessages($0) }
                )
            )
            .disabled(!model.isProtectedOrdinarySettingsEditable)
        } header: {
            Text(String(localized: "settings.encryption", defaultValue: "Encryption"))
        } footer: {
            Text(String(
                localized: "settings.signMessages.footer",
                defaultValue: "Signing proves a message came from you and ties it to your key. These are the defaults for new messages; each message can still be changed before you encrypt it."
            ))
        }
    }
}
