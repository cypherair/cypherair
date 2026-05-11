import SwiftUI

struct EncryptOptionsSection: View {
    let model: EncryptScreenModel

    var body: some View {
        @Bindable var model = model

        Section {
            Toggle(
                String(localized: "encrypt.encryptToSelf", defaultValue: "Encrypt to Self"),
                isOn: Binding(
                    get: { model.encryptToSelfToggleValue },
                    set: { model.encryptToSelf = $0 }
                )
            )
            .disabled(!model.isEncryptToSelfControlEnabled)

            if model.encryptToSelfToggleValue && model.ownKeys.count > 1 {
                Picker(
                    String(localized: "encrypt.encryptToSelfKey", defaultValue: "Encrypt to Self With"),
                    selection: $model.encryptToSelfFingerprint
                ) {
                    ForEach(model.ownKeys) { key in
                        Text(key.userId ?? key.shortKeyId)
                            .tag(Optional(key.fingerprint))
                    }
                }
            }

            Toggle(
                String(localized: "encrypt.sign", defaultValue: "Sign Message"),
                isOn: $model.signMessage
            )
            .disabled(model.configuration.signingPolicy.isLocked)

            if model.signMessage && model.ownKeys.count > 1 {
                Picker(
                    String(localized: "encrypt.signingKey", defaultValue: "Signing Key"),
                    selection: $model.signerFingerprint
                ) {
                    ForEach(model.ownKeys) { key in
                        Text(key.userId ?? key.shortKeyId)
                            .tag(Optional(key.fingerprint))
                    }
                }
            }
        }
    }
}
