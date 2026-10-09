import SwiftUI

struct SettingsSecuritySection: View {
    let model: SettingsScreenModel

    var body: some View {
        Section {
            if !model.configuration.isSandbox {
                Button {
                    model.presentChangePassphrase()
                } label: {
                    Label(
                        String(localized: "settings.changePassphrase", defaultValue: "Change Passphrase"),
                        systemImage: "key.horizontal"
                    )
                }
                .disabled(!model.isSettingsEditable)
                .accessibilityIdentifier("settings.changePassphrase")
            }
            Picker(
                String(localized: "settings.gracePeriod", defaultValue: "Re-authentication"),
                selection: Binding(
                    get: { model.gracePeriodSelection },
                    set: { model.setGracePeriod($0) }
                )
            ) {
                ForEach(SettingsGracePeriodPresentation.options) { option in
                    Text(option.label).tag(option.value)
                }
            }
            .disabled(!model.isSettingsEditable)
            SettingsClipboardNoticeRow(model: model)
        } header: {
            Text(String(localized: "settings.security", defaultValue: "Security"))
        } footer: {
            Text(String(
                localized: "settings.security.footer",
                defaultValue: "Unlocking takes your passphrase and one Face ID or Touch ID confirmation. Device-bound keys ask for biometrics again on every use."
            ))
        }
    }
}

struct SettingsClipboardNoticeRow: View {
    let model: SettingsScreenModel

    var body: some View {
        if model.configuration.isSandbox {
            VStack(alignment: .leading, spacing: 4) {
                Toggle(
                    String(localized: "settings.clipboardNotice", defaultValue: "Clipboard Safety Notice"),
                    isOn: .constant(true)
                )
                .disabled(true)
                Text(
                    String(
                        localized: "protectedSettings.tutorial.message",
                        defaultValue: "The tutorial sandbox never reads or writes your real Clipboard Safety Notice."
                    )
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
        } else {
            Toggle(
                String(localized: "settings.clipboardNotice", defaultValue: "Clipboard Safety Notice"),
                isOn: Binding(
                    get: { model.isClipboardNoticeEnabled },
                    set: { model.setClipboardNoticeEnabled($0) }
                )
            )
            .disabled(!model.isSettingsEditable)
            .accessibilityIdentifier("settings.clipboardNotice")
        }
    }
}
