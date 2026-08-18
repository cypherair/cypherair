import SwiftUI

struct EncryptScreenFormView: View {
    let model: EncryptScreenModel
    var showsModePicker = true

    @FocusState private var passwordFocus: CypherPassphraseEntry.Field?

    var body: some View {
        @Bindable var model = model
        let operation = model.operation

        CypherToolScreenLayout(hasOutput: hasOutput) {
            if showsModePicker {
                Section {
                    modePicker(
                        selection: $model.encryptMode,
                        selectedValueLabel: model.encryptMode.label,
                        isDisabled: operation.isRunning
                    )
                }
            }

            if model.encryptMode == .text {
                EncryptTextInputSection(model: model)
                    .disabled(operation.isRunning)
            } else {
                EncryptFileInputSection(model: model)
                    .disabled(operation.isRunning)
            }

            EncryptProtectionSection(model: model, passwordFocus: $passwordFocus)
                .disabled(operation.isRunning)

            // Signing and the self copy are done with the sender's own keys, so
            // they have nothing to say about a message protected by a password.
            if model.activeProtection == .recipientKeys {
                EncryptOptionsSection(model: model)
                    .disabled(operation.isRunning)
            }

            EncryptActionSections(model: model)
        } output: {
            EncryptResultSections(model: model)
        }
        .onChange(of: model.activeProtection) {
            passwordFocus = nil
        }
        .screenReady("encrypt.ready")
    }

    private var hasOutput: Bool {
        switch model.encryptMode {
        case .text:
            model.ciphertextString != nil
        case .file:
            model.encryptedFileURL != nil
        }
    }

    private func modePicker(
        selection: Binding<EncryptView.EncryptMode>,
        selectedValueLabel: String,
        isDisabled: Bool
    ) -> some View {
        CypherModePicker(
            title: String(localized: "encrypt.mode", defaultValue: "Mode"),
            selection: selection,
            selectedValueLabel: selectedValueLabel,
            isDisabled: isDisabled,
            accessibilityIdentifier: "encrypt.mode.picker"
        ) {
            ForEach(EncryptView.EncryptMode.allCases, id: \.self) { mode in
                Text(mode.label).tag(mode)
            }
        }
    }
}
