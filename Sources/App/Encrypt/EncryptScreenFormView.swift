import SwiftUI

struct EncryptScreenFormView: View {
    let model: EncryptScreenModel
    var showsModePicker = true

    var body: some View {
        @Bindable var model = model
        let operation = model.operation

        Form {
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

            EncryptRecipientsSection(model: model)
                .disabled(operation.isRunning)

            EncryptOptionsSection(model: model)
                .disabled(operation.isRunning)

            EncryptResultSections(model: model)
        }
        .screenReady("encrypt.ready")
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
