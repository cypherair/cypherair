import SwiftUI

struct EncryptScreenFormView: View {
    let model: EncryptScreenModel
    @Binding var isRecipientTagPickerPresented: Bool

    var body: some View {
        @Bindable var model = model
        let operation = model.operation

        Form {
            Section {
                Picker(String(localized: "encrypt.mode", defaultValue: "Mode"), selection: $model.encryptMode) {
                    ForEach(EncryptView.EncryptMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(operation.isRunning)
            }

            if model.encryptMode == .text {
                EncryptTextInputSection(model: model)
                    .disabled(operation.isRunning)
            } else {
                EncryptFileInputSection(model: model)
                    .disabled(operation.isRunning)
            }

            EncryptRecipientsSection(
                model: model,
                openTagPicker: {
                    isRecipientTagPickerPresented = true
                }
            )
            .disabled(operation.isRunning)

            EncryptOptionsSection(model: model)
                .disabled(operation.isRunning)

            EncryptResultSections(model: model)
        }
    }
}
