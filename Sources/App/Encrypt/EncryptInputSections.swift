import SwiftUI

struct EncryptTextInputSection: View {
    let model: EncryptScreenModel

    var body: some View {
        @Bindable var model = model

        Section {
            CypherMultilineTextInput(
                text: $model.plaintext,
                mode: .prose,
                title: String(localized: "encrypt.plaintext", defaultValue: "Message")
            )
        } header: {
            Text(String(localized: "encrypt.plaintext", defaultValue: "Message"))
        }
        .id(model.textInputSectionEpoch)
    }
}

struct EncryptFileInputSection: View {
    let model: EncryptScreenModel

    var body: some View {
        Section {
            Button {
                model.requestFileImport()
            } label: {
                Label(
                    String(localized: "fileEncrypt.selectFile", defaultValue: "Select File"),
                    systemImage: "doc.badge.plus"
                )
            }
            .disabled(!model.configuration.allowsFileInput)

            if let selectedFileName = model.selectedFileName {
                LabeledContent(
                    String(localized: "fileEncrypt.selectedFile", defaultValue: "Selected"),
                    value: selectedFileName
                )
            }
        } header: {
            Text(String(localized: "fileEncrypt.file", defaultValue: "File"))
        } footer: {
            if let fileRestrictionMessage = model.configuration.fileRestrictionMessage {
                Text(fileRestrictionMessage)
            }
        }
    }
}
