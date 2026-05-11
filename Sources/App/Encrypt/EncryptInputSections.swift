import SwiftUI

struct EncryptTextInputSection: View {
    let model: EncryptScreenModel

    var body: some View {
        @Bindable var model = model

        Section {
            CypherMultilineTextInput(
                text: $model.plaintext,
                mode: .prose
            )
            .frame(
                minHeight: editorHeightRange.min,
                idealHeight: editorHeightRange.ideal,
                maxHeight: editorHeightRange.max
            )
        } header: {
            Text(String(localized: "encrypt.plaintext", defaultValue: "Message"))
        }
        .id(model.textInputSectionEpoch)
    }

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        (110, 160, 240)
        #else
        (120, 170, 240)
        #endif
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
