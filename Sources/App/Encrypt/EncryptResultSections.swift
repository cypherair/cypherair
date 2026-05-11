import SwiftUI

struct EncryptResultSections: View {
    let model: EncryptScreenModel

    var body: some View {
        let operation = model.operation

        Section {
            Button {
                model.requestEncrypt()
            } label: {
                CypherOperationButtonLabel(
                    idleTitle: String(localized: "encrypt.button", defaultValue: "Encrypt"),
                    runningTitle: String(localized: "fileEncrypt.encrypting", defaultValue: "Encrypting..."),
                    isRunning: operation.isRunning,
                    isCancelling: operation.isCancelling,
                    progressFraction: model.encryptMode == .file ? operation.progress?.fractionCompleted : nil
                )
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.encryptButtonDisabled)
        }

        if model.showsFileCancelAction {
            CypherOperationCancelSection(
                isCancelling: operation.isCancelling,
                cancel: operation.cancel
            )
        }

        if model.encryptMode == .text, let ciphertextString = model.ciphertextString {
            Section {
                CypherOutputTextBlock(
                    text: ciphertextString,
                    font: .system(.caption, design: .monospaced)
                )

                Button {
                    model.copyCiphertextToClipboard()
                } label: {
                    Label(
                        String(localized: "common.copy", defaultValue: "Copy"),
                        systemImage: "doc.on.doc"
                    )
                }
                .disabled(!model.configuration.allowsClipboardWrite)

                Button {
                    model.exportCiphertext()
                } label: {
                    Label(
                        String(localized: "common.save", defaultValue: "Save"),
                        systemImage: "square.and.arrow.down"
                    )
                }
                .disabled(!model.configuration.allowsResultExport)
            } header: {
                Text(String(localized: "encrypt.result", defaultValue: "Encrypted Message"))
            }
        }

        if model.encryptMode == .file, model.encryptedFileURL != nil {
            Section {
                Button {
                    model.exportEncryptedFile()
                } label: {
                    Label(
                        String(localized: "fileEncrypt.share", defaultValue: "Save Encrypted File"),
                        systemImage: "square.and.arrow.down"
                    )
                }
                .disabled(!model.configuration.allowsFileResultExport)
            }
        }
    }
}
