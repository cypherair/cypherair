import SwiftUI

struct EncryptActionSections: View {
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
            .keyboardShortcut(.defaultAction)
            .disabled(model.encryptButtonDisabled)
        }

        if model.showsFileCancelAction {
            CypherOperationCancelSection(
                isCancelling: operation.isCancelling,
                cancel: operation.cancel
            )
        }
    }
}

struct EncryptResultSections: View {
    let model: EncryptScreenModel

    var body: some View {
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
                .keyboardShortcut("s", modifiers: .command)
                .disabled(!model.configuration.allowsResultExport)
            } header: {
                Text(String(localized: "encrypt.result", defaultValue: "Encrypted Message"))
            } footer: {
                EncryptQuantumSafetyFooter(model: model)
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
                .keyboardShortcut("s", modifiers: .command)
                .disabled(!model.configuration.allowsFileResultExport)
            } footer: {
                EncryptQuantumSafetyFooter(model: model)
            }
        }
    }
}

/// Quiet quantum-safety state for the encryption result (design doc §5,
/// campaign #567): a small badge when every targeted key is post-quantum,
/// a neutral caption when the set is mixed, nothing otherwise.
struct EncryptQuantumSafetyFooter: View {
    let model: EncryptScreenModel

    var body: some View {
        if model.showsQuantumSafeBadge {
            Label(
                String(localized: "encrypt.quantumSafe.badge", defaultValue: "Quantum-safe"),
                systemImage: "checkmark.shield"
            )
            .accessibilityIdentifier("encrypt.quantumSafeBadge")
        } else if model.showsMixedQuantumSafetyCaption {
            Text(String(
                localized: "encrypt.quantumSafe.mixedCaption",
                defaultValue: "Not fully quantum-safe: some recipients use classical keys."
            ))
            .accessibilityIdentifier("encrypt.quantumSafeMixedCaption")
        }
    }
}
