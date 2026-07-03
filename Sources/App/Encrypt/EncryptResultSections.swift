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
/// campaign #567): a small badge when every session-key packet of the
/// produced message is post-quantum, a neutral caption when the artifact
/// is mixed, nothing otherwise — with a help sheet for the fuller story.
struct EncryptQuantumSafetyFooter: View {
    let model: EncryptScreenModel
    @State private var showHelp = false

    var body: some View {
        if model.showsQuantumSafeBadge || model.showsMixedQuantumSafetyCaption {
            HStack(spacing: 6) {
                if model.showsQuantumSafeBadge {
                    Label(
                        String(localized: "encrypt.quantumSafe.badge", defaultValue: "Quantum-safe"),
                        systemImage: "checkmark.shield"
                    )
                    .accessibilityIdentifier("encrypt.quantumSafeBadge")
                } else {
                    Text(String(
                        localized: "encrypt.quantumSafe.mixedCaption",
                        defaultValue: "Not fully quantum-safe: some recipients use classical keys."
                    ))
                    .accessibilityIdentifier("encrypt.quantumSafeMixedCaption")
                }

                Button {
                    showHelp = true
                } label: {
                    Image(systemName: "info.circle")
                }
                .buttonStyle(.plain)
                .accessibilityLabel(String(
                    localized: "encrypt.quantumSafe.helpButton",
                    defaultValue: "About quantum safety"
                ))
                .accessibilityIdentifier("encrypt.quantumSafeHelp")
            }
            .sheet(isPresented: $showHelp) {
                EncryptQuantumSafetyHelpSheet()
            }
        }
    }
}

struct EncryptQuantumSafetyHelpSheet: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text(String(
                        localized: "encrypt.quantumSafe.helpBody1",
                        defaultValue: "A message is quantum-safe when every key it is encrypted to uses post-quantum algorithms (RFC 9980). Those algorithms are designed to resist attackers with future quantum computers."
                    ))
                    Text(String(
                        localized: "encrypt.quantumSafe.helpBody2",
                        defaultValue: "When some of the targeted keys are classical, the message can still be read through those keys by such an attacker. For a fully quantum-safe message, every recipient — and your own key, when Encrypt to Self is on — must use a post-quantum key."
                    ))
                }
                .padding()
            }
            .navigationTitle(String(
                localized: "encrypt.quantumSafe.helpTitle",
                defaultValue: "Quantum Safety"
            ))
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "common.done", defaultValue: "Done")) {
                        dismiss()
                    }
                }
            }
        }
        .presentationDetents([.medium])
    }
}
