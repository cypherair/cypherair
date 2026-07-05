import SwiftUI
import UniformTypeIdentifiers

/// Import a private key from file, paste, or QR photo.
struct ImportKeyView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ImportKeyScreenHostView(
            keyManagement: keyManagement,
            appSessionOrchestrator: appSessionOrchestrator,
            dismissAction: { dismiss() }
        )
    }
}

private struct ImportKeyScreenHostView: View {
    let appSessionOrchestrator: AppSessionOrchestrator

    @State private var model: ImportKeyScreenModel

    init(
        keyManagement: KeyManagementService,
        appSessionOrchestrator: AppSessionOrchestrator,
        dismissAction: @escaping @MainActor () -> Void
    ) {
        self.appSessionOrchestrator = appSessionOrchestrator
        _model = State(
            initialValue: ImportKeyScreenModel(
                keyManagement: keyManagement,
                dismissAction: dismissAction
            )
        )
    }

    var body: some View {
        @Bindable var model = model
        let fileImportRequestToken = model.fileImportRequestToken

        Form {
            Section {
                if let fileName = model.importedFileName, model.importedKeyData != nil {
                    CypherImportedFileRow(
                        fileName: fileName,
                        clearAccessibilityLabel: String(localized: "import.clearFile", defaultValue: "Clear file")
                    ) {
                        model.clearImportedFile()
                    }
                } else {
                    CypherMultilineTextInput(
                        text: $model.armoredText,
                        mode: .machineText,
                        title: String(localized: "import.editor.title", defaultValue: "Private Key")
                    )
                }
            } header: {
                Text(String(localized: "import.paste.header", defaultValue: "Paste armored private key"))
            }

            Section {
                Button {
                    model.requestFileImport()
                } label: {
                    Label(
                        String(localized: "import.fromFile", defaultValue: "Import from File"),
                        systemImage: "doc"
                    )
                }
            } header: {
                Text(String(localized: "import.file.header", defaultValue: "Or Import from File"))
            }

            Section {
                CypherSecureTextField(
                    String(localized: "import.passphrase", defaultValue: "Passphrase"),
                    text: $model.passphrase
                )
            } header: {
                Text(String(localized: "import.passphrase.header", defaultValue: "Key Passphrase"))
            }

            Section {
                Button {
                    model.importKey()
                } label: {
                    if model.isImporting {
                        ProgressView()
                            .cypherPrimaryActionLabelFrame()
                    } else {
                        Text(String(localized: "import.button", defaultValue: "Import Key"))
                            .cypherPrimaryActionLabelFrame()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.importButtonDisabled)
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent(maxWidth: MacPresentationWidth.textHeavy)
        .navigationTitle(String(localized: "import.title", defaultValue: "Import Key"))
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: Binding(
                get: { model.showError },
                set: { if !$0 { model.dismissError() } }
            ),
            presenting: model.error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                model.dismissError()
            }
        } message: { err in
            Text(err.localizedDescription)
        }
        .fileImporter(
            isPresented: $model.showFileImporter,
            allowedContentTypes: [
                UTType(filenameExtension: "asc") ?? .plainText,
                UTType(filenameExtension: "gpg") ?? .data,
                UTType(filenameExtension: "pgp") ?? .data,
                .data
            ],
            allowsMultipleSelection: false
        ) { result in
            model.handleFileImporterResult(result, token: fileImportRequestToken)
        }
        .onDisappear {
            model.handleDisappear()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            model.handleContentClearGenerationChange()
        }
    }
}
