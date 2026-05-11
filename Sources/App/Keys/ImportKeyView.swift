import SwiftUI
import UniformTypeIdentifiers

/// Import a private key from file, paste, or QR photo.
struct ImportKeyView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
    @Environment(\.dismiss) private var dismiss

    @State private var armoredText = ""
    @State private var passphrase = ""
    @State private var isImporting = false
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showFileImporter = false
    /// Raw key data for binary .gpg/.pgp files that cannot be represented as a String.
    @State private var importedKeyData: Data?
    @State private var importedFileName: String?

    var body: some View {
        Form {
            Section {
                if let fileName = importedFileName, importedKeyData != nil {
                    CypherImportedFileRow(
                        fileName: fileName,
                        clearAccessibilityLabel: String(localized: "import.clearFile", defaultValue: "Clear file")
                    ) {
                        clearImportedKeyData()
                    }
                } else {
                    CypherMultilineTextInput(
                        text: $armoredText,
                        mode: .machineText
                    )
                        .frame(
                            minHeight: editorHeightRange.min,
                            idealHeight: editorHeightRange.ideal,
                            maxHeight: editorHeightRange.max
                        )
                }
            } header: {
                Text(String(localized: "import.paste.header", defaultValue: "Paste armored private key"))
            }

            Section {
                Button {
                    showFileImporter = true
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
                    text: $passphrase
                )
            } header: {
                Text(String(localized: "import.passphrase.header", defaultValue: "Key Passphrase"))
            }

            Section {
                Button {
                    importKey()
                } label: {
                    if isImporting {
                        ProgressView()
                            .cypherPrimaryActionLabelFrame()
                    } else {
                        Text(String(localized: "import.button", defaultValue: "Import Key"))
                            .cypherPrimaryActionLabelFrame()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled((armoredText.isEmpty && importedKeyData == nil) || passphrase.isEmpty || isImporting)
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
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: [
                UTType(filenameExtension: "asc") ?? .plainText,
                UTType(filenameExtension: "gpg") ?? .data,
                UTType(filenameExtension: "pgp") ?? .data,
                .data
            ],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                loadFileContents(from: url)
            }
        }
        .onDisappear {
            clearTransientInput()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            clearTransientInput()
        }
    }

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        return (120, 170, 250)
        #else
        return (120, 170, 240)
        #endif
    }

    private func loadFileContents(from url: URL) {
        do {
            let data = try SecurityScopedFileAccess.withAccess(
                to: url,
                failure: .invalidKeyData(
                    reason: String(localized: "import.file.readFailed", defaultValue: "Could not read key file")
                )
            ) {
                try Data(contentsOf: url)
            }

            if let text = String(data: data, encoding: .utf8) {
                clearImportedKeyData()
                armoredText = text
            } else {
                // Binary .gpg/.pgp key — store raw Data, bypass String conversion
                clearImportedKeyData()
                importedKeyData = data
                importedFileName = url.lastPathComponent
                armoredText = ""
            }
        } catch {
            self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            showError = true
        }
    }

    private func importKey() {
        isImporting = true
        let service = keyManagement
        let data = importedKeyData ?? Data(armoredText.utf8)
        let pass = passphrase
        Task {
            do {
                _ = try await service.importKey(
                    armoredData: data,
                    passphrase: pass
                )
                // Clear sensitive state before dismiss.
                // Note: Swift String cannot be reliably zeroized (SECURITY.md §7.1),
                // but we minimize lifetime by clearing references immediately.
                clearTransientInput()
                dismiss()
            } catch {
                self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
                showError = true
            }
            isImporting = false
        }
    }

    private func clearTransientInput() {
        armoredText = ""
        passphrase = ""
        showFileImporter = false
        clearImportedKeyData()
    }

    private func clearImportedKeyData() {
        importedKeyData?.resetBytes(in: 0..<(importedKeyData?.count ?? 0))
        importedKeyData = nil
        importedFileName = nil
    }
}
