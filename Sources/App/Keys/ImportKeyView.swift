import SwiftUI
import UniformTypeIdentifiers

/// Import a private key from file, paste, or QR photo.
struct ImportKeyView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config
    @Environment(\.dismiss) private var dismiss

    @State private var armoredText = ""
    @State private var passphrase = ""
    @State private var isImporting = false
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showFileImporter = false

    var body: some View {
        Form {
            Section {
                TextEditor(text: $armoredText)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 120)
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
                SecureField(
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
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "import.button", defaultValue: "Import Key"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(armoredText.isEmpty || passphrase.isEmpty || isImporting)
            }
        }
        .scrollDismissesKeyboard(.interactively)
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
    }

    private func loadFileContents(from url: URL) {
        guard url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            let data = try Data(contentsOf: url)
            if let text = String(data: data, encoding: .utf8) {
                armoredText = text
            } else {
                // Binary key data — convert to string representation for the text field
                armoredText = String(data: data, encoding: .ascii) ?? ""
            }
        } catch {
            self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            showError = true
        }
    }

    private func importKey() {
        isImporting = true
        Task {
            do {
                let data = Data(armoredText.utf8)
                _ = try keyManagement.importKey(
                    armoredData: data,
                    passphrase: passphrase,
                    authMode: config.authMode
                )
                // Clear sensitive state before dismiss.
                // Note: Swift String cannot be reliably zeroized (SECURITY.md §7.1),
                // but we minimize lifetime by clearing references immediately.
                armoredText = ""
                passphrase = ""
                dismiss()
            } catch {
                self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
                showError = true
            }
            isImporting = false
        }
    }
}
