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
    /// Raw key data for binary .gpg/.pgp files that cannot be represented as a String.
    @State private var importedKeyData: Data?
    @State private var importedFileName: String?

    var body: some View {
        Form {
            Section {
                if let fileName = importedFileName, importedKeyData != nil {
                    HStack {
                        Label(fileName, systemImage: "doc.fill")
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Button {
                            importedKeyData = nil
                            importedFileName = nil
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                                .frame(minWidth: 44, minHeight: 44)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(String(localized: "import.clearFile", defaultValue: "Clear file"))
                    }
                } else {
                    TextEditor(text: $armoredText)
                        .font(.system(.body, design: .monospaced))
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
                .disabled((armoredText.isEmpty && importedKeyData == nil) || passphrase.isEmpty || isImporting)
            }
        }
        #if canImport(UIKit)
        .scrollDismissesKeyboard(.interactively)
        #endif
        #if os(macOS)
        .formStyle(.grouped)
        #endif
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

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        return (120, 170, 250)
        #else
        return (140, 210, 300)
        #endif
    }

    private func loadFileContents(from url: URL) {
        guard url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            let data = try Data(contentsOf: url)
            if let text = String(data: data, encoding: .utf8) {
                armoredText = text
                importedKeyData = nil
                importedFileName = nil
            } else {
                // Binary .gpg/.pgp key — store raw Data, bypass String conversion
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
        let authMode = config.authMode
        Task {
            do {
                _ = try await service.importKey(
                    armoredData: data,
                    passphrase: pass,
                    authMode: authMode
                )
                // Clear sensitive state before dismiss.
                // Note: Swift String cannot be reliably zeroized (SECURITY.md §7.1),
                // but we minimize lifetime by clearing references immediately.
                armoredText = ""
                passphrase = ""
                importedKeyData?.resetBytes(in: 0..<(importedKeyData?.count ?? 0))
                importedKeyData = nil
                importedFileName = nil
                dismiss()
            } catch {
                self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
                showError = true
            }
            isImporting = false
        }
    }
}
