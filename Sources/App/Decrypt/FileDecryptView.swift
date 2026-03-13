import SwiftUI
import UniformTypeIdentifiers

/// File decryption view with document picker, two-phase decryption, and preview/save.
/// Decrypted files are stored in tmp/decrypted/ and deleted on view exit + app launch.
struct FileDecryptView: View {
    @Environment(DecryptionService.self) private var decryptionService

    @State private var showDocumentPicker = false
    @State private var isDecrypting = false
    @State private var decryptedData: Data?
    @State private var signatureVerification: SignatureVerification?
    @State private var originalFilename: String?
    @State private var error: CypherAirError?
    @State private var showError = false

    var body: some View {
        Form {
            Section {
                Button {
                    showDocumentPicker = true
                } label: {
                    Label(
                        String(localized: "fileDecrypt.selectFile", defaultValue: "Select Encrypted File"),
                        systemImage: "doc.badge.arrow.up"
                    )
                }
            } header: {
                Text(String(localized: "fileDecrypt.file", defaultValue: "Encrypted File"))
            } footer: {
                Text(String(localized: "fileDecrypt.types", defaultValue: "Supports .gpg, .pgp, and .asc files"))
            }

            if isDecrypting {
                Section {
                    ProgressView(String(localized: "fileDecrypt.decrypting", defaultValue: "Decrypting..."))
                }
            }

            if let signatureVerification {
                Section {
                    HStack {
                        Image(systemName: signatureVerification.symbolName)
                            .foregroundStyle(Color(signatureVerification.statusColor))
                        Text(signatureVerification.statusDescription)
                            .font(.subheadline)
                    }
                } header: {
                    Text(String(localized: "decrypt.signature", defaultValue: "Signature"))
                }
            }

            if let data = decryptedData {
                Section {
                    let filename = decryptedFilename()
                    ShareLink(
                        item: data,
                        preview: SharePreview(
                            filename,
                            image: Image(systemName: "doc")
                        )
                    ) {
                        Label(
                            String(localized: "fileDecrypt.save", defaultValue: "Save Decrypted File"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                }
            }
        }
        .navigationTitle(String(localized: "fileDecrypt.title", defaultValue: "Decrypt File"))
        .fileImporter(
            isPresented: $showDocumentPicker,
            allowedContentTypes: [
                UTType(filenameExtension: "gpg") ?? .data,
                UTType(filenameExtension: "pgp") ?? .data,
                UTType(filenameExtension: "asc") ?? .data,
                .data
            ],
            allowsMultipleSelection: false
        ) { result in
            handleFileSelection(result)
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .onDisappear {
            // PRD §4.4: Zeroize decrypted data when leaving the view.
            // Operate directly on the original buffer, not a value-type copy.
            decryptedData?.resetBytes(in: 0..<(decryptedData?.count ?? 0))
            decryptedData = nil
        }
    }

    private func handleFileSelection(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else { return }

        originalFilename = url.lastPathComponent
        let service = decryptionService

        isDecrypting = true
        Task {
            defer { isDecrypting = false }
            do {
                guard url.startAccessingSecurityScopedResource() else {
                    error = .corruptData(reason: "Cannot access file")
                    showError = true
                    return
                }
                defer { url.stopAccessingSecurityScopedResource() }

                let ciphertext = try Data(contentsOf: url)
                let result = try await service.decryptMessage(ciphertext: ciphertext)

                decryptedData = result.plaintext
                signatureVerification = result.signature
            } catch {
                self.error = CypherAirError.from(error) { .corruptData(reason: $0) }
                showError = true
            }
        }
    }

    private func decryptedFilename() -> String {
        guard let name = originalFilename else { return "decrypted" }
        // Strip common PGP extensions
        for ext in [".gpg", ".pgp", ".asc"] {
            if name.hasSuffix(ext) {
                return String(name.dropLast(ext.count))
            }
        }
        return name
    }
}
