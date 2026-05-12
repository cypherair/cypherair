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
    @State private var importTask: Task<Void, Never>?
    @State private var importToken: UInt64 = 0
    @State private var fileImportRequestGate = FileImportRequestGate()

    var body: some View {
        let fileImportRequestToken = fileImportRequestGate.currentToken

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
                    requestFileImport()
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
            handleFileImporterResult(result, token: fileImportRequestToken)
        }
        .onDisappear {
            cancelImportAndClearTransientInput()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            cancelImportAndClearTransientInput()
        }
    }

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        return (120, 170, 250)
        #else
        return (120, 170, 240)
        #endif
    }

    private func requestFileImport() {
        fileImportRequestGate.begin()
        showFileImporter = true
    }

    private func handleFileImporterResult(
        _ result: Result<[URL], Error>,
        token: FileImportRequestGate.Token?
    ) {
        guard fileImportRequestGate.consumeIfCurrent(token) else {
            return
        }

        if case .success(let urls) = result, let url = urls.first {
            loadFileContents(from: url)
        }
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
        importTask?.cancel()
        importToken &+= 1
        let token = importToken
        isImporting = true
        let service = keyManagement
        let importedKeyDataSnapshot = importedKeyData
        let armoredTextSnapshot = armoredText
        let pass = passphrase

        importTask = Task { @MainActor in
            defer {
                if token == importToken {
                    isImporting = false
                    importTask = nil
                }
            }

            do {
                var data = importedKeyDataSnapshot ?? Data(armoredTextSnapshot.utf8)
                defer {
                    data.resetBytes(in: 0..<data.count)
                }
                _ = try await service.importKey(
                    armoredData: data,
                    passphrase: pass
                )
                try Task.checkCancellation()
                guard token == importToken else {
                    return
                }
                // Clear sensitive state before dismiss.
                // Note: Swift String cannot be reliably zeroized (SECURITY.md §7.1),
                // but we minimize lifetime by clearing references immediately.
                clearTransientInput()
                dismiss()
            } catch {
                guard !Self.shouldIgnore(error), token == importToken else {
                    return
                }
                self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
                showError = true
            }
        }
    }

    private func cancelImportAndClearTransientInput() {
        importTask?.cancel()
        importToken &+= 1
        importTask = nil
        isImporting = false
        clearTransientInput()
    }

    private func clearTransientInput() {
        armoredText = ""
        passphrase = ""
        showFileImporter = false
        fileImportRequestGate.invalidate()
        clearImportedKeyData()
    }

    private func clearImportedKeyData() {
        importedKeyData?.resetBytes(in: 0..<(importedKeyData?.count ?? 0))
        importedKeyData = nil
        importedFileName = nil
    }

    private static func shouldIgnore(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let cypherAirError = error as? CypherAirError,
           case .operationCancelled = cypherAirError {
            return true
        }
        if let pgpError = error as? PgpError,
           case .OperationCancelled = pgpError {
            return true
        }
        return false
    }
}
