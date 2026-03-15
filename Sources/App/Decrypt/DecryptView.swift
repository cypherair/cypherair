import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// Unified two-phase decryption view for text and files.
struct DecryptView: View {
    @Environment(DecryptionService.self) private var decryptionService
    @Environment(AppConfiguration.self) private var config

    enum DecryptMode: String, CaseIterable {
        case text, file
        var label: String {
            switch self {
            case .text: String(localized: "decrypt.mode.text", defaultValue: "Text")
            case .file: String(localized: "decrypt.mode.file", defaultValue: "File")
            }
        }
    }

    @State private var decryptMode: DecryptMode = .text
    @State private var ciphertextInput = ""
    @State private var isDecrypting = false
    @State private var decryptedText: String?
    @State private var signatureVerification: SignatureVerification?
    @State private var error: CypherAirError?
    @State private var showError = false

    // File mode state
    @State private var showFileImporter = false
    @State private var selectedFileURL: URL?
    @State private var selectedFileName: String?
    @State private var decryptedFileData: Data?
    @State private var currentTask: Task<Void, Never>?

    var body: some View {
        Form {
            Section {
                Picker(String(localized: "decrypt.mode", defaultValue: "Mode"), selection: $decryptMode) {
                    ForEach(DecryptMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
            }

            if decryptMode == .text {
                textInputContent
            } else {
                fileInputContent
            }

            Section {
                Button {
                    if decryptMode == .text {
                        decryptText()
                    } else {
                        decryptFile()
                    }
                } label: {
                    if isDecrypting {
                        HStack {
                            ProgressView(decryptMode == .file
                                ? String(localized: "fileDecrypt.decrypting", defaultValue: "Decrypting...")
                                : "")
                            if decryptMode == .file {
                                Spacer()
                                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                                    currentTask?.cancel()
                                    currentTask = nil
                                    isDecrypting = false
                                }
                            }
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "decrypt.button", defaultValue: "Decrypt"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(decryptButtonDisabled)
            }

            // Text mode result
            if decryptMode == .text, let decryptedText {
                Section {
                    Text(decryptedText)
                        .textSelection(.enabled)
                } header: {
                    Text(String(localized: "decrypt.result", defaultValue: "Decrypted Message"))
                }
            }

            // File mode result
            if decryptMode == .file, let data = decryptedFileData,
               let fileURL = data.writeToShareTempFile(named: decryptedFilename()) {
                Section {
                    ShareLink(item: fileURL) {
                        Label(
                            String(localized: "fileDecrypt.save", defaultValue: "Save Decrypted File"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                }
            }

            // Signature verification (shared by both modes)
            if let sigVerification = signatureVerification {
                Section {
                    HStack {
                        Image(systemName: sigVerification.symbolName)
                            .foregroundStyle(sigVerification.statusColor)
                        Text(sigVerification.statusDescription)
                            .font(.subheadline)
                    }
                } header: {
                    Text(String(localized: "decrypt.signature", defaultValue: "Signature"))
                }
            }
        }
        .navigationTitle(String(localized: "decrypt.title", defaultValue: "Decrypt"))
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: [
                UTType(filenameExtension: "gpg") ?? .data,
                UTType(filenameExtension: "pgp") ?? .data,
                UTType(filenameExtension: "asc") ?? .data,
                .data
            ],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                selectedFileURL = url
                selectedFileName = url.lastPathComponent
            }
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
            decryptedText = nil
            decryptedFileData?.resetBytes(in: 0..<(decryptedFileData?.count ?? 0))
            decryptedFileData = nil
            signatureVerification = nil
        }
        .onChange(of: config.contentClearGeneration) {
            // PRD §4.4: Clear decrypted content when grace period expires.
            decryptedText = nil
            decryptedFileData?.resetBytes(in: 0..<(decryptedFileData?.count ?? 0))
            decryptedFileData = nil
            signatureVerification = nil
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var textInputContent: some View {
        Section {
            TextEditor(text: $ciphertextInput)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 100)
        } header: {
            Text(String(localized: "decrypt.input", defaultValue: "Encrypted Message"))
        }
    }

    @ViewBuilder
    private var fileInputContent: some View {
        Section {
            Button {
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "fileDecrypt.selectFile", defaultValue: "Select Encrypted File"),
                    systemImage: "doc.badge.arrow.up"
                )
            }

            if let selectedFileName {
                LabeledContent(
                    String(localized: "fileDecrypt.selectedFile", defaultValue: "Selected"),
                    value: selectedFileName
                )
            }
        } header: {
            Text(String(localized: "fileDecrypt.file", defaultValue: "Encrypted File"))
        } footer: {
            Text(String(localized: "fileDecrypt.types", defaultValue: "Supports .gpg, .pgp, and .asc files"))
        }
    }

    // MARK: - State

    private var decryptButtonDisabled: Bool {
        if isDecrypting { return true }
        switch decryptMode {
        case .text: return ciphertextInput.isEmpty
        case .file: return selectedFileURL == nil
        }
    }

    private func decryptedFilename() -> String {
        guard let name = selectedFileName else { return "decrypted" }
        for ext in [".gpg", ".pgp", ".asc"] {
            if name.hasSuffix(ext) {
                return String(name.dropLast(ext.count))
            }
        }
        return name
    }

    // MARK: - Actions

    private func decryptText() {
        isDecrypting = true
        let service = decryptionService
        let inputData = Data(ciphertextInput.utf8)
        Task {
            do {
                let result = try await service.decryptMessage(ciphertext: inputData)

                if let text = String(data: result.plaintext, encoding: .utf8) {
                    decryptedText = text
                }
                signatureVerification = result.signature

                // Zeroize plaintext data
                var mutablePlaintext = result.plaintext
                mutablePlaintext.resetBytes(in: 0..<mutablePlaintext.count)
            } catch {
                self.error = CypherAirError.from(error) { .corruptData(reason: $0) }
                showError = true
            }
            isDecrypting = false
        }
    }

    private func decryptFile() {
        guard let fileURL = selectedFileURL else { return }
        let service = decryptionService

        isDecrypting = true
        currentTask = Task {
            var bgTaskID = UIBackgroundTaskIdentifier.invalid
            bgTaskID = UIApplication.shared.beginBackgroundTask {
                UIApplication.shared.endBackgroundTask(bgTaskID)
                bgTaskID = .invalid
            }
            defer {
                if bgTaskID != .invalid {
                    UIApplication.shared.endBackgroundTask(bgTaskID)
                }
                isDecrypting = false
                currentTask = nil
            }
            do {
                guard fileURL.startAccessingSecurityScopedResource() else {
                    error = .corruptData(reason: "Cannot access file")
                    showError = true
                    return
                }
                defer { fileURL.stopAccessingSecurityScopedResource() }

                let ciphertext = try Data(contentsOf: fileURL)
                try Task.checkCancellation()
                let result = try await service.decryptMessage(ciphertext: ciphertext)
                try Task.checkCancellation()

                decryptedFileData = result.plaintext
                signatureVerification = result.signature
            } catch is CancellationError {
                // User cancelled — no error to show
            } catch {
                self.error = CypherAirError.from(error) { .corruptData(reason: $0) }
                showError = true
            }
        }
    }
}
