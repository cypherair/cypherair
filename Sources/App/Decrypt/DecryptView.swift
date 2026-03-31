import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
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

    enum FileImportTarget {
        case textCiphertextImport
        case fileCiphertextImport
    }

    private struct PendingTextModeImport {
        let fileURL: URL
        let fileName: String
        let data: Data
        let text: String
    }

    @State private var decryptMode: DecryptMode = .text
    @State private var ciphertextInput = ""
    @State private var decryptedText: String?
    @State private var signatureVerification: SignatureVerification?
    @State private var operation = OperationController()

    // Phase 1 result — shown to user before authentication
    @State private var phase1Result: DecryptionService.Phase1Result?

    // File mode state
    @State private var showFileImporter = false
    @State private var fileImportTarget: FileImportTarget?
    @State private var selectedFileURL: URL?
    @State private var selectedFileName: String?
    @State private var decryptedFileURL: URL?
    @State private var filePhase1Result: DecryptionService.FilePhase1Result?
    @State private var importedCiphertext = ImportedTextInputState()
    @State private var pendingTextModeImport: PendingTextModeImport?
    @State private var showTextModeSuggestion = false
    @State private var exportController = FileExportController()

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

            // Phase 1: Parse recipients (no authentication)
            Section {
                Button {
                    if decryptMode == .text {
                        parseRecipientsText()
                    } else {
                        parseRecipientsFile()
                    }
                } label: {
                    if operation.isRunning && !hasPhase1Result {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "decrypt.parse.button", defaultValue: "Check Recipients"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(decryptButtonDisabled || hasPhase1Result)
            }

            // Phase 1 result: show matched key before authentication
            if let matchedKey = activeMatchedKey {
                Section {
                    LabeledContent(
                        String(localized: "decrypt.matchedKey.name", defaultValue: "Key"),
                        value: matchedKey.userId ?? matchedKey.shortKeyId
                    )
                    LabeledContent(
                        String(localized: "decrypt.matchedKey.profile", defaultValue: "Profile"),
                        value: matchedKey.profile.displayName
                    )
                    Text(matchedKey.formattedFingerprint)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .accessibilityLabel(
                            IdentityPresentation.fingerprintAccessibilityLabel(matchedKey.fingerprint)
                        )
                } header: {
                    Text(String(localized: "decrypt.matchedKey", defaultValue: "Matched Key"))
                }

                // Phase 2: Decrypt with authentication
                Section {
                    Button {
                        if decryptMode == .text, let phase1 = phase1Result {
                            decryptText(phase1: phase1)
                        } else if let filePhase1 = filePhase1Result {
                            decryptFile(phase1: filePhase1)
                        }
                    } label: {
                        if operation.isRunning {
                            HStack {
                                if decryptMode == .file, let progress = operation.progress {
                                    ProgressView(value: progress.fractionCompleted)
                                        .progressViewStyle(.linear)
                                    Text(String(localized: "fileDecrypt.decrypting", defaultValue: "Decrypting..."))
                                } else {
                                    ProgressView()
                                }
                                if decryptMode == .file {
                                    Spacer()
                                    Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                                        operation.cancel()
                                    }
                                }
                            }
                            .frame(maxWidth: .infinity)
                        } else {
                            Text(String(localized: "decrypt.button", defaultValue: "Decrypt with \(matchedKey.userId ?? matchedKey.shortKeyId)"))
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(operation.isRunning)
                }
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
            if decryptMode == .file, decryptedFileURL != nil {
                Section {
                    Button {
                        if let url = decryptedFileURL {
                            guard FileManager.default.fileExists(atPath: url.path) else {
                                operation.present(
                                    error: .corruptData(
                                        reason: String(
                                            localized: "fileDecrypt.readFailed",
                                            defaultValue: "Could not read decrypted file"
                                        )
                                    )
                                )
                                return
                            }
                            exportController.prepareFileExport(
                                fileURL: url,
                                suggestedFilename: decryptedFilename()
                            )
                        }
                    } label: {
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
                    .accessibilityElement(children: .combine)
                } header: {
                    Text(String(localized: "decrypt.signature", defaultValue: "Signature"))
                }
            }
        }
        #if canImport(UIKit)
        .scrollDismissesKeyboard(.interactively)
        #endif
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .navigationTitle(String(localized: "decrypt.title", defaultValue: "Decrypt"))
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: allowedImportContentTypes,
            allowsMultipleSelection: false
        ) { result in
            let target = fileImportTarget
            fileImportTarget = nil

            if case .success(let urls) = result,
               let url = urls.first,
               let target {
                handleImportedFile(url, target: target)
            }
        }
        .confirmationDialog(
            String(localized: "decrypt.openAsText.title", defaultValue: "Open as Text?"),
            isPresented: Binding(
                get: { showTextModeSuggestion },
                set: { newValue in
                    showTextModeSuggestion = newValue
                    if !newValue {
                        pendingTextModeImport = nil
                    }
                }
            ),
            titleVisibility: .visible
        ) {
            Button(String(localized: "decrypt.openAsText.action", defaultValue: "Open as Text")) {
                openPendingFileAsText()
            }
            Button(String(localized: "decrypt.openAsText.keepFile", defaultValue: "Keep as File")) {
                commitPendingFileSelection()
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {}
        } message: {
            Text(String(localized: "decrypt.openAsText.message", defaultValue: "This file looks like an armored text message. Open it in Text mode instead?"))
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: Binding(
                get: { operation.isShowingError },
                set: { if !$0 { operation.dismissError() } }
            ),
            presenting: operation.error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .fileExporter(
            isPresented: Binding(
                get: { exportController.isPresented },
                set: { if !$0 { exportController.finish() } }
            ),
            item: exportController.payload,
            contentTypes: [.data],
            defaultFilename: exportController.defaultFilename
        ) { result in
            exportController.finish()
            if case .failure(let exportError) = result {
                operation.present(error: mapDecryptError(exportError))
            }
        }
        .onDisappear {
            // PRD §4.4: Zeroize/delete decrypted data when leaving the view.
            // Note: Swift String cannot be reliably zeroized (SECURITY.md §7.1).
            // Assigning empty string before nil reduces the old string's reference lifetime.
            decryptedText = ""
            decryptedText = nil
            // Delete streaming decrypted file from disk
            if let url = decryptedFileURL {
                try? FileManager.default.removeItem(at: url)
                decryptedFileURL = nil
            }
            signatureVerification = nil
            phase1Result = nil
            filePhase1Result = nil
            importedCiphertext.clear()
            pendingTextModeImport = nil
            fileImportTarget = nil
        }
        .onChange(of: config.contentClearGeneration) {
            // PRD §4.4: Clear decrypted content when grace period expires.
            decryptedText = ""
            decryptedText = nil
            if let url = decryptedFileURL {
                try? FileManager.default.removeItem(at: url)
                decryptedFileURL = nil
            }
            signatureVerification = nil
            phase1Result = nil
            filePhase1Result = nil
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var textInputContent: some View {
        Section {
            TextEditor(text: ciphertextBinding)
                .font(.system(.body, design: .monospaced))
                #if canImport(UIKit)
                .frame(minHeight: 100)
                #else
                .frame(minHeight: 250)
                #endif

            Button {
                fileImportTarget = .textCiphertextImport
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "decrypt.importTextFile", defaultValue: "Import .asc File"),
                    systemImage: "doc.badge.plus"
                )
            }

            if let importedFileName = importedCiphertext.fileName, importedCiphertext.hasImportedFile {
                HStack {
                    Label(importedFileName, systemImage: "doc.fill")
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button {
                        clearImportedCiphertext()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                            .frame(minWidth: 44, minHeight: 44)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(String(localized: "decrypt.clearImportedFile", defaultValue: "Clear imported file"))
                }
            }
        } header: {
            Text(String(localized: "decrypt.input", defaultValue: "Encrypted Message"))
        }
    }

    @ViewBuilder
    private var fileInputContent: some View {
        Section {
            Button {
                fileImportTarget = .fileCiphertextImport
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

    private var activeMatchedKey: PGPKeyIdentity? {
        if decryptMode == .text {
            return phase1Result?.matchedKey
        } else {
            return filePhase1Result?.matchedKey
        }
    }

    private var hasPhase1Result: Bool {
        if decryptMode == .text {
            return phase1Result != nil
        } else {
            return filePhase1Result != nil
        }
    }

    private var decryptButtonDisabled: Bool {
        if operation.isRunning { return true }
        if hasPhase1Result { return true }
        switch decryptMode {
        case .text:
            return ciphertextInput.isEmpty && importedCiphertext.rawData == nil
        case .file: return selectedFileURL == nil
        }
    }

    private var allowedImportContentTypes: [UTType] {
        switch fileImportTarget {
        case .textCiphertextImport:
            return [
                UTType(filenameExtension: "asc") ?? .plainText,
                .plainText
            ]
        case .fileCiphertextImport, .none:
            return [
                UTType(filenameExtension: "gpg") ?? .data,
                UTType(filenameExtension: "pgp") ?? .data,
                UTType(filenameExtension: "asc") ?? .data,
                .data
            ]
        }
    }

    private var ciphertextBinding: Binding<String> {
        Binding(
            get: { ciphertextInput },
            set: { newValue in
                guard newValue != ciphertextInput else { return }
                ciphertextInput = newValue
                _ = importedCiphertext.invalidateIfEditedTextDiffers(newValue)
                invalidateTextInputState()
            }
        )
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

    // Phase 1: Parse recipients (no authentication)

    private func parseRecipientsText() {
        let service = decryptionService
        let inputData = importedCiphertext.rawData ?? Data(ciphertextInput.utf8)
        decryptedText = nil
        signatureVerification = nil
        operation.run(mapError: mapDecryptError) {
            let result = try await service.parseRecipients(ciphertext: inputData)
            phase1Result = result
        }
    }

    private func parseRecipientsFile() {
        guard let fileURL = selectedFileURL else { return }
        let service = decryptionService
        invalidateFileInputState(deleteTemporaryOutput: true)
        operation.run(mapError: mapDecryptError) {
            let result = try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: fileURL,
                        failure: .corruptData(
                            reason: String(
                                localized: "fileDecrypt.cannotAccess",
                                defaultValue: "Cannot access file"
                            )
                        )
                    )
                ]
            ) {
                try await service.parseRecipientsFromFile(fileURL: fileURL)
            }
            filePhase1Result = result
        }
    }

    // Phase 2: Decrypt with authentication

    private func decryptText(phase1: DecryptionService.Phase1Result) {
        let service = decryptionService
        operation.run(mapError: mapDecryptError) {
            let result = try await service.decrypt(phase1: phase1)

            if let text = String(data: result.plaintext, encoding: .utf8) {
                decryptedText = text
            }
            signatureVerification = result.signature

            var mutablePlaintext = result.plaintext
            mutablePlaintext.resetBytes(in: 0..<mutablePlaintext.count)
        }
    }

    private func decryptFile(phase1: DecryptionService.FilePhase1Result) {
        guard let fileURL = selectedFileURL else { return }
        let service = decryptionService
        operation.runFileOperation(mapError: mapDecryptError) { progress in
            let result = try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: fileURL,
                        failure: .corruptData(
                            reason: String(
                                localized: "fileDecrypt.cannotAccess",
                                defaultValue: "Cannot access file"
                            )
                        )
                    )
                ]
            ) {
                try await service.decryptFileStreaming(
                    phase1: phase1,
                    progress: progress
                )
            }
            try Task.checkCancellation()
            decryptedFileURL = result.outputURL
            signatureVerification = result.signature
        }
    }

    private func mapDecryptError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .corruptData(reason: $0) }
    }

    private func handleImportedFile(_ url: URL, target: FileImportTarget) {
        switch target {
        case .textCiphertextImport:
            importCiphertextTextFile(from: url)
        case .fileCiphertextImport:
            inspectCiphertextFileSelection(url)
        }
    }

    private func importCiphertextTextFile(from url: URL) {
        do {
            let data = try withSecurityScopedAccess(
                to: url,
                failure: .corruptData(
                    reason: String(localized: "decrypt.importTextReadFailed",
                                   defaultValue: "Could not read text message file")
                )
            ) {
                try Data(contentsOf: url)
            }

            guard let text = String(data: data, encoding: .utf8) else {
                throw CypherAirError.corruptData(
                    reason: String(localized: "decrypt.importTextReadFailed",
                                   defaultValue: "Could not read text message file")
                )
            }

            importedCiphertext.setImportedFile(
                data: data,
                fileName: url.lastPathComponent,
                text: text
            )
            ciphertextInput = text
            invalidateTextInputState()
        } catch let error as CypherAirError {
            operation.present(error: error)
        } catch {
            operation.present(error: mapDecryptError(error))
        }
    }

    private func clearImportedCiphertext() {
        importedCiphertext.clear()
        ciphertextInput = ""
        invalidateTextInputState()
    }

    private func inspectCiphertextFileSelection(_ url: URL) {
        let fileName = url.lastPathComponent

        do {
            let inspection: PendingTextModeImport? = try withSecurityScopedAccess(
                to: url,
                failure: .corruptData(
                    reason: String(localized: "fileDecrypt.cannotAccess",
                                   defaultValue: "Cannot access file")
                )
            ) {
                let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
                let fileSize = attributes[.size] as? NSNumber
                let fileSizeValue = fileSize?.intValue ?? 0

                guard fileSizeValue <= ArmoredTextMessageClassifier.maxInspectableFileSize else {
                    return nil
                }

                let data = try Data(contentsOf: url)
                guard ArmoredTextMessageClassifier.classify(fileSize: fileSizeValue, data: data) == .encryptedTextMessage,
                      let text = String(data: data, encoding: .utf8) else {
                    return nil
                }

                return PendingTextModeImport(
                    fileURL: url,
                    fileName: fileName,
                    data: data,
                    text: text
                )
            }

            if let inspection {
                pendingTextModeImport = inspection
                showTextModeSuggestion = true
            } else {
                commitFileSelection(url: url, fileName: fileName)
            }
        } catch let error as CypherAirError {
            operation.present(error: error)
        } catch {
            operation.present(error: mapDecryptError(error))
        }
    }

    private func openPendingFileAsText() {
        guard let pendingTextModeImport else { return }

        decryptMode = .text
        importedCiphertext.setImportedFile(
            data: pendingTextModeImport.data,
            fileName: pendingTextModeImport.fileName,
            text: pendingTextModeImport.text
        )
        ciphertextInput = pendingTextModeImport.text
        invalidateTextInputState()
        self.pendingTextModeImport = nil
        showTextModeSuggestion = false
    }

    private func commitPendingFileSelection() {
        guard let pendingTextModeImport else { return }
        commitFileSelection(url: pendingTextModeImport.fileURL, fileName: pendingTextModeImport.fileName)
        self.pendingTextModeImport = nil
        showTextModeSuggestion = false
    }

    private func commitFileSelection(url: URL, fileName: String) {
        selectedFileURL = url
        selectedFileName = fileName
        invalidateFileInputState(deleteTemporaryOutput: true)
    }

    private func invalidateTextInputState() {
        decryptedText = ""
        decryptedText = nil
        signatureVerification = nil
        phase1Result = nil
    }

    private func invalidateFileInputState(deleteTemporaryOutput: Bool) {
        if deleteTemporaryOutput, let url = decryptedFileURL {
            try? FileManager.default.removeItem(at: url)
            decryptedFileURL = nil
        } else if deleteTemporaryOutput {
            decryptedFileURL = nil
        }
        signatureVerification = nil
        filePhase1Result = nil
    }

    private func withSecurityScopedAccess<T>(
        to url: URL,
        failure: CypherAirError,
        operation: () throws -> T
    ) throws -> T {
        guard url.startAccessingSecurityScopedResource() else {
            throw failure
        }

        defer { url.stopAccessingSecurityScopedResource() }
        return try operation()
    }
}
