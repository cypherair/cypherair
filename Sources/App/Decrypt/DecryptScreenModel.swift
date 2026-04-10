import Foundation

@MainActor
@Observable
final class DecryptScreenModel {
    typealias ParseTextRecipientsAction = @MainActor (Data) async throws -> DecryptionService.Phase1Result
    typealias ParseFileRecipientsAction = @MainActor (URL) async throws -> DecryptionService.FilePhase1Result
    typealias TextCiphertextFileImportAction = @MainActor (URL) throws -> (data: Data, text: String)
    typealias CiphertextFileInspectionAction = @MainActor (URL) throws -> (data: Data, text: String)?
    typealias TextDecryptionAction = @MainActor (
        DecryptionService.Phase1Result
    ) async throws -> (plaintext: Data, signature: SignatureVerification)
    typealias FileDecryptionAction = @MainActor (
        URL,
        DecryptionService.FilePhase1Result,
        FileProgressReporter
    ) async throws -> (outputURL: URL, signature: SignatureVerification)

    let configuration: DecryptView.Configuration
    let operation: OperationController
    let exportController: FileExportController

    private let parseTextRecipientsAction: ParseTextRecipientsAction
    private let parseFileRecipientsAction: ParseFileRecipientsAction
    private let textCiphertextFileImportAction: TextCiphertextFileImportAction
    private let ciphertextFileInspectionAction: CiphertextFileInspectionAction
    private let textDecryptionAction: TextDecryptionAction
    private let fileDecryptionAction: FileDecryptionAction

    private struct PendingTextModeImport {
        let fileURL: URL
        let fileName: String
        let data: Data
        let text: String
    }

    var decryptMode: DecryptView.DecryptMode = .text
    var ciphertextInput = ""
    var decryptedText: String?
    var signatureVerification: SignatureVerification?
    var phase1Result: DecryptionService.Phase1Result?
    var showFileImporter = false
    var fileImportTarget: DecryptView.FileImportTarget?
    var selectedFileURL: URL?
    var selectedFileName: String?
    var decryptedFileURL: URL?
    var filePhase1Result: DecryptionService.FilePhase1Result?
    var importedCiphertext = ImportedTextInputState()
    private var pendingTextModeImport: PendingTextModeImport?
    var showTextModeSuggestion = false
    var textInputSectionEpoch = 0

    init(
        decryptionService: DecryptionService,
        configuration: DecryptView.Configuration,
        operation: OperationController = OperationController(),
        exportController: FileExportController = FileExportController(),
        parseTextRecipientsAction: ParseTextRecipientsAction? = nil,
        parseFileRecipientsAction: ParseFileRecipientsAction? = nil,
        textCiphertextFileImportAction: TextCiphertextFileImportAction? = nil,
        ciphertextFileInspectionAction: CiphertextFileInspectionAction? = nil,
        textDecryptionAction: TextDecryptionAction? = nil,
        fileDecryptionAction: FileDecryptionAction? = nil
    ) {
        self.configuration = configuration
        self.operation = operation
        self.exportController = exportController
        self.parseTextRecipientsAction = parseTextRecipientsAction ?? { ciphertext in
            try await decryptionService.parseRecipients(ciphertext: ciphertext)
        }
        self.parseFileRecipientsAction = parseFileRecipientsAction ?? { fileURL in
            try await SecurityScopedFileAccess.withAccess(
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
                try await decryptionService.parseRecipientsFromFile(fileURL: fileURL)
            }
        }
        self.textCiphertextFileImportAction = textCiphertextFileImportAction ?? { url in
            let data = try SecurityScopedFileAccess.withAccess(
                to: url,
                failure: .corruptData(
                    reason: String(
                        localized: "decrypt.importTextReadFailed",
                        defaultValue: "Could not read text message file"
                    )
                )
            ) {
                try Data(contentsOf: url)
            }

            guard let text = String(data: data, encoding: .utf8) else {
                throw CypherAirError.corruptData(
                    reason: String(
                        localized: "decrypt.importTextReadFailed",
                        defaultValue: "Could not read text message file"
                    )
                )
            }

            return (data, text)
        }
        self.ciphertextFileInspectionAction = ciphertextFileInspectionAction ?? { url in
            try SecurityScopedFileAccess.withAccess(
                to: url,
                failure: .corruptData(
                    reason: String(
                        localized: "fileDecrypt.cannotAccess",
                        defaultValue: "Cannot access file"
                    )
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

                return (data, text)
            }
        }
        self.textDecryptionAction = textDecryptionAction ?? { phase1 in
            try await decryptionService.decrypt(phase1: phase1)
        }
        self.fileDecryptionAction = fileDecryptionAction ?? { fileURL, phase1, progress in
            try await SecurityScopedFileAccess.withAccess(
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
                try await decryptionService.decryptFileStreaming(
                    phase1: phase1,
                    progress: progress
                )
            }
        }
    }

    var activeMatchedKey: PGPKeyIdentity? {
        switch decryptMode {
        case .text:
            phase1Result?.matchedKey
        case .file:
            filePhase1Result?.matchedKey
        }
    }

    var hasPhase1Result: Bool {
        switch decryptMode {
        case .text:
            phase1Result != nil
        case .file:
            filePhase1Result != nil
        }
    }

    var decryptButtonDisabled: Bool {
        if operation.isRunning || hasPhase1Result {
            return true
        }

        switch decryptMode {
        case .text:
            return ciphertextInput.isEmpty && importedCiphertext.rawData == nil
        case .file:
            return selectedFileURL == nil
        }
    }

    var showsFileDecryptCancelAction: Bool {
        decryptMode == .file && operation.isRunning && operation.progress != nil
    }

    func handleAppear() {
        if ciphertextInput.isEmpty,
           let prefilledCiphertext = configuration.prefilledCiphertext {
            ciphertextInput = prefilledCiphertext
        }
        if let initialPhase1Result = configuration.initialPhase1Result {
            phase1Result = initialPhase1Result
        }
    }

    func handleDisappear() {
        clearDisplayedText()
        deleteTemporaryDecryptedFile()
        signatureVerification = nil
        phase1Result = nil
        filePhase1Result = nil
        importedCiphertext.clear()
        pendingTextModeImport = nil
        fileImportTarget = nil
    }

    func handleContentClearGenerationChange() {
        clearDisplayedText()
        deleteTemporaryDecryptedFile()
        signatureVerification = nil
        phase1Result = nil
        filePhase1Result = nil
    }

    func setCiphertextInput(_ newValue: String) {
        guard newValue != ciphertextInput else { return }
        ciphertextInput = newValue
        _ = importedCiphertext.invalidateIfEditedTextDiffers(newValue)
        invalidateTextInputState()
    }

    func requestTextCiphertextImport() {
        guard configuration.allowsTextFileImport else { return }
        fileImportTarget = .textCiphertextImport
        showFileImporter = true
    }

    func requestFileCiphertextImport() {
        guard configuration.allowsFileInput else { return }
        fileImportTarget = .fileCiphertextImport
        showFileImporter = true
    }

    func finishFileImportRequest() {
        fileImportTarget = nil
    }

    func handleImportedFile(_ url: URL) {
        switch fileImportTarget {
        case .textCiphertextImport:
            importCiphertextTextFile(from: url)
        case .fileCiphertextImport:
            inspectCiphertextFileSelection(url)
        case .none:
            break
        }
    }

    func parseRecipientsText() {
        let inputData = importedCiphertext.rawData ?? Data(ciphertextInput.utf8)
        decryptedText = nil
        signatureVerification = nil

        operation.run(mapError: mapDecryptError) { [self] in
            let result = try await self.parseTextRecipientsAction(inputData)
            self.phase1Result = result
            self.textInputSectionEpoch &+= 1
            self.configuration.onParsed?(result)
        }
    }

    func parseRecipientsFile() {
        guard let fileURL = selectedFileURL else { return }

        invalidateFileInputState(deleteTemporaryOutput: true)

        operation.run(mapError: mapDecryptError) { [self] in
            let result = try await self.parseFileRecipientsAction(fileURL)
            self.filePhase1Result = result
        }
    }

    func decryptText() {
        guard let phase1Result else { return }

        operation.run(mapError: mapDecryptError) { [self] in
            let result = try await self.textDecryptionAction(phase1Result)

            if let text = String(data: result.plaintext, encoding: .utf8) {
                self.decryptedText = text
            }
            self.signatureVerification = result.signature
            self.configuration.onDecrypted?(result.plaintext, result.signature)

            var mutablePlaintext = result.plaintext
            mutablePlaintext.resetBytes(in: 0..<mutablePlaintext.count)
        }
    }

    func decryptFile() {
        guard let fileURL = selectedFileURL,
              let filePhase1Result else {
            return
        }

        operation.runFileOperation(mapError: mapDecryptError) { [self] progress in
            let result = try await self.fileDecryptionAction(
                fileURL,
                filePhase1Result,
                progress
            )
            try Task.checkCancellation()
            self.decryptedFileURL = result.outputURL
            self.signatureVerification = result.signature
        }
    }

    func exportDecryptedFile() {
        guard configuration.allowsFileResultExport,
              let decryptedFileURL else {
            return
        }

        guard FileManager.default.fileExists(atPath: decryptedFileURL.path) else {
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

        if configuration.outputInterceptionPolicy.interceptFileExport?(
            decryptedFileURL,
            decryptedFilename(),
            .generic
        ) != true {
            exportController.prepareFileExport(
                fileURL: decryptedFileURL,
                suggestedFilename: decryptedFilename()
            )
        }
    }

    func dismissTextModeSuggestion() {
        pendingTextModeImport = nil
        showTextModeSuggestion = false
    }

    func openPendingFileAsText() {
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

    func keepPendingFileAsFile() {
        guard let pendingTextModeImport else { return }

        commitFileSelection(
            url: pendingTextModeImport.fileURL,
            fileName: pendingTextModeImport.fileName
        )
        self.pendingTextModeImport = nil
        showTextModeSuggestion = false
    }

    func clearImportedCiphertext() {
        importedCiphertext.clear()
        ciphertextInput = ""
        invalidateTextInputState()
    }

    func dismissError() {
        operation.dismissError()
    }

    func finishExport() {
        exportController.finish()
    }

    func handleExportError(_ error: Error) {
        operation.present(error: mapDecryptError(error))
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

    private func importCiphertextTextFile(from url: URL) {
        do {
            let imported = try textCiphertextFileImportAction(url)

            importedCiphertext.setImportedFile(
                data: imported.data,
                fileName: url.lastPathComponent,
                text: imported.text
            )
            ciphertextInput = imported.text
            invalidateTextInputState()
        } catch let error as CypherAirError {
            operation.present(error: error)
        } catch {
            operation.present(error: mapDecryptError(error))
        }
    }

    private func inspectCiphertextFileSelection(_ url: URL) {
        let fileName = url.lastPathComponent

        do {
            let inspection = try ciphertextFileInspectionAction(url).map { inspection in
                PendingTextModeImport(
                    fileURL: url,
                    fileName: fileName,
                    data: inspection.data,
                    text: inspection.text
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

    private func commitFileSelection(url: URL, fileName: String) {
        selectedFileURL = url
        selectedFileName = fileName
        invalidateFileInputState(deleteTemporaryOutput: true)
    }

    private func invalidateTextInputState() {
        clearDisplayedText()
        signatureVerification = nil
        phase1Result = nil
        textInputSectionEpoch &+= 1
    }

    private func invalidateFileInputState(deleteTemporaryOutput: Bool) {
        if deleteTemporaryOutput {
            deleteTemporaryDecryptedFile()
        }
        signatureVerification = nil
        filePhase1Result = nil
    }

    private func clearDisplayedText() {
        decryptedText = ""
        decryptedText = nil
    }

    private func deleteTemporaryDecryptedFile() {
        if let decryptedFileURL {
            try? FileManager.default.removeItem(at: decryptedFileURL)
            self.decryptedFileURL = nil
        } else {
            decryptedFileURL = nil
        }
    }

    private func mapDecryptError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .corruptData(reason: $0) }
    }
}
