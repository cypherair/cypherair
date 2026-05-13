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
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification)
    typealias FileDecryptionAction = @MainActor (
        URL,
        DecryptionService.FilePhase1Result,
        FileProgressReporter
    ) async throws -> (artifact: AppTemporaryArtifact, verification: DetailedSignatureVerification)

    private(set) var configuration: DecryptView.Configuration
    let operation: OperationController
    let exportController: FileExportController

    private let parseTextRecipientsAction: ParseTextRecipientsAction
    private let parseFileRecipientsAction: ParseFileRecipientsAction
    private let textCiphertextFileImportAction: TextCiphertextFileImportAction
    private let ciphertextFileInspectionAction: CiphertextFileInspectionAction
    private let textDecryptionAction: TextDecryptionAction
    private let fileDecryptionAction: FileDecryptionAction
    private let authLifecycleTraceStore: AuthLifecycleTraceStore?
    @ObservationIgnored private var decryptedFileArtifact: AppTemporaryArtifact?
    private var fileImportRequestGate = FileImportRequestGate()

    private struct PendingTextModeImport {
        let fileURL: URL
        let fileName: String
        let data: Data
        let text: String
    }

    var decryptMode: DecryptView.DecryptMode = .text
    var ciphertextInput = ""
    var decryptedText: String?
    var detailedSignatureVerification: DetailedSignatureVerification?
    var phase1Result: DecryptionService.Phase1Result?
    var showFileImporter = false
    var fileImportTarget: DecryptView.FileImportTarget?
    var selectedFileURL: URL?
    var selectedFileName: String?
    var decryptedFileURL: URL? {
        didSet {
            if decryptedFileURL != decryptedFileArtifact?.fileURL {
                decryptedFileArtifact = decryptedFileURL.map { AppTemporaryArtifact(fileURL: $0) }
            }
        }
    }
    var filePhase1Result: DecryptionService.FilePhase1Result?
    var importedCiphertext = ImportedTextInputState()
    private var pendingTextModeImport: PendingTextModeImport?
    var showTextModeSuggestion = false
    var textInputSectionEpoch = 0

    init(
        decryptionService: DecryptionService,
        authLifecycleTraceStore: AuthLifecycleTraceStore? = nil,
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
        self.authLifecycleTraceStore = authLifecycleTraceStore
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
            try await decryptionService.decryptDetailed(phase1: phase1)
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
                try await decryptionService.decryptFileStreamingDetailed(
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

    var fileImportRequestToken: FileImportRequestGate.Token? {
        fileImportRequestGate.currentToken
    }

    func handleAppear() {
        applyPrefilledCiphertextIfNeeded(from: configuration)
        applyInitialPhase1ResultIfPresent(from: configuration)
    }

    func updateConfiguration(_ configuration: DecryptView.Configuration) {
        let previousConfiguration = self.configuration
        self.configuration = configuration

        if previousConfiguration.prefilledCiphertext != configuration.prefilledCiphertext {
            applyPrefilledCiphertextIfNeeded(from: configuration)
        }

        if Self.phase1Seed(from: previousConfiguration.initialPhase1Result) !=
            Self.phase1Seed(from: configuration.initialPhase1Result) {
            syncRuntimeInitialPhase1Result(from: configuration)
        }
    }

    func handleDisappear() {
        clearDisplayedText()
        deleteTemporaryDecryptedFile()
        clearDetailedSignatureVerification()
        phase1Result = nil
        filePhase1Result = nil
        importedCiphertext.clear()
        pendingTextModeImport = nil
        fileImportRequestGate.invalidate()
        fileImportTarget = nil
    }

    func handleContentClearGenerationChange() {
        authLifecycleTraceStore?.record(
            category: .operation,
            name: "decrypt.contentClearObserved",
            metadata: ["mode": decryptMode.rawValue]
        )
        operation.cancelAndInvalidate()
        clearTransientInput()
    }

    func clearTransientInput() {
        ciphertextInput = ""
        clearDisplayedText()
        deleteTemporaryDecryptedFile()
        clearDetailedSignatureVerification()
        phase1Result = nil
        filePhase1Result = nil
        importedCiphertext.clear()
        pendingTextModeImport = nil
        fileImportTarget = nil
        selectedFileURL = nil
        selectedFileName = nil
        showFileImporter = false
        fileImportRequestGate.invalidate()
        showTextModeSuggestion = false
        exportController.finish()
        textInputSectionEpoch &+= 1
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
        fileImportRequestGate.begin()
        showFileImporter = true
    }

    func requestFileCiphertextImport() {
        guard configuration.allowsFileInput else { return }
        fileImportTarget = .fileCiphertextImport
        fileImportRequestGate.begin()
        showFileImporter = true
    }

    func finishFileImportRequest() {
        fileImportRequestGate.invalidate()
        fileImportTarget = nil
    }

    func handleFileImporterResult(
        _ result: Result<[URL], Error>,
        token: FileImportRequestGate.Token?
    ) {
        guard fileImportRequestGate.consumeIfCurrent(token) else {
            return
        }

        defer {
            finishFileImportRequest()
        }

        if case .success(let urls) = result,
           let url = urls.first {
            handleImportedFile(url)
        }
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
        clearDetailedSignatureVerification()
        let onParsed = configuration.onParsed

        operation.run(mapError: mapDecryptError) { [self] in
            let result = try await self.parseTextRecipientsAction(inputData)
            try Task.checkCancellation()
            self.phase1Result = result
            self.textInputSectionEpoch &+= 1
            onParsed?(result)
        }
    }

    func parseRecipientsFile() {
        guard let fileURL = selectedFileURL else { return }

        invalidateFileInputState(deleteTemporaryOutput: true)

        operation.run(mapError: mapDecryptError) { [self] in
            let result = try await self.parseFileRecipientsAction(fileURL)
            try Task.checkCancellation()
            self.filePhase1Result = result
        }
    }

    func decryptText() {
        guard let phase1Result else { return }
        let onDecrypted = configuration.onDecrypted
        authLifecycleTraceStore?.record(category: .operation, name: "decrypt.text.start", metadata: ["mode": "text"])

        operation.run(mapError: mapDecryptError) { [self] in
            var (plaintext, verification) = try await self.textDecryptionAction(phase1Result)
            defer {
                plaintext.resetBytes(in: 0..<plaintext.count)
            }
            try Task.checkCancellation()

            if let text = String(data: plaintext, encoding: .utf8) {
                self.decryptedText = text
            }
            self.replaceDetailedSignatureVerification(with: verification)
            onDecrypted?(plaintext, verification)
            self.authLifecycleTraceStore?.record(
                category: .operation,
                name: "decrypt.text.finish",
                metadata: ["result": "success"]
            )
        }
    }

    func decryptFile() {
        guard let fileURL = selectedFileURL,
              let filePhase1Result else {
            return
        }

        authLifecycleTraceStore?.record(category: .operation, name: "decrypt.file.start", metadata: ["mode": "file"])

        operation.runFileOperation(mapError: mapDecryptError) { [self] progress in
            let result = try await self.fileDecryptionAction(
                fileURL,
                filePhase1Result,
                progress
            )
            var pendingArtifact: AppTemporaryArtifact? = result.artifact
            defer {
                pendingArtifact?.cleanup()
            }
            try Task.checkCancellation()
            self.adoptDecryptedFileArtifact(result.artifact)
            pendingArtifact = nil
            self.replaceDetailedSignatureVerification(with: result.verification)
            self.authLifecycleTraceStore?.record(
                category: .operation,
                name: "decrypt.file.finish",
                metadata: ["result": "success"]
            )
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
        clearDetailedSignatureVerification()
        phase1Result = nil
        textInputSectionEpoch &+= 1
    }

    private func invalidateFileInputState(deleteTemporaryOutput: Bool) {
        if deleteTemporaryOutput {
            deleteTemporaryDecryptedFile()
        }
        clearDetailedSignatureVerification()
        filePhase1Result = nil
    }

    private func replaceDetailedSignatureVerification(with verification: DetailedSignatureVerification) {
        detailedSignatureVerification = verification
    }

    private func clearDetailedSignatureVerification() {
        detailedSignatureVerification = nil
    }

    private func clearDisplayedText() {
        decryptedText = ""
        decryptedText = nil
    }

    private func deleteTemporaryDecryptedFile() {
        decryptedFileArtifact?.cleanup()
        decryptedFileArtifact = nil
        decryptedFileURL = nil
    }

    private func adoptDecryptedFileArtifact(_ artifact: AppTemporaryArtifact) {
        deleteTemporaryDecryptedFile()
        decryptedFileArtifact = artifact
        decryptedFileURL = artifact.fileURL
    }

    private func applyPrefilledCiphertextIfNeeded(from configuration: DecryptView.Configuration) {
        if ciphertextInput.isEmpty,
           let prefilledCiphertext = configuration.prefilledCiphertext {
            ciphertextInput = prefilledCiphertext
        }
    }

    private func applyInitialPhase1ResultIfPresent(from configuration: DecryptView.Configuration) {
        if let initialPhase1Result = configuration.initialPhase1Result {
            phase1Result = initialPhase1Result
        }
    }

    private func syncRuntimeInitialPhase1Result(from configuration: DecryptView.Configuration) {
        phase1Result = configuration.initialPhase1Result
    }

    private static func phase1Seed(
        from result: DecryptionService.Phase1Result?
    ) -> Phase1Seed? {
        result.map(Phase1Seed.init)
    }

    private func mapDecryptError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .corruptData(reason: $0) }
    }
}

private struct Phase1Seed: Equatable {
    let recipientKeyIds: [String]
    let matchedKeyFingerprint: String?
    let ciphertext: Data

    init(_ result: DecryptionService.Phase1Result) {
        recipientKeyIds = result.recipientKeyIds
        matchedKeyFingerprint = result.matchedKey?.fingerprint
        ciphertext = result.ciphertext
    }
}
