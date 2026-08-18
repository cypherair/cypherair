import Foundation

@MainActor
@Observable
final class DecryptScreenModel {
    struct FileDecryptionRequest {
        let fileURL: URL
        let phase1Result: FileDecryptionPhase1Result
    }

    struct TextDecryptionResult {
        let plaintext: String
        let verification: DetailedSignatureVerification
    }

    struct FileDecryptionResult {
        let output: TemporaryFileOutput
        let verification: DetailedSignatureVerification
    }

    typealias InspectTextMessageAction = @MainActor (Data) async throws -> DecryptionPhase1Result
    typealias ParseFileRecipientsAction = @MainActor (URL) async throws -> FileDecryptionPhase1Result
    typealias TextCiphertextFileImportAction = @MainActor (URL) throws -> (data: Data, text: String)
    typealias CiphertextFileInspectionAction = @MainActor (URL) throws -> (data: Data, text: String)?
    typealias TextDecryptionAction = @MainActor (
        DecryptionPhase1Result
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification)
    typealias PasswordDecryptionAction = @MainActor (
        DecryptionPhase1Result,
        String
    ) async throws -> PasswordMessageDetailedDecryptOutcome
    typealias FileDecryptionAction = @MainActor (
        FileDecryptionRequest
    ) async throws -> FileDecryptionResult

    private(set) var configuration: DecryptView.Configuration
    let operation: OperationController
    let exportController: FileExportController

    private let inspectTextMessageAction: InspectTextMessageAction
    private let parseFileRecipientsAction: ParseFileRecipientsAction
    private let textCiphertextFileImportAction: TextCiphertextFileImportAction
    private let ciphertextFileInspectionAction: CiphertextFileInspectionAction
    private let textDecryptionAction: TextDecryptionAction
    private let passwordDecryptionAction: PasswordDecryptionAction
    private let fileDecryptionAction: FileOperationAction<FileDecryptionRequest, FileDecryptionResult>
    private var fileImportRequestGate = FileImportRequestGate()

    private struct PendingTextModeImport {
        let fileURL: URL
        let fileName: String
        let data: Data
        let text: String
    }

    var decryptMode: DecryptView.DecryptMode = .text
    var ciphertextInput = ""
    /// What the reader typed to open a password-protected message. Never gated
    /// on `PassphraseRequirements`: whoever wrote the message fixed its
    /// protection, and refusing a weak one here would only lock the reader out
    /// of a message they are entitled to read.
    var password = ""
    var textDecryptionResult: TextDecryptionResult?
    var fileDecryptionResult: FileDecryptionResult? {
        didSet {
            oldValue?.output.cleanup()
        }
    }
    var phase1Result: DecryptionPhase1Result?
    var showFileImporter = false
    var fileImportTarget: DecryptView.FileImportTarget?
    var selectedFileURL: URL?
    var selectedFileName: String?
    var filePhase1Result: FileDecryptionPhase1Result?
    var importedCiphertext = ImportedTextInputState()
    private var pendingTextModeImport: PendingTextModeImport?
    var showTextModeSuggestion = false
    var textInputSectionEpoch = 0

    init(
        decryptionService: DecryptionService,
        configuration: DecryptView.Configuration,
        operation: OperationController = OperationController(),
        exportController: FileExportController = FileExportController(),
        inspectTextMessageAction: InspectTextMessageAction? = nil,
        parseFileRecipientsAction: ParseFileRecipientsAction? = nil,
        textCiphertextFileImportAction: TextCiphertextFileImportAction? = nil,
        ciphertextFileInspectionAction: CiphertextFileInspectionAction? = nil,
        textDecryptionAction: TextDecryptionAction? = nil,
        passwordDecryptionAction: PasswordDecryptionAction? = nil,
        fileDecryptionAction: FileDecryptionAction? = nil
    ) {
        self.configuration = configuration
        self.operation = operation
        self.exportController = exportController
        self.inspectTextMessageAction = inspectTextMessageAction ?? { ciphertext in
            try await decryptionService.inspectMessage(ciphertext: ciphertext)
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
        self.passwordDecryptionAction = passwordDecryptionAction ?? { phase1, password in
            try await decryptionService.decryptDetailedWithPassword(
                phase1: phase1,
                password: password
            )
        }
        self.fileDecryptionAction = FileOperationAction(injectedAction: fileDecryptionAction) { request, progress in
            try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: request.fileURL,
                        failure: .corruptData(
                            reason: String(
                                localized: "fileDecrypt.cannotAccess",
                                defaultValue: "Cannot access file"
                            )
                        )
                    )
                ]
            ) {
                let result = try await decryptionService.decryptFileStreamingDetailed(
                    phase1: request.phase1Result,
                    progress: progress
                )
                return FileDecryptionResult(
                    output: result.artifact.temporaryFileOutput,
                    verification: result.verification
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

    /// The inspected message can only be opened with a password. A message that
    /// also matches a local key is not offered this route: the key is the
    /// stronger of the two and needs nothing typed.
    var asksForPassword: Bool {
        guard decryptMode == .text, let phase1Result else {
            return false
        }
        return phase1Result.matchedKey == nil && phase1Result.acceptsPassword
    }

    var passwordDecryptButtonDisabled: Bool {
        operation.isRunning || password.isEmpty
    }

    var hasPhase1Result: Bool {
        switch decryptMode {
        case .text:
            phase1Result != nil
        case .file:
            filePhase1Result != nil
        }
    }

    var activeDetailedSignatureVerification: DetailedSignatureVerification? {
        switch decryptMode {
        case .text:
            textDecryptionResult?.verification
        case .file:
            fileDecryptionResult?.verification
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
        operation.cancelAndInvalidate()
        clearTextDecryptionResult()
        clearFileDecryptionResult()
        phase1Result = nil
        filePhase1Result = nil
        password = ""
        importedCiphertext.clear()
        pendingTextModeImport = nil
        fileImportRequestGate.invalidate()
        fileImportTarget = nil
    }

    func handleContentClearGenerationChange() {
        operation.cancelAndInvalidate()
        clearTransientInput()
    }

    func clearTransientInput() {
        ciphertextInput = ""
        password = ""
        clearTextDecryptionResult()
        clearFileDecryptionResult()
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
        invalidateTextInputState(refreshInputSection: false)
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

    func inspectTextMessage() {
        let inputData = importedCiphertext.rawData ?? Data(ciphertextInput.utf8)
        clearTextDecryptionResult()
        let onParsed = configuration.onParsed

        operation.run(mapError: mapDecryptError) { [self] in
            let result = try await self.inspectTextMessageAction(inputData)
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

        operation.run(mapError: mapDecryptError) { [self] in
            var (plaintext, verification) = try await self.textDecryptionAction(phase1Result)
            defer {
                plaintext.resetBytes(in: 0..<plaintext.count)
            }
            try Task.checkCancellation()

            if let text = String(data: plaintext, encoding: .utf8) {
                self.textDecryptionResult = TextDecryptionResult(
                    plaintext: text,
                    verification: verification
                )
            }
            onDecrypted?(plaintext, verification)
        }
    }

    /// Open a password-protected message. No key is used and no authentication
    /// prompt is raised; the engine refuses an Argon2 cost this device cannot
    /// afford before it derives anything.
    func decryptTextWithPassword() {
        guard let phase1Result, !password.isEmpty else { return }
        let passwordSnapshot = password
        let onDecrypted = configuration.onDecrypted

        operation.run(mapError: mapDecryptError) { [self] in
            let outcome = try await self.passwordDecryptionAction(phase1Result, passwordSnapshot)
            try Task.checkCancellation()

            switch outcome {
            case .decrypted(var plaintext, let verification):
                defer {
                    plaintext.resetBytes(in: 0..<plaintext.count)
                }
                if let text = String(data: plaintext, encoding: .utf8) {
                    self.textDecryptionResult = TextDecryptionResult(
                        plaintext: text,
                        verification: verification
                    )
                }
                // The password worked, so it has no further job. Holding it
                // would only widen the window in which it can be read back off
                // the screen.
                self.password = ""
                onDecrypted?(plaintext, verification)

            case .passwordRejected:
                throw CypherAirError.wrongMessagePassword

            case .noSkesk:
                // Phase 1 said this message carries a password slot, so it does.
                // Reaching here means the two disagree about the same bytes.
                throw CypherAirError.noMatchingKey
            }
        }
    }

    func decryptFile() {
        guard let fileURL = selectedFileURL,
              let filePhase1Result else {
            return
        }

        operation.runFileOperation(mapError: mapDecryptError) { [self] progress in
            let result = try await self.fileDecryptionAction(
                FileDecryptionRequest(
                    fileURL: fileURL,
                    phase1Result: filePhase1Result
                ),
                progress: progress
            )
            var pendingOutput: TemporaryFileOutput? = result.output
            defer {
                pendingOutput?.cleanup()
            }
            try Task.checkCancellation()
            self.adoptFileDecryptionResult(result)
            pendingOutput = nil
        }
    }

    func exportDecryptedFile() {
        guard configuration.allowsFileResultExport,
              let fileDecryptionResult else {
            return
        }
        let decryptedFileURL = fileDecryptionResult.output.fileURL

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
        invalidateTextInputState(refreshInputSection: true)
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
        invalidateTextInputState(refreshInputSection: true)
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
            invalidateTextInputState(refreshInputSection: true)
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

    private func invalidateTextInputState(refreshInputSection: Bool) {
        clearTextDecryptionResult()
        phase1Result = nil
        // The password belonged to the message that just went away.
        password = ""
        if refreshInputSection {
            textInputSectionEpoch &+= 1
        }
    }

    private func invalidateFileInputState(deleteTemporaryOutput: Bool) {
        if deleteTemporaryOutput {
            clearFileDecryptionResult()
        }
        filePhase1Result = nil
    }

    private func clearTextDecryptionResult() {
        textDecryptionResult = nil
    }

    private func clearFileDecryptionResult() {
        fileDecryptionResult = nil
    }

    private func adoptFileDecryptionResult(_ result: FileDecryptionResult) {
        fileDecryptionResult = result
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
        from result: DecryptionPhase1Result?
    ) -> Phase1Seed? {
        result.map(Phase1Seed.init)
    }

    private func mapDecryptError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .corruptData(reason: $0) }
    }
}

private struct Phase1Seed: Equatable {
    let matchedKeyFingerprint: String?
    let acceptsPassword: Bool
    let ciphertext: Data

    init(_ result: DecryptionPhase1Result) {
        matchedKeyFingerprint = result.matchedKey?.fingerprint
        acceptsPassword = result.acceptsPassword
        ciphertext = result.ciphertext
    }
}
