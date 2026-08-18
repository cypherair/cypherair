import Foundation
import UniformTypeIdentifiers

@MainActor
@Observable
final class VerifyScreenModel {
    struct DetachedVerificationRequest {
        let originalFileURL: URL
        let signatureFileURL: URL
    }

    enum FilePickerTarget {
        case cleartextSignedImport
        case original
        case signature
    }

    typealias CleartextVerificationAction = @MainActor (Data) async throws -> (
        text: Data?,
        verification: DetailedSignatureVerification
    )
    typealias DetachedVerificationAction = @MainActor (
        DetachedVerificationRequest
    ) async throws -> DetailedSignatureVerification
    typealias CleartextFileImportAction = @MainActor (URL) throws -> (
        data: Data,
        text: String
    )

    let configuration: VerifyView.Configuration
    let operation: OperationController

    private let cleartextVerificationAction: CleartextVerificationAction
    private let detachedVerificationAction: FileOperationAction<DetachedVerificationRequest, DetailedSignatureVerification>
    private let cleartextFileImportAction: CleartextFileImportAction
    private var fileImportRequestGate = FileImportRequestGate()

    var verifyMode: VerifyView.VerifyMode = .cleartext
    var signedInput = ""
    var cleartextOriginalText: String?
    var cleartextDetailedVerification: DetailedSignatureVerification?
    var detachedDetailedVerification: DetailedSignatureVerification?
    var filePickerTarget: FilePickerTarget?
    var showFileImporter = false
    var importedCleartext = ImportedTextInputState()
    var originalFileURL: URL?
    var originalFileName: String?
    var signatureFileURL: URL?
    var signatureFileName: String?
    var textInputSectionEpoch = 0

    init(
        signingService: SigningService,
        configuration: VerifyView.Configuration,
        operation: OperationController = OperationController(),
        cleartextVerificationAction: CleartextVerificationAction? = nil,
        detachedVerificationAction: DetachedVerificationAction? = nil,
        cleartextFileImportAction: CleartextFileImportAction? = nil
    ) {
        self.configuration = configuration
        self.operation = operation
        self.cleartextVerificationAction = cleartextVerificationAction ?? { signedMessage in
            try await signingService.verifyCleartextDetailed(signedMessage)
        }
        self.detachedVerificationAction = FileOperationAction(injectedAction: detachedVerificationAction) { request, progress in
            try await SecurityScopedFileAccess.withAccess(
                to: [request.originalFileURL, request.signatureFileURL]
            ) {
                let signature = try readVerificationInputFile(at: request.signatureFileURL)
                try Task.checkCancellation()
                return try await signingService.verifyDetachedStreamingDetailed(
                    fileURL: request.originalFileURL,
                    signature: signature,
                    progress: progress
                )
            }
        }
        self.cleartextFileImportAction = cleartextFileImportAction ?? { url in
            let data = try SecurityScopedFileAccess.withAccess(to: url) {
                try readVerificationInputFile(at: url)
            }

            guard let text = String(data: data, encoding: .utf8) else {
                throw CypherAirError.corruptData(
                    reason: String(
                        localized: "verify.importCleartextReadFailed",
                        defaultValue: "Could not read signed message file"
                    )
                )
            }

            return (data, text)
        }
    }

    var activeDetailedVerification: DetailedSignatureVerification? {
        switch verifyMode {
        case .cleartext:
            cleartextDetailedVerification
        case .detached:
            detachedDetailedVerification
        }
    }

    var verifyButtonDisabled: Bool {
        if operation.isRunning {
            return true
        }

        switch verifyMode {
        case .cleartext:
            return signedInput.isEmpty && importedCleartext.rawData == nil
        case .detached:
            return originalFileURL == nil || signatureFileURL == nil
        }
    }

    var allowedImportContentTypes: [UTType] {
        switch filePickerTarget {
        case .cleartextSignedImport:
            [
                UTType(filenameExtension: "asc") ?? .plainText,
                .plainText
            ]
        case .signature:
            [UTType(filenameExtension: "sig") ?? .data, .data]
        case .original, .none:
            [.data]
        }
    }

    var showsDetachedCancelAction: Bool {
        verifyMode == .detached && operation.isRunning && operation.progress != nil
    }

    var fileImportRequestToken: FileImportRequestGate.Token? {
        fileImportRequestGate.currentToken
    }

    func setSignedInput(_ newValue: String) {
        guard newValue != signedInput else {
            return
        }

        signedInput = newValue
        _ = importedCleartext.invalidateIfEditedTextDiffers(newValue)
        invalidateCleartextVerificationState(refreshInputSection: false)
    }

    func requestCleartextFileImport() {
        guard configuration.allowsCleartextFileImport else {
            return
        }

        filePickerTarget = .cleartextSignedImport
        fileImportRequestGate.begin()
        showFileImporter = true
    }

    func requestOriginalFileImport() {
        guard configuration.allowsDetachedOriginalImport else {
            return
        }

        filePickerTarget = .original
        fileImportRequestGate.begin()
        showFileImporter = true
    }

    func requestSignatureFileImport() {
        guard configuration.allowsDetachedSignatureImport else {
            return
        }

        filePickerTarget = .signature
        fileImportRequestGate.begin()
        showFileImporter = true
    }

    func finishFileImportRequest() {
        fileImportRequestGate.invalidate()
        filePickerTarget = nil
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

        if case .success(let urls) = result, let url = urls.first {
            handleImportedFile(url)
        }
    }

    func handleImportedFile(_ url: URL) {
        switch filePickerTarget {
        case .cleartextSignedImport:
            importCleartextFile(from: url)
        case .original:
            originalFileURL = url
            originalFileName = url.lastPathComponent
            invalidateDetachedVerificationState()
        case .signature:
            signatureFileURL = url
            signatureFileName = url.lastPathComponent
            invalidateDetachedVerificationState()
        case .none:
            break
        }
    }

    func handleDisappear() {
        importedCleartext.clear()
        fileImportRequestGate.invalidate()
        filePickerTarget = nil
    }

    func clearTransientInput() {
        signedInput = ""
        cleartextOriginalText = nil
        clearCleartextVerificationState()
        clearDetachedVerificationState()
        importedCleartext.clear()
        originalFileURL = nil
        originalFileName = nil
        signatureFileURL = nil
        signatureFileName = nil
        filePickerTarget = nil
        showFileImporter = false
        fileImportRequestGate.invalidate()
        textInputSectionEpoch &+= 1
    }

    func handleContentClearGenerationChange() {
        operation.cancelAndInvalidate()
        clearTransientInput()
    }

    func verify() {
        switch verifyMode {
        case .cleartext:
            verifyCleartext()
        case .detached:
            verifyDetached()
        }
    }

    func verifyCleartext() {
        let inputData = importedCleartext.rawData ?? Data(signedInput.utf8)
        invalidateCleartextVerificationState(refreshInputSection: false)

        operation.run(mapError: mapVerificationError) { [self] in
            let result = try await self.cleartextVerificationAction(inputData)
            try Task.checkCancellation()
            if let content = result.text {
                self.cleartextOriginalText = String(data: content, encoding: .utf8)
            }
            self.replaceCleartextDetailedVerification(with: result.verification)
            self.textInputSectionEpoch &+= 1
        }
    }

    func verifyDetached() {
        guard let originalFileURL,
              let signatureFileURL else {
            return
        }

        clearDetachedVerificationState()

        operation.runFileOperation(mapError: mapVerificationError) { [self] progress in
            let result = try await self.detachedVerificationAction(
                DetachedVerificationRequest(
                    originalFileURL: originalFileURL,
                    signatureFileURL: signatureFileURL
                ),
                progress: progress
            )
            try Task.checkCancellation()
            self.replaceDetachedDetailedVerification(with: result)
        }
    }

    func dismissError() {
        operation.dismissError()
    }

    func clearImportedCleartext() {
        importedCleartext.clear()
        signedInput = ""
        invalidateCleartextVerificationState(refreshInputSection: true)
    }

    /// Take a signed message the system asked the app to open.
    ///
    /// The same state a chosen file produces: the message is loaded and the
    /// reader still presses Verify. A signed message is text by construction —
    /// the cleartext framework, or an armored one-pass-signed message — so
    /// content that is not decodable text was misidentified, and saying so is
    /// better than showing an empty editor.
    func adoptOpenedSignedMessage(data: Data, fileName: String) {
        guard let text = String(data: data, encoding: .utf8) else {
            operation.present(error: .openedFileUnsupportedContent)
            return
        }

        verifyMode = .cleartext
        loadCleartext(data: data, fileName: fileName, text: text)
    }

    private func importCleartextFile(from url: URL) {
        do {
            let loadedFile = try cleartextFileImportAction(url)
            loadCleartext(
                data: loadedFile.data,
                fileName: url.lastPathComponent,
                text: loadedFile.text
            )
        } catch let error as CypherAirError {
            operation.present(error: error)
        } catch {
            operation.present(error: mapFileImportError(error))
        }
    }

    private func loadCleartext(data: Data, fileName: String, text: String) {
        importedCleartext.setImportedFile(data: data, fileName: fileName, text: text)
        signedInput = text
        invalidateCleartextVerificationState(refreshInputSection: true)
    }

    private func invalidateCleartextVerificationState(refreshInputSection: Bool) {
        cleartextOriginalText = nil
        clearCleartextVerificationState()
        if refreshInputSection {
            textInputSectionEpoch &+= 1
        }
    }

    private func invalidateDetachedVerificationState() {
        clearDetachedVerificationState()
    }

    private func replaceCleartextDetailedVerification(with verification: DetailedSignatureVerification) {
        cleartextDetailedVerification = verification
    }

    private func replaceDetachedDetailedVerification(with verification: DetailedSignatureVerification) {
        detachedDetailedVerification = verification
    }

    private func clearCleartextVerificationState() {
        cleartextDetailedVerification = nil
    }

    private func clearDetachedVerificationState() {
        detachedDetailedVerification = nil
    }

    /// Normalizes a failure raised while *performing* verification.
    ///
    /// Verification reports through two separate channels, and they must not be
    /// mixed. The verdict — what the check found — travels as
    /// `DetailedSignatureVerification`, and it alone may say a signature is
    /// invalid. This error channel says only that the check could not be run to
    /// completion, so nothing mapped here may borrow the verdict vocabulary:
    /// `.badSignature` claims a cryptographic rejection the app never reached,
    /// and a false "this signature is invalid" is the one claim a verification
    /// tool must never make wrongly. The crypto layer keeps the same separation
    /// and never throws a verdict either — a real rejection returns as
    /// `.invalid` in the result.
    private func mapVerificationError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .internalError(reason: $0) }
    }

    /// Normalizes a failure raised while loading a file the user picked for
    /// verification. This runs before any verification is attempted, so the
    /// failure is about the file, never about a signature.
    private func mapFileImportError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .fileIoError(reason: $0) }
    }
}

/// Reads a file the user picked as verification input.
///
/// A file the app cannot read is an infrastructure failure, not a finding about
/// the signature the file was supposed to carry, so the read failure surfaces as
/// the I/O failure it is instead of falling through to a verdict-shaped error.
private func readVerificationInputFile(at url: URL) throws -> Data {
    do {
        return try Data(contentsOf: url)
    } catch {
        throw CypherAirError.fileIoError(reason: error.localizedDescription)
    }
}
