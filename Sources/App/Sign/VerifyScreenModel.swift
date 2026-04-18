import Foundation
import UniformTypeIdentifiers

@MainActor
@Observable
final class VerifyScreenModel {
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
        URL,
        URL,
        FileProgressReporter
    ) async throws -> DetailedSignatureVerification
    typealias CleartextFileImportAction = @MainActor (URL) throws -> (
        data: Data,
        text: String
    )

    let configuration: VerifyView.Configuration
    let operation: OperationController

    private let cleartextVerificationAction: CleartextVerificationAction
    private let detachedVerificationAction: DetachedVerificationAction
    private let cleartextFileImportAction: CleartextFileImportAction

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
        self.detachedVerificationAction = detachedVerificationAction ?? { originalURL, signatureURL, progress in
            try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: originalURL,
                        failure: .internalError(
                            reason: String(
                                localized: "verify.cannotAccessOriginal",
                                defaultValue: "Cannot access original file"
                            )
                        )
                    ),
                    SecurityScopedAccessRequest(
                        resource: signatureURL,
                        failure: .internalError(
                            reason: String(
                                localized: "verify.cannotAccessSignature",
                                defaultValue: "Cannot access signature file"
                            )
                        )
                    )
                ]
            ) {
                let signature = try Data(contentsOf: signatureURL)
                try Task.checkCancellation()
                return try await signingService.verifyDetachedStreamingDetailed(
                    fileURL: originalURL,
                    signature: signature,
                    progress: progress
                )
            }
        }
        self.cleartextFileImportAction = cleartextFileImportAction ?? { url in
            let data = try SecurityScopedFileAccess.withAccess(
                to: url,
                failure: .corruptData(
                    reason: String(
                        localized: "verify.importCleartextReadFailed",
                        defaultValue: "Could not read signed message file"
                    )
                )
            ) {
                try Data(contentsOf: url)
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

    var activeVerification: SignatureVerification? {
        activeDetailedVerification?.legacyVerification
    }

    var activeDetailedVerification: DetailedSignatureVerification? {
        switch verifyMode {
        case .cleartext:
            cleartextDetailedVerification
        case .detached:
            detachedDetailedVerification
        }
    }

    var cleartextVerification: SignatureVerification? {
        cleartextDetailedVerification?.legacyVerification
    }

    var detachedVerification: SignatureVerification? {
        detachedDetailedVerification?.legacyVerification
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

    func setSignedInput(_ newValue: String) {
        guard newValue != signedInput else {
            return
        }

        signedInput = newValue
        _ = importedCleartext.invalidateIfEditedTextDiffers(newValue)
        invalidateCleartextVerificationState()
    }

    func requestCleartextFileImport() {
        guard configuration.allowsCleartextFileImport else {
            return
        }

        filePickerTarget = .cleartextSignedImport
        showFileImporter = true
    }

    func requestOriginalFileImport() {
        guard configuration.allowsDetachedOriginalImport else {
            return
        }

        filePickerTarget = .original
        showFileImporter = true
    }

    func requestSignatureFileImport() {
        guard configuration.allowsDetachedSignatureImport else {
            return
        }

        filePickerTarget = .signature
        showFileImporter = true
    }

    func finishFileImportRequest() {
        filePickerTarget = nil
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
        filePickerTarget = nil
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
        invalidateCleartextVerificationState()

        operation.run(mapError: mapVerificationError) { [self] in
            let result = try await self.cleartextVerificationAction(inputData)
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
                originalFileURL,
                signatureFileURL,
                progress
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
        invalidateCleartextVerificationState()
    }

    private func importCleartextFile(from url: URL) {
        do {
            let loadedFile = try cleartextFileImportAction(url)
            importedCleartext.setImportedFile(
                data: loadedFile.data,
                fileName: url.lastPathComponent,
                text: loadedFile.text
            )
            signedInput = loadedFile.text
            invalidateCleartextVerificationState()
        } catch let error as CypherAirError {
            operation.present(error: error)
        } catch {
            operation.present(error: mapVerificationError(error))
        }
    }

    private func invalidateCleartextVerificationState() {
        cleartextOriginalText = nil
        clearCleartextVerificationState()
        textInputSectionEpoch &+= 1
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

    private func mapVerificationError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { _ in .badSignature }
    }
}
