import Foundation

@MainActor
@Observable
final class SignScreenModel {
    typealias CleartextSigningAction = @MainActor (String, String) async throws -> Data
    typealias DetachedFileSigningAction = @MainActor (URL, String, FileProgressReporter) async throws -> Data

    let configuration: SignView.Configuration
    let operation: OperationController
    let exportController: FileExportController

    private let keyManagement: KeyManagementService
    private let appConfiguration: AppConfiguration
    private let protectedSettingsHost: ProtectedSettingsHost?
    private let cleartextSigningAction: CleartextSigningAction
    private let detachedFileSigningAction: DetachedFileSigningAction

    var signMode: SignView.SignMode = .text
    var text = ""
    var signerFingerprint: String?
    var signedMessage: String?
    var detachedSignature: Data?
    var showFileImporter = false
    var selectedFileURL: URL?
    var selectedFileName: String?
    var textInputSectionEpoch = 0

    init(
        signingService: SigningService,
        keyManagement: KeyManagementService,
        config: AppConfiguration,
        protectedSettingsHost: ProtectedSettingsHost? = nil,
        configuration: SignView.Configuration,
        operation: OperationController = OperationController(),
        exportController: FileExportController = FileExportController(),
        cleartextSigningAction: CleartextSigningAction? = nil,
        detachedFileSigningAction: DetachedFileSigningAction? = nil
    ) {
        self.configuration = configuration
        self.operation = operation
        self.exportController = exportController
        self.keyManagement = keyManagement
        self.appConfiguration = config
        self.protectedSettingsHost = protectedSettingsHost
        self.cleartextSigningAction = cleartextSigningAction ?? { message, signerFingerprint in
            try await signingService.signCleartext(message, signerFingerprint: signerFingerprint)
        }
        self.detachedFileSigningAction = detachedFileSigningAction ?? { fileURL, signerFingerprint, progress in
            try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: fileURL,
                        failure: .internalError(
                            reason: String(
                                localized: "sign.cannotAccessFile",
                                defaultValue: "Cannot access selected file"
                            )
                        )
                    )
                ]
            ) {
                try await signingService.signDetachedStreaming(
                    fileURL: fileURL,
                    signerFingerprint: signerFingerprint,
                    progress: progress
                )
            }
        }
    }

    var signingKeys: [PGPKeyIdentity] {
        keyManagement.keys
    }

    var signButtonDisabled: Bool {
        if operation.isRunning {
            return true
        }
        if resolvedSignerFingerprint == nil {
            return true
        }

        switch signMode {
        case .text:
            return text.isEmpty
        case .file:
            return !configuration.allowsFileInput || selectedFileURL == nil
        }
    }

    var showsFileCancelAction: Bool {
        signMode == .file && operation.isRunning && operation.progress != nil
    }

    func syncSignerFromDefaultOnAppear() {
        signerFingerprint = keyManagement.defaultKey?.fingerprint
    }

    func requestFileImport() {
        guard configuration.allowsFileInput else { return }
        showFileImporter = true
    }

    func handleImportedFile(_ url: URL) {
        selectedFileURL = url
        selectedFileName = url.lastPathComponent
    }

    func sign() {
        switch signMode {
        case .text:
            signText()
        case .file:
            signFile()
        }
    }

    func signText() {
        guard let signerFingerprint = resolvedSignerFingerprint else { return }

        let message = text
        signedMessage = nil

        operation.run(mapError: mapSigningError) { [self] in
            let signed = try await self.cleartextSigningAction(message, signerFingerprint)
            self.signedMessage = String(data: signed, encoding: .utf8)
            self.textInputSectionEpoch &+= 1
        }
    }

    func signFile() {
        guard let fileURL = selectedFileURL,
              let signerFingerprint = resolvedSignerFingerprint else {
            return
        }

        detachedSignature = nil

        operation.runFileOperation(mapError: mapSigningError) { [self] progress in
            let signature = try await self.detachedFileSigningAction(fileURL, signerFingerprint, progress)
            try Task.checkCancellation()
            self.detachedSignature = signature
        }
    }

    func copySignedMessageToClipboard() {
        guard configuration.allowsClipboardWrite,
              let signedMessage else {
            return
        }

        if configuration.outputInterceptionPolicy.interceptClipboardCopy?(
            signedMessage,
            appConfiguration,
            .generic
        ) != true {
            Task { @MainActor [weak self] in
                guard let self else { return }
                let shouldShowNotice = await self.protectedSettingsHost?.clipboardNoticeDecision() ?? true
                self.operation.copyToClipboard(
                    signedMessage,
                    shouldShowNotice: shouldShowNotice
                )
            }
        }
    }

    func exportSignedMessage() {
        guard configuration.allowsTextResultExport,
              let signedMessage else {
            return
        }

        do {
            let exportData = Data(signedMessage.utf8)
            if try configuration.outputInterceptionPolicy.interceptDataExport?(
                exportData,
                "signed.asc",
                .generic
            ) != true {
                try exportController.prepareDataExport(
                    exportData,
                    suggestedFilename: "signed.asc"
                )
            }
        } catch {
            operation.present(error: mapSigningError(error))
        }
    }

    func exportDetachedSignature() {
        guard let detachedSignature,
              configuration.allowsFileResultExport else {
            return
        }

        do {
            let suggestedFilename = (selectedFileName ?? "file") + ".sig"
            if try configuration.outputInterceptionPolicy.interceptDataExport?(
                detachedSignature,
                suggestedFilename,
                .generic
            ) != true {
                try exportController.prepareDataExport(
                    detachedSignature,
                    suggestedFilename: suggestedFilename
                )
            }
        } catch {
            operation.present(error: mapSigningError(error))
        }
    }

    func dismissError() {
        operation.dismissError()
    }

    func dismissClipboardNotice(disableFutureNotices: Bool = false) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            if disableFutureNotices {
                await self.protectedSettingsHost?.disableClipboardNotice()
            }
            self.operation.dismissClipboardNotice()
        }
    }

    func finishExport() {
        exportController.finish()
    }

    func handleExportError(_ error: Error) {
        operation.present(error: mapSigningError(error))
    }

    private var resolvedSignerFingerprint: String? {
        signerFingerprint ?? keyManagement.defaultKey?.fingerprint
    }

    private func mapSigningError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .signingFailed(reason: $0) }
    }
}
