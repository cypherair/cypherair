import Foundation

@MainActor
@Observable
final class EncryptScreenModel {
    typealias TextEncryptionAction = @MainActor (
        String,
        [String],
        String?,
        Bool,
        String?
    ) async throws -> Data
    typealias FileEncryptionAction = @MainActor (
        URL,
        [String],
        String?,
        Bool,
        String?,
        FileProgressReporter
    ) async throws -> URL

    let configuration: EncryptView.Configuration
    let operation: OperationController
    let exportController: FileExportController

    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let appConfiguration: AppConfiguration
    private let textEncryptionAction: TextEncryptionAction
    private let fileEncryptionAction: FileEncryptionAction

    var encryptMode: EncryptView.EncryptMode = .text
    var plaintext = ""
    var selectedRecipients: Set<String> = []
    var signMessage = true
    var signerFingerprint: String?
    var ciphertext: Data?
    var encryptToSelf: Bool?
    var encryptToSelfFingerprint: String?
    var showFileImporter = false
    var selectedFileURL: URL?
    var selectedFileName: String?
    var encryptedFileURL: URL?
    var showUnverifiedRecipientsWarning = false
    var textInputSectionEpoch = 0

    init(
        encryptionService: EncryptionService,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        config: AppConfiguration,
        configuration: EncryptView.Configuration,
        operation: OperationController = OperationController(),
        exportController: FileExportController = FileExportController(),
        textEncryptionAction: TextEncryptionAction? = nil,
        fileEncryptionAction: FileEncryptionAction? = nil
    ) {
        self.configuration = configuration
        self.operation = operation
        self.exportController = exportController
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.appConfiguration = config
        self.textEncryptionAction = textEncryptionAction ?? {
            plaintext,
            recipients,
            signerFingerprint,
            encryptToSelf,
            encryptToSelfFingerprint in
            try await encryptionService.encryptText(
                plaintext,
                recipientFingerprints: recipients,
                signWithFingerprint: signerFingerprint,
                encryptToSelf: encryptToSelf,
                encryptToSelfFingerprint: encryptToSelfFingerprint
            )
        }
        self.fileEncryptionAction = fileEncryptionAction ?? {
            fileURL,
            recipients,
            signerFingerprint,
            encryptToSelf,
            encryptToSelfFingerprint,
            progress in
            try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: fileURL,
                        failure: .corruptData(
                            reason: String(
                                localized: "fileEncrypt.cannotAccess",
                                defaultValue: "Cannot access file"
                            )
                        )
                    )
                ]
            ) {
                try await encryptionService.encryptFileStreaming(
                    inputURL: fileURL,
                    recipientFingerprints: recipients,
                    signWithFingerprint: signerFingerprint,
                    encryptToSelf: encryptToSelf,
                    encryptToSelfFingerprint: encryptToSelfFingerprint,
                    progress: progress
                )
            }
        }
    }

    var encryptableContacts: [Contact] {
        contactService.contacts.filter(\.canEncryptTo)
    }

    var ownKeys: [PGPKeyIdentity] {
        keyManagement.keys
    }

    var defaultKeyVersion: UInt8? {
        keyManagement.defaultKey.map(\.keyVersion)
    }

    var selectedUnverifiedContacts: [Contact] {
        contactService.contacts.filter { contact in
            selectedRecipients.contains(contact.fingerprint) && !contact.isVerified
        }
    }

    var encryptButtonDisabled: Bool {
        if operation.isRunning {
            return true
        }
        if selectedRecipients.isEmpty {
            return true
        }

        switch encryptMode {
        case .text:
            return plaintext.isEmpty
        case .file:
            return selectedFileURL == nil
        }
    }

    var showsFileCancelAction: Bool {
        encryptMode == .file && operation.isRunning && operation.progress != nil
    }

    var resolvedEncryptToSelf: Bool {
        encryptToSelf ?? appConfiguration.encryptToSelf
    }

    var ciphertextString: String? {
        ciphertext.flatMap { String(data: $0, encoding: .utf8) }
    }

    var unverifiedRecipientsWarningMessage: String {
        String.localizedStringWithFormat(
            String(
                localized: "encrypt.unverified.confirm.message",
                defaultValue: "These recipients are not verified yet: %@. Continue only if you trust these keys."
            ),
            selectedUnverifiedContacts.map(\.displayName).joined(separator: ", ")
        )
    }

    func handleAppear() {
        if plaintext.isEmpty,
           let prefilledPlaintext = configuration.prefilledPlaintext {
            plaintext = prefilledPlaintext
        }
        if !configuration.initialRecipientFingerprints.isEmpty {
            selectedRecipients = Set(configuration.initialRecipientFingerprints)
        }

        let defaultSigner = configuration.initialSignerFingerprint ?? keyManagement.defaultKey?.fingerprint
        signerFingerprint = defaultSigner
        encryptToSelfFingerprint = defaultSigner
        signMessage = configuration.signingPolicy.initialValue(appDefault: true)
        encryptToSelf = configuration.encryptToSelfPolicy.initialValue(
            appDefault: appConfiguration.encryptToSelf
        )
    }

    func toggleRecipient(_ fingerprint: String, isOn: Bool) {
        if isOn {
            selectedRecipients.insert(fingerprint)
        } else {
            selectedRecipients.remove(fingerprint)
        }
    }

    func requestFileImport() {
        guard configuration.allowsFileInput else { return }
        showFileImporter = true
    }

    func handleImportedFile(_ url: URL) {
        selectedFileURL = url
        selectedFileName = url.lastPathComponent
    }

    func requestEncrypt() {
        if !selectedUnverifiedContacts.isEmpty {
            showUnverifiedRecipientsWarning = true
            return
        }

        performEncrypt()
    }

    func confirmEncryptWithUnverifiedRecipients() {
        showUnverifiedRecipientsWarning = false
        performEncrypt()
    }

    func dismissUnverifiedRecipientsWarning() {
        showUnverifiedRecipientsWarning = false
    }

    func encryptText() {
        let text = plaintext
        let recipients = Array(selectedRecipients)
        let signerFingerprint = signMessage ? signerFingerprint : nil
        let encryptToSelf = resolvedEncryptToSelf
        let encryptToSelfFingerprint = encryptToSelf ? self.encryptToSelfFingerprint : nil

        ciphertext = nil

        operation.run(mapError: mapEncryptionError) { [self] in
            let result = try await self.textEncryptionAction(
                text,
                recipients,
                signerFingerprint,
                encryptToSelf,
                encryptToSelfFingerprint
            )
            self.ciphertext = result
            self.textInputSectionEpoch &+= 1
            self.configuration.onEncrypted?(result)
        }
    }

    func encryptFile() {
        guard let fileURL = selectedFileURL else { return }

        let recipients = Array(selectedRecipients)
        let signerFingerprint = signMessage ? signerFingerprint : nil
        let encryptToSelf = resolvedEncryptToSelf
        let encryptToSelfFingerprint = encryptToSelf ? self.encryptToSelfFingerprint : nil

        encryptedFileURL = nil

        operation.runFileOperation(mapError: mapEncryptionError) { [self] progress in
            let result = try await self.fileEncryptionAction(
                fileURL,
                recipients,
                signerFingerprint,
                encryptToSelf,
                encryptToSelfFingerprint,
                progress
            )
            try Task.checkCancellation()
            self.encryptedFileURL = result
        }
    }

    func copyCiphertextToClipboard() {
        guard configuration.allowsClipboardWrite,
              let ciphertextString else {
            return
        }

        if configuration.outputInterceptionPolicy.interceptClipboardCopy?(
            ciphertextString,
            appConfiguration,
            .ciphertext
        ) != true {
            operation.copyToClipboard(ciphertextString, config: appConfiguration)
        }
    }

    func exportCiphertext() {
        guard configuration.allowsResultExport,
              let ciphertext else {
            return
        }

        do {
            if try configuration.outputInterceptionPolicy.interceptDataExport?(
                ciphertext,
                "encrypted.asc",
                .ciphertext
            ) != true {
                try exportController.prepareDataExport(
                    ciphertext,
                    suggestedFilename: "encrypted.asc"
                )
            }
        } catch {
            operation.present(error: mapEncryptionError(error))
        }
    }

    func exportEncryptedFile() {
        guard configuration.allowsFileResultExport,
              let url = encryptedFileURL else {
            return
        }

        guard FileManager.default.fileExists(atPath: url.path) else {
            operation.present(
                error: .encryptionFailed(
                    reason: String(
                        localized: "fileEncrypt.readFailed",
                        defaultValue: "Could not read encrypted file"
                    )
                )
            )
            return
        }

        let suggestedFilename = (selectedFileName ?? "file") + ".gpg"

        if configuration.outputInterceptionPolicy.interceptFileExport?(
            url,
            suggestedFilename,
            .ciphertext
        ) != true {
            exportController.prepareFileExport(
                fileURL: url,
                suggestedFilename: suggestedFilename
            )
        }
    }

    func dismissError() {
        operation.dismissError()
    }

    func dismissClipboardNotice(disableFutureNotices: Bool = false) {
        operation.dismissClipboardNotice(
            disableFutureNoticesIn: disableFutureNotices ? appConfiguration : nil
        )
    }

    func finishExport() {
        exportController.finish()
    }

    func handleExportError(_ error: Error) {
        operation.present(error: mapEncryptionError(error))
    }

    private func performEncrypt() {
        switch encryptMode {
        case .text:
            encryptText()
        case .file:
            encryptFile()
        }
    }

    private func mapEncryptionError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .encryptionFailed(reason: $0) }
    }
}
