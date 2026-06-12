import Foundation

@MainActor
@Observable
final class BackupKeyScreenModel {
    typealias ExportBackupAction = @MainActor (String, String) async throws -> Data
    typealias ConfirmBackupExportedAction = @MainActor (String) -> Void

    let fingerprint: String
    let configuration: BackupKeyView.Configuration

    private let keyManagement: KeyManagementService
    private let exportBackupAction: ExportBackupAction
    private let confirmBackupExportedAction: ConfirmBackupExportedAction
    private var exportTask: Task<Void, Never>?
    private var exportToken: UInt64 = 0
    private var exportedDataToken: UInt64?

    var passphrase = ""
    var passphraseConfirm = ""
    var isExporting = false
    var exportedData: Data?
    var error: CypherAirError?
    var showError = false
    var showFileExporter = false

    init(
        fingerprint: String,
        keyManagement: KeyManagementService,
        configuration: BackupKeyView.Configuration,
        exportBackupAction: ExportBackupAction? = nil,
        confirmBackupExportedAction: ConfirmBackupExportedAction? = nil
    ) {
        self.fingerprint = fingerprint
        self.configuration = configuration
        self.keyManagement = keyManagement
        self.exportBackupAction = exportBackupAction ?? { fingerprint, passphrase in
            try await keyManagement.exportKeyBackupData(
                fingerprint: fingerprint,
                passphrase: passphrase
            )
        }
        self.confirmBackupExportedAction = confirmBackupExportedAction ?? { fingerprint in
            keyManagement.confirmKeyBackupExported(fingerprint: fingerprint)
        }
    }

    /// Device-bound Secure Enclave keys have no exportable private material.
    /// The route is not offered for them in UI; this is defense-in-depth for
    /// stale navigation paths (the service layer also fails closed). Computed,
    /// not captured at init, so late key loads cannot read as software custody.
    var isDeviceBound: Bool {
        keyManagement.keys.first { $0.fingerprint == fingerprint }?
            .privateKeyCustodyKind == .appleSecureEnclavePrivateOperations
    }

    var exportButtonDisabled: Bool {
        passphrase.isEmpty || passphrase != passphraseConfirm || isExporting
    }

    var passphrasesMismatch: Bool {
        !passphrase.isEmpty && passphrase != passphraseConfirm
    }

    var exportedString: String? {
        guard let exportedData else {
            return nil
        }
        return String(data: exportedData, encoding: .utf8)
    }

    var defaultFilename: String {
        "\(fingerprint.prefix(16)).asc"
    }

    func exportBackup() {
        exportTask?.cancel()
        exportToken &+= 1
        let token = exportToken
        isExporting = true
        error = nil
        showError = false

        let fingerprint = self.fingerprint
        let passphraseSnapshot = passphrase

        exportTask = Task { @MainActor [weak self, token] in
            guard let self else { return }
            defer {
                if token == self.exportToken {
                    self.isExporting = false
                    self.exportTask = nil
                }
            }

            do {
                var data = try await self.exportBackupAction(fingerprint, passphraseSnapshot)
                var didHandOffData = false
                defer {
                    if !didHandOffData {
                        data.resetBytes(in: 0..<data.count)
                    }
                }
                try Task.checkCancellation()
                guard token == self.exportToken else {
                    return
                }

                self.exportedData = data
                self.exportedDataToken = token
                didHandOffData = true

                if self.configuration.resultPresentation == .inlinePreview {
                    self.configuration.onExported?(data)
                    self.confirmBackupExportedAction(fingerprint)
                }

                self.passphrase = ""
                self.passphraseConfirm = ""
            } catch {
                guard !Self.shouldIgnore(error), token == self.exportToken else {
                    return
                }
                self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
                self.showError = true
            }
        }
    }

    func handleFileExporterResult(_ result: Result<URL, Error>) {
        switch result {
        case .success:
            guard exportedDataToken == exportToken,
                  var exportedData = consumeExportedData() else {
                return
            }
            defer {
                exportedData.zeroize()
            }
            configuration.onExported?(exportedData)
            confirmBackupExportedAction(fingerprint)
        case .failure(let exportError):
            guard exportedDataToken == exportToken else {
                return
            }
            clearExportedData()
            error = CypherAirError.from(exportError) { .encryptionFailed(reason: $0) }
            showError = true
        }
    }

    func handleDisappear() {
        cancelExportAndClearTransientInput()
    }

    func handleContentClearGenerationChange() {
        cancelExportAndClearTransientInput()
    }

    func dismissError() {
        error = nil
        showError = false
    }

    func clearTransientInput() {
        passphrase = ""
        passphraseConfirm = ""
        showFileExporter = false
        clearExportedData()
    }

    private func cancelExportAndClearTransientInput() {
        exportTask?.cancel()
        exportToken &+= 1
        exportTask = nil
        isExporting = false
        clearTransientInput()
    }

    private func clearExportedData() {
        if let count = exportedData?.count {
            exportedData?.resetBytes(in: 0..<count)
        }
        exportedData = nil
        exportedDataToken = nil
    }

    private func consumeExportedData() -> Data? {
        guard let data = exportedData else {
            exportedDataToken = nil
            return nil
        }
        exportedData = nil
        exportedDataToken = nil
        return data
    }

    private static func shouldIgnore(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let cypherAirError = error as? CypherAirError,
           case .operationCancelled = cypherAirError {
            return true
        }
        return false
    }
}
