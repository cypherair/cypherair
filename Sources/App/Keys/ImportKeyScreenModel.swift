import Foundation

@MainActor
@Observable
final class ImportKeyScreenModel {
    struct ImportedKeyFile {
        let data: Data
        let text: String?
        let fileName: String
    }

    typealias ImportKeyAction = @MainActor (Data, String) async throws -> PGPKeyIdentity
    typealias LoadFileAction = @MainActor (URL) throws -> ImportedKeyFile

    private let importKeyAction: ImportKeyAction
    private let loadFileAction: LoadFileAction
    private let dismissAction: @MainActor () -> Void
    private var fileImportRequestGate = FileImportRequestGate()
    private var importTask: Task<Void, Never>?
    private var importToken: UInt64 = 0

    var armoredText = ""
    var passphrase = ""
    var isImporting = false
    var error: CypherAirError?
    var showError = false
    var showFileImporter = false
    var importedKeyData: Data?
    var importedFileName: String?

    init(
        keyManagement: KeyManagementService,
        dismissAction: @escaping @MainActor () -> Void,
        importKeyAction: ImportKeyAction? = nil,
        loadFileAction: LoadFileAction? = nil
    ) {
        self.dismissAction = dismissAction
        self.importKeyAction = importKeyAction ?? { data, passphrase in
            try await keyManagement.importKey(
                armoredData: data,
                passphrase: passphrase
            )
        }
        self.loadFileAction = loadFileAction ?? { url in
            let data = try SecurityScopedFileAccess.withAccess(
                to: url,
                failure: .invalidKeyData(
                    reason: String(
                        localized: "import.file.readFailed",
                        defaultValue: "Could not read key file"
                    )
                )
            ) {
                try Data(contentsOf: url)
            }

            return ImportedKeyFile(
                data: data,
                text: String(data: data, encoding: .utf8),
                fileName: url.lastPathComponent
            )
        }
    }

    var importButtonDisabled: Bool {
        (armoredText.isEmpty && importedKeyData == nil) || passphrase.isEmpty || isImporting
    }

    var fileImportRequestToken: FileImportRequestGate.Token? {
        fileImportRequestGate.currentToken
    }

    func requestFileImport() {
        fileImportRequestGate.begin()
        showFileImporter = true
    }

    func clearImportedFile() {
        fileImportRequestGate.invalidate()
        clearImportedKeyData()
    }

    func handleFileImporterResult(
        _ result: Result<[URL], Error>,
        token: FileImportRequestGate.Token?
    ) {
        guard fileImportRequestGate.consumeIfCurrent(token) else {
            return
        }

        if case .success(let urls) = result, let url = urls.first {
            loadFileContents(from: url)
        }
    }

    func loadFileContents(from url: URL) {
        do {
            let loadedFile = try loadFileAction(url)

            if let text = loadedFile.text {
                clearImportedKeyData()
                armoredText = text
            } else {
                clearImportedKeyData()
                importedKeyData = loadedFile.data
                importedFileName = loadedFile.fileName
                armoredText = ""
            }
        } catch {
            self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            showError = true
        }
    }

    func importKey() {
        importTask?.cancel()
        importToken &+= 1
        let token = importToken
        isImporting = true
        error = nil
        showError = false

        let importedKeyDataSnapshot = importedKeyData
        let armoredTextSnapshot = armoredText
        let passphraseSnapshot = passphrase

        importTask = Task { @MainActor [weak self, token] in
            guard let self else { return }
            defer {
                if token == self.importToken {
                    self.isImporting = false
                    self.importTask = nil
                }
            }

            do {
                var data = importedKeyDataSnapshot ?? Data(armoredTextSnapshot.utf8)
                defer {
                    data.resetBytes(in: 0..<data.count)
                }
                _ = try await self.importKeyAction(data, passphraseSnapshot)
                try Task.checkCancellation()
                guard token == self.importToken else {
                    return
                }

                clearTransientInput()
                dismissAction()
            } catch {
                guard !Self.shouldIgnore(error), token == self.importToken else {
                    return
                }
                self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
                self.showError = true
            }
        }
    }

    func handleDisappear() {
        cancelImportAndClearTransientInput()
    }

    func handleContentClearGenerationChange() {
        cancelImportAndClearTransientInput()
    }

    func dismissError() {
        error = nil
        showError = false
    }

    func clearTransientInput() {
        armoredText = ""
        passphrase = ""
        showFileImporter = false
        fileImportRequestGate.invalidate()
        clearImportedKeyData()
    }

    private func cancelImportAndClearTransientInput() {
        importTask?.cancel()
        importToken &+= 1
        importTask = nil
        isImporting = false
        clearTransientInput()
    }

    private func clearImportedKeyData() {
        importedKeyData?.resetBytes(in: 0..<(importedKeyData?.count ?? 0))
        importedKeyData = nil
        importedFileName = nil
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
