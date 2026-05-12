import Foundation

struct AddContactScreenHostActions {
    let presentImportConfirmation: @MainActor (ImportConfirmationRequest) -> Void
    let dismissPresentedImportConfirmation: @MainActor () -> Void
    let completeImportedContact: @MainActor (Contact) -> Void
}

@MainActor
@Observable
final class AddContactScreenModel {
    typealias InspectKeyDataAction = @MainActor (Data) throws -> PublicKeyImportInspection
    typealias LoadFileAction = @MainActor (URL) throws -> LoadedPublicKeyFile
    typealias QRPhotoKeyDataLoader = @MainActor () async throws -> Data

    private(set) var configuration: AddContactView.Configuration

    private let importWorkflow: ContactImportWorkflow
    private let inspectKeyDataAction: InspectKeyDataAction
    private let loadFileAction: LoadFileAction
    private var qrProcessingTask: Task<Void, Never>?
    private var qrProcessingGeneration: UInt64 = 0
    private var fileImportRequestGate = FileImportRequestGate()

    var importMode: AddContactView.ImportMode = .paste
    var armoredText = ""
    var error: CypherAirError?
    var showError = false
    var pendingKeyUpdateRequest: ContactKeyUpdateConfirmationRequest?
    var showKeyUpdateAlert = false
    var isProcessingQR = false
    var showFileImporter = false
    var importedKeyData: Data?
    var importedFileName: String?

    init(
        importLoader: PublicKeyImportLoader,
        importWorkflow: ContactImportWorkflow,
        configuration: AddContactView.Configuration,
        inspectKeyDataAction: InspectKeyDataAction? = nil,
        loadFileAction: LoadFileAction? = nil
    ) {
        self.importWorkflow = importWorkflow
        self.configuration = configuration
        self.inspectKeyDataAction = inspectKeyDataAction ?? { keyData in
            try importLoader.inspect(keyData: keyData)
        }
        self.loadFileAction = loadFileAction ?? { url in
            try importLoader.loadFromFile(
                url: url,
                failure: .invalidKeyData(
                    reason: String(
                        localized: "addcontact.file.readFailed",
                        defaultValue: "Could not read key file"
                    )
                )
            )
        }
    }

    var addButtonDisabled: Bool {
        switch importMode {
        case .paste:
            armoredText.isEmpty
        case .qrPhoto:
            (armoredText.isEmpty && importedKeyData == nil) || isProcessingQR
        case .file:
            armoredText.isEmpty && importedKeyData == nil
        }
    }

    var fileImportRequestToken: FileImportRequestGate.Token? {
        fileImportRequestGate.currentToken
    }

    func handleAppear() {
        let defaultImportMode = configuration.allowedImportModes.first ?? .paste
        setImportMode(defaultImportMode)

        if armoredText.isEmpty,
           let prefilledArmoredText = configuration.prefilledArmoredText {
            armoredText = prefilledArmoredText
        }
    }

    func handleDisappear() {
        fileImportRequestGate.invalidate()
    }

    func updateConfiguration(_ configuration: AddContactView.Configuration) {
        let previousConfiguration = self.configuration
        self.configuration = configuration

        if previousConfiguration.allowedImportModes != configuration.allowedImportModes,
           !configuration.allowedImportModes.contains(importMode) {
            setImportMode(configuration.allowedImportModes.first ?? .paste)
        }
    }

    func setImportMode(_ newValue: AddContactView.ImportMode) {
        guard importMode != newValue else {
            return
        }

        importMode = newValue
        fileImportRequestGate.invalidate()
        clearImportedKeyData()
    }

    func requestFileImport() {
        fileImportRequestGate.begin()
        showFileImporter = true
    }

    func clearImportedFile() {
        fileImportRequestGate.invalidate()
        clearImportedKeyData()
    }

    func dismissError() {
        error = nil
        showError = false
    }

    func dismissPendingKeyUpdateRequest() {
        pendingKeyUpdateRequest = nil
        showKeyUpdateAlert = false
    }

    func confirmPendingKeyUpdate() {
        guard let pendingKeyUpdateRequest else {
            return
        }

        dismissPendingKeyUpdateRequest()
        pendingKeyUpdateRequest.onConfirm()
    }

    func cancelPendingKeyUpdate() {
        guard let pendingKeyUpdateRequest else {
            return
        }

        dismissPendingKeyUpdateRequest()
        pendingKeyUpdateRequest.onCancel()
    }

    func addContact(actions: AddContactScreenHostActions) {
        do {
            let keyData = importedKeyData ?? Data(armoredText.utf8)
            let inspection = try inspectKeyDataAction(keyData)
            let request = importWorkflow.makeImportConfirmationRequest(
                inspection: inspection,
                allowsUnverifiedImport: configuration.verificationPolicy == .allowUnverified,
                onSuccess: { contact in
                    actions.dismissPresentedImportConfirmation()
                    actions.completeImportedContact(contact)
                },
                onReplaceRequested: { [self] request in
                    actions.dismissPresentedImportConfirmation()
                    self.pendingKeyUpdateRequest = request
                    self.showKeyUpdateAlert = true
                },
                onFailure: { [self] importError in
                    self.error = importError
                    actions.dismissPresentedImportConfirmation()
                    self.showError = true
                }
            )

            actions.presentImportConfirmation(request)
        } catch {
            self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            showError = true
        }
    }

    func processSelectedQRPhoto(loadKeyData: @escaping QRPhotoKeyDataLoader) {
        qrProcessingTask?.cancel()
        qrProcessingGeneration &+= 1
        let generation = qrProcessingGeneration
        isProcessingQR = true
        qrProcessingTask = Task { @MainActor [weak self, generation] in
            defer {
                if let self, generation == self.qrProcessingGeneration {
                    self.isProcessingQR = false
                    self.qrProcessingTask = nil
                }
            }

            do {
                let publicKeyData = try await loadKeyData()
                try Task.checkCancellation()
                guard let self, generation == self.qrProcessingGeneration else {
                    return
                }
                if let armoredString = String(data: publicKeyData, encoding: .utf8) {
                    self.armoredText = armoredString
                    self.clearImportedKeyData()
                } else {
                    self.clearImportedKeyData()
                    self.importedKeyData = publicKeyData
                    self.importedFileName = String(
                        localized: "addcontact.qr.binaryKey",
                        defaultValue: "Binary key from QR"
                    )
                    self.armoredText = ""
                }
            } catch {
                guard let self else {
                    return
                }
                guard !Self.shouldIgnore(error), generation == self.qrProcessingGeneration else {
                    return
                }
                self.error = CypherAirError.from(error) { _ in .invalidQRCode }
                self.showError = true
            }
        }
    }

    func loadFileContents(from url: URL) {
        do {
            let loadedFile = try loadFileAction(url)

            if let armoredString = loadedFile.text {
                armoredText = armoredString
                clearImportedKeyData()
            } else {
                armoredText = ""
                clearImportedKeyData()
                importedKeyData = loadedFile.data
            }
            importedFileName = loadedFile.fileName
        } catch let error as CypherAirError {
            self.error = error
            showError = true
        } catch {
            self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            showError = true
        }
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

    func clearTransientInput() {
        qrProcessingTask?.cancel()
        qrProcessingGeneration &+= 1
        fileImportRequestGate.invalidate()
        qrProcessingTask = nil
        isProcessingQR = false
        armoredText = ""
        clearImportedKeyData()
        pendingKeyUpdateRequest = nil
        showKeyUpdateAlert = false
        showFileImporter = false
        error = nil
        showError = false
    }

    private func clearImportedKeyData() {
        if let count = importedKeyData?.count {
            importedKeyData?.resetBytes(in: 0..<count)
        }
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
        if let pgpError = error as? PgpError,
           case .OperationCancelled = pgpError {
            return true
        }
        return false
    }
}
