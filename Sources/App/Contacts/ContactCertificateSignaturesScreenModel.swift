import Foundation
import UniformTypeIdentifiers

@MainActor
@Observable
final class ContactCertificateSignaturesScreenModel {
    enum Mode: String, CaseIterable, Identifiable {
        case directKeyVerify
        case userIdBindingVerify
        case certifyUserId

        var id: String { rawValue }
    }

    enum LoadState {
        case idle
        case loading
        case loaded
        case failed
    }

    enum ActiveOperation: Equatable {
        case directKeyVerify
        case userIdBindingVerify
        case certifyUserId
    }

    typealias SelectionCatalogAction = @MainActor (Data) async throws -> CertificateSelectionCatalog
    typealias VerifyDirectKeyAction = @MainActor (Data, Data) async throws -> CertificateSignatureVerification
    typealias VerifyUserIdBindingAction = @MainActor (
        Data,
        Data,
        UserIdSelectionOption
    ) async throws -> CertificateSignatureVerification
    typealias GenerateArmoredCertificationAction = @MainActor (
        String,
        Data,
        UserIdSelectionOption,
        CertificationKind
    ) async throws -> Data
    typealias SignatureFileImportAction = @MainActor (URL) throws -> (data: Data, text: String?)

    private static let certificationKinds: [CertificationKind] = [
        .generic,
        .persona,
        .casual,
        .positive,
    ]

    let fingerprint: String
    let configuration: ContactCertificateSignaturesView.Configuration
    let exportController: FileExportController

    private let contactService: ContactService
    private let keyManagement: KeyManagementService
    private let certificateSignatureService: CertificateSignatureService
    private let selectionCatalogAction: SelectionCatalogAction
    private let verifyDirectKeyAction: VerifyDirectKeyAction
    private let verifyUserIdBindingAction: VerifyUserIdBindingAction
    private let generateArmoredCertificationAction: GenerateArmoredCertificationAction
    private let signatureFileImportAction: SignatureFileImportAction

    private var catalogLoadTask: Task<Void, Never>?
    private var catalogLoadGeneration: UInt64 = 0
    private var operationTask: Task<Void, Never>?
    private var operationGeneration: UInt64 = 0

    private(set) var loadState: LoadState = .idle
    private(set) var catalog: CertificateSelectionCatalog?
    private(set) var loadError: CypherAirError?
    private(set) var activeOperation: ActiveOperation?

    var mode: Mode = .directKeyVerify
    var signatureInput = ""
    var importedSignature = ImportedTextInputState()
    var showFileImporter = false
    var selectedUserId: UserIdSelectionOption?
    var selectedSignerFingerprint: String?
    var selectedCertificationKind: CertificationKind = .generic
    var verification: CertificateSignatureVerification?
    var error: CypherAirError?
    var showError = false

    init(
        fingerprint: String,
        contactService: ContactService,
        keyManagement: KeyManagementService,
        certificateSignatureService: CertificateSignatureService,
        configuration: ContactCertificateSignaturesView.Configuration = .default,
        exportController: FileExportController = FileExportController(),
        selectionCatalogAction: SelectionCatalogAction? = nil,
        verifyDirectKeyAction: VerifyDirectKeyAction? = nil,
        verifyUserIdBindingAction: VerifyUserIdBindingAction? = nil,
        generateArmoredCertificationAction: GenerateArmoredCertificationAction? = nil,
        signatureFileImportAction: SignatureFileImportAction? = nil
    ) {
        self.fingerprint = fingerprint
        self.contactService = contactService
        self.keyManagement = keyManagement
        self.certificateSignatureService = certificateSignatureService
        self.configuration = configuration
        self.exportController = exportController
        self.selectionCatalogAction = selectionCatalogAction ?? { targetCert in
            try certificateSignatureService.selectionCatalog(targetCert: targetCert)
        }
        self.verifyDirectKeyAction = verifyDirectKeyAction ?? { signature, targetCert in
            try await certificateSignatureService.verifyDirectKeySignature(
                signature: signature,
                targetCert: targetCert
            )
        }
        self.verifyUserIdBindingAction = verifyUserIdBindingAction ?? {
            signature,
            targetCert,
            selectedUserId in
            try await certificateSignatureService.verifyUserIdBindingSignature(
                signature: signature,
                targetCert: targetCert,
                selectedUserId: selectedUserId
            )
        }
        self.generateArmoredCertificationAction = generateArmoredCertificationAction ?? {
            signerFingerprint,
            targetCert,
            selectedUserId,
            certificationKind in
            try await certificateSignatureService.generateArmoredUserIdCertification(
                signerFingerprint: signerFingerprint,
                targetCert: targetCert,
                selectedUserId: selectedUserId,
                certificationKind: certificationKind
            )
        }
        self.signatureFileImportAction = signatureFileImportAction ?? { url in
            let data = try SecurityScopedFileAccess.withAccess(
                to: url,
                failure: .fileIoError(
                    reason: String(
                        localized: "contactcertsig.import.failed",
                        defaultValue: "Could not read signature file."
                    )
                )
            ) {
                try Data(contentsOf: url)
            }

            return (data, String(data: data, encoding: .utf8))
        }
    }

    var contact: Contact? {
        contactService.availableContact(forFingerprint: fingerprint)
    }

    var contactsAvailability: ContactsAvailability {
        contactService.contactsAvailability
    }

    var userIds: [UserIdSelectionOption] {
        catalog?.userIds ?? []
    }

    var signers: [PGPKeyIdentity] {
        keyManagement.keys
    }

    var certificationKinds: [CertificationKind] {
        Self.certificationKinds
    }

    var selectedSigner: PGPKeyIdentity? {
        guard let selectedSignerFingerprint else { return nil }
        return signers.first(where: { $0.fingerprint == selectedSignerFingerprint })
    }

    var signatureFileName: String? {
        importedSignature.fileName
    }

    var allowedImportContentTypes: [UTType] {
        [
            UTType(filenameExtension: "asc") ?? .plainText,
            UTType(filenameExtension: "sig") ?? .data,
            .plainText,
            .data,
        ]
    }

    var isLoading: Bool {
        if case .loading = loadState {
            return true
        }
        return false
    }

    var isOperationLocked: Bool {
        activeOperation != nil || exportController.isPresented
    }

    var canVerifyDirectKey: Bool {
        currentSignatureData != nil && !isLoading && !isOperationLocked
    }

    var canVerifyUserIdBinding: Bool {
        currentSignatureData != nil
            && selectedUserId != nil
            && !isLoading
            && !isOperationLocked
    }

    var canCertifyUserId: Bool {
        selectedSigner != nil
            && selectedUserId != nil
            && !isLoading
            && !isOperationLocked
    }

    func setMode(_ newMode: Mode) {
        guard !isOperationLocked, mode != newMode else {
            return
        }

        mode = newMode
        invalidateVerification()
    }

    func setSignatureInput(_ newValue: String) {
        guard newValue != signatureInput else {
            return
        }

        signatureInput = newValue
        _ = importedSignature.invalidateIfEditedTextDiffers(newValue)
        invalidateVerification()
    }

    func requestSignatureFileImport() {
        guard !isOperationLocked else {
            return
        }

        showFileImporter = true
    }

    func handleImportedFile(_ url: URL) {
        do {
            let loadedFile = try signatureFileImportAction(url)
            let visibleText = loadedFile.text ?? ""
            importedSignature.setImportedFile(
                data: loadedFile.data,
                fileName: url.lastPathComponent,
                text: visibleText
            )
            signatureInput = visibleText
            invalidateVerification()
        } catch {
            presentMappedError(error)
        }
    }

    func clearImportedSignature() {
        importedSignature.clear()
        signatureInput = ""
        invalidateVerification()
    }

    func clearTransientInput() {
        invalidateAsyncWork()
        importedSignature.clear()
        signatureInput = ""
        verification = nil
        showFileImporter = false
        exportController.finish()
    }

    func loadIfNeeded() {
        guard case .idle = loadState else {
            return
        }

        loadCatalog()
    }

    func retry() {
        guard !isLoading else {
            return
        }

        catalog = nil
        loadError = nil
        selectedUserId = nil
        loadCatalog()
    }

    func selectUserId(_ userId: UserIdSelectionOption) {
        guard !isOperationLocked else {
            return
        }

        selectedUserId = userId
        invalidateVerification()
    }

    func selectSigner(_ fingerprint: String?) {
        guard !isOperationLocked else {
            return
        }

        selectedSignerFingerprint = fingerprint
        invalidateVerification()
    }

    func selectCertificationKind(_ kind: CertificationKind) {
        guard !isOperationLocked else {
            return
        }

        selectedCertificationKind = kind
        invalidateVerification()
    }

    func verifyDirectKey() {
        guard let contact, let signature = currentSignatureData else {
            return
        }

        startOperation(.directKeyVerify) {
            let verification = try await self.verifyDirectKeyAction(signature, contact.publicKeyData)
            return (verification, nil, nil)
        }
    }

    func verifyUserIdBinding() {
        guard let contact,
              let selectedUserId,
              let signature = currentSignatureData else {
            return
        }

        startOperation(.userIdBindingVerify) {
            let verification = try await self.verifyUserIdBindingAction(
                signature,
                contact.publicKeyData,
                selectedUserId
            )
            return (verification, nil, nil)
        }
    }

    func certifyUserId() {
        guard let contact,
              let selectedUserId,
              let selectedSigner else {
            return
        }

        let exportFilename = certificationExportFilename(
            signer: selectedSigner,
            userId: selectedUserId
        )

        startOperation(.certifyUserId) {
            let armoredCertification = try await self.generateArmoredCertificationAction(
                selectedSigner.fingerprint,
                contact.publicKeyData,
                selectedUserId,
                self.selectedCertificationKind
            )
            try Task.checkCancellation()
            let verification = try await self.verifyUserIdBindingAction(
                armoredCertification,
                contact.publicKeyData,
                selectedUserId
            )
            return (verification, armoredCertification, exportFilename)
        }
    }

    func finishExport() {
        exportController.finish()
    }

    func handleExportError(_ error: Error) {
        presentMappedError(error)
    }

    func dismissError() {
        error = nil
        showError = false
    }

    func handleDisappear() {
        catalogLoadGeneration &+= 1
        catalogLoadTask?.cancel()
        catalogLoadTask = nil

        if isLoading {
            loadState = .idle
        }

        operationGeneration &+= 1
        operationTask?.cancel()
        operationTask = nil
        activeOperation = nil
        showFileImporter = false
        exportController.finish()
    }

    func title(for mode: Mode) -> String {
        switch mode {
        case .directKeyVerify:
            String(
                localized: "contactcertsig.mode.direct",
                defaultValue: "Direct Key Verify"
            )
        case .userIdBindingVerify:
            String(
                localized: "contactcertsig.mode.binding",
                defaultValue: "User ID Binding Verify"
            )
        case .certifyUserId:
            String(
                localized: "contactcertsig.mode.certify",
                defaultValue: "Certify User ID"
            )
        }
    }

    func title(for kind: CertificationKind) -> String {
        switch kind {
        case .generic:
            String(localized: "contactcertsig.kind.generic", defaultValue: "Generic")
        case .persona:
            String(localized: "contactcertsig.kind.persona", defaultValue: "Persona")
        case .casual:
            String(localized: "contactcertsig.kind.casual", defaultValue: "Casual")
        case .positive:
            String(localized: "contactcertsig.kind.positive", defaultValue: "Positive")
        }
    }

    private var currentSignatureData: Data? {
        if let imported = importedSignature.rawData {
            return imported
        }

        guard !signatureInput.isEmpty else {
            return nil
        }

        return Data(signatureInput.utf8)
    }

    private func loadCatalog() {
        guard contactsAvailability.isAvailable else {
            catalog = nil
            loadError = .contactsUnavailable(contactsAvailability)
            loadState = .failed
            return
        }

        guard let targetCert = contact?.publicKeyData else {
            loadState = .loaded
            return
        }

        catalogLoadTask?.cancel()
        catalogLoadGeneration &+= 1
        let generation = catalogLoadGeneration
        loadState = .loading
        let selectionCatalogAction = self.selectionCatalogAction

        catalogLoadTask = Task { [weak self, generation] in
            defer {
                if let self, generation == self.catalogLoadGeneration {
                    self.catalogLoadTask = nil
                }
            }

            do {
                await Task.yield()
                let catalog = try await selectionCatalogAction(targetCert)
                try Task.checkCancellation()

                guard let self, generation == self.catalogLoadGeneration else {
                    return
                }

                self.catalog = catalog
                self.loadError = nil
                self.loadState = .loaded
                self.ensureDefaultSignerSelection()
            } catch {
                guard let self else {
                    return
                }
                guard !Self.shouldIgnore(error), generation == self.catalogLoadGeneration else {
                    return
                }

                self.catalog = nil
                self.loadError = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
                self.loadState = .failed
            }
        }
    }

    private func startOperation(
        _ operation: ActiveOperation,
        work: @escaping @MainActor () async throws -> (
            CertificateSignatureVerification,
            Data?,
            String?
        )
    ) {
        operationTask?.cancel()
        operationGeneration &+= 1
        let generation = operationGeneration
        activeOperation = operation
        invalidateVerification()

        operationTask = Task { [weak self, generation] in
            defer {
                if let self, generation == self.operationGeneration {
                    self.activeOperation = nil
                    self.operationTask = nil
                }
            }

            do {
                let (verification, exportData, exportFilename) = try await work()
                try Task.checkCancellation()

                guard let self, generation == self.operationGeneration else {
                    return
                }

                self.verification = verification

                if let exportData, let exportFilename {
                    try self.prepareExport(exportData, filename: exportFilename)
                }
            } catch {
                guard let self else {
                    return
                }
                guard !Self.shouldIgnore(error), generation == self.operationGeneration else {
                    return
                }

                self.presentMappedError(error)
            }
        }
    }

    private func prepareExport(_ data: Data, filename: String) throws {
        if try configuration.outputInterceptionPolicy.interceptDataExport?(
            data,
            filename,
            .generic
        ) != true {
            try exportController.prepareDataExport(data, suggestedFilename: filename)
        }
    }

    private func invalidateAsyncWork() {
        catalogLoadGeneration &+= 1
        catalogLoadTask?.cancel()
        catalogLoadTask = nil
        if case .loading = loadState {
            loadState = .idle
        }

        operationGeneration &+= 1
        operationTask?.cancel()
        operationTask = nil
        activeOperation = nil
    }

    private func certificationExportFilename(
        signer: PGPKeyIdentity,
        userId: UserIdSelectionOption
    ) -> String {
        let contactShortKeyId = contact?.shortKeyId ?? "contact"
        return "userid-certification-\(contactShortKeyId)-\(userId.occurrenceIndex + 1)-by-\(signer.shortKeyId).asc"
    }

    private func ensureDefaultSignerSelection() {
        guard selectedSignerFingerprint == nil else {
            return
        }

        if let defaultKey = keyManagement.defaultKey {
            selectedSignerFingerprint = defaultKey.fingerprint
        } else if let firstKey = signers.first {
            selectedSignerFingerprint = firstKey.fingerprint
        }
    }

    private func invalidateVerification() {
        verification = nil
    }

    private func presentMappedError(_ error: Error) {
        self.error = CypherAirError.from(error) { .fileIoError(reason: $0) }
        showError = true
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
