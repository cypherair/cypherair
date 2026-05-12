import Foundation
import UniformTypeIdentifiers

struct ContactCertificationDetailsConfiguration {
    var outputInterceptionPolicy: OutputInterceptionPolicy = .passthrough

    static let `default` = ContactCertificationDetailsConfiguration()
}

@MainActor
@Observable
final class ContactCertificationDetailsScreenModel {
    enum LoadState {
        case idle
        case loading
        case loaded
        case failed
    }

    enum ImportMode: String, CaseIterable, Identifiable {
        case userIdBinding
        case directKey

        var id: String { rawValue }
    }

    enum ActiveOperation: Equatable {
        case load
        case generateAndSave
        case verifyImport
        case savePending
        case exportArtifact(String)
    }

    typealias SelectionCatalogAction = @MainActor (Data) async throws -> CertificateSelectionCatalog
    typealias GenerateArmoredCertificationAction = @MainActor (
        String,
        Data,
        UserIdSelectionOption,
        CertificationKind
    ) async throws -> Data
    typealias ValidateUserIdArtifactAction = @MainActor (
        Data,
        ContactKeySummary,
        Data,
        UserIdSelectionOption,
        ContactCertificationArtifactSource,
        String?
    ) async throws -> ContactCertificationArtifactValidation
    typealias ValidateDirectKeyArtifactAction = @MainActor (
        Data,
        ContactKeySummary,
        Data,
        ContactCertificationArtifactSource,
        String?
    ) async throws -> ContactCertificationArtifactValidation
    typealias SaveArtifactAction = @MainActor (VerifiedContactCertificationArtifact) throws -> ContactCertificationArtifactReference
    typealias ExportArtifactAction = @MainActor (String) throws -> (data: Data, filename: String)
    typealias SignatureFileImportAction = @MainActor (URL) throws -> (data: Data, text: String?)

    private static let certificationKinds: [CertificationKind] = [
        .generic,
        .persona,
        .casual,
        .positive,
    ]

    let contactId: String
    let initialKeyId: String?
    let intent: ContactCertificationRouteIntent
    let configuration: ContactCertificationDetailsConfiguration
    let exportController: FileExportController

    private let contactService: ContactService
    private let keyManagement: KeyManagementService
    private let certificateSignatureService: CertificateSignatureService
    private let selectionCatalogAction: SelectionCatalogAction
    private let generateArmoredCertificationAction: GenerateArmoredCertificationAction
    private let validateUserIdArtifactAction: ValidateUserIdArtifactAction
    private let validateDirectKeyArtifactAction: ValidateDirectKeyArtifactAction
    private let saveArtifactAction: SaveArtifactAction
    private let exportArtifactAction: ExportArtifactAction
    private let signatureFileImportAction: SignatureFileImportAction

    private var loadTask: Task<Void, Never>?
    private var loadGeneration: UInt64 = 0
    private var operationTask: Task<Void, Never>?
    private var operationGeneration: UInt64 = 0

    private(set) var loadState: LoadState = .idle
    private(set) var catalog: CertificateSelectionCatalog?
    private(set) var loadError: CypherAirError?
    private(set) var activeOperation: ActiveOperation?
    private(set) var pendingArtifact: VerifiedContactCertificationArtifact?
    private(set) var verification: CertificateSignatureVerification?
    private(set) var lastSavedArtifact: ContactCertificationArtifactReference?

    var selectedKeyId: String?
    var selectedUserId: UserIdSelectionOption?
    var selectedSignerFingerprint: String?
    var selectedCertificationKind: CertificationKind = .generic
    var importMode: ImportMode = .userIdBinding
    var signatureInput = ""
    var importedSignature = ImportedTextInputState()
    var showFileImporter = false
    var error: CypherAirError?
    var showError = false

    init(
        contactId: String,
        initialKeyId: String?,
        intent: ContactCertificationRouteIntent,
        contactService: ContactService,
        keyManagement: KeyManagementService,
        certificateSignatureService: CertificateSignatureService,
        configuration: ContactCertificationDetailsConfiguration = .default,
        exportController: FileExportController = FileExportController(),
        selectionCatalogAction: SelectionCatalogAction? = nil,
        generateArmoredCertificationAction: GenerateArmoredCertificationAction? = nil,
        validateUserIdArtifactAction: ValidateUserIdArtifactAction? = nil,
        validateDirectKeyArtifactAction: ValidateDirectKeyArtifactAction? = nil,
        saveArtifactAction: SaveArtifactAction? = nil,
        exportArtifactAction: ExportArtifactAction? = nil,
        signatureFileImportAction: SignatureFileImportAction? = nil
    ) {
        self.contactId = contactId
        self.initialKeyId = initialKeyId
        self.intent = intent
        self.contactService = contactService
        self.keyManagement = keyManagement
        self.certificateSignatureService = certificateSignatureService
        self.configuration = configuration
        self.exportController = exportController
        self.selectionCatalogAction = selectionCatalogAction ?? { targetCert in
            try certificateSignatureService.selectionCatalog(targetCert: targetCert)
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
        self.validateUserIdArtifactAction = validateUserIdArtifactAction ?? {
            signature,
            targetKey,
            targetCert,
            selectedUserId,
            source,
            filename in
            try await certificateSignatureService.validateUserIdCertificationArtifact(
                signature: signature,
                targetKey: targetKey,
                targetCert: targetCert,
                selectedUserId: selectedUserId,
                source: source,
                exportFilename: filename
            )
        }
        self.validateDirectKeyArtifactAction = validateDirectKeyArtifactAction ?? {
            signature,
            targetKey,
            targetCert,
            source,
            filename in
            try await certificateSignatureService.validateDirectKeyCertificationArtifact(
                signature: signature,
                targetKey: targetKey,
                targetCert: targetCert,
                source: source,
                exportFilename: filename
            )
        }
        self.saveArtifactAction = saveArtifactAction ?? { artifact in
            try contactService.saveCertificationArtifact(artifact)
        }
        self.exportArtifactAction = exportArtifactAction ?? { artifactId in
            try contactService.exportCertificationArtifact(artifactId: artifactId)
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
        selectedKeyId = initialKeyId
        importMode = .userIdBinding
    }

    var contactsAvailability: ContactsAvailability {
        contactService.contactsAvailability
    }

    var contact: ContactIdentitySummary? {
        contactService.availableContactIdentity(forContactID: contactId)
    }

    var keys: [ContactKeySummary] {
        contact?.keys ?? []
    }

    var selectedKey: ContactKeySummary? {
        guard let selectedKeyId else {
            return nil
        }
        return keys.first { $0.keyId == selectedKeyId }
    }

    var selectedKeyRecord: ContactKeyRecord? {
        guard let selectedKeyId else {
            return nil
        }
        return contactService.availableContactKeyRecord(keyId: selectedKeyId)
    }

    var savedArtifacts: [ContactCertificationArtifactReference] {
        guard let selectedKeyId else {
            return []
        }
        return contactService.certificationArtifacts(for: selectedKeyId)
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
        guard let selectedSignerFingerprint else {
            return nil
        }
        return signers.first { $0.fingerprint == selectedSignerFingerprint }
    }

    var allowedImportContentTypes: [UTType] {
        [
            UTType(filenameExtension: "asc") ?? .plainText,
            UTType(filenameExtension: "sig") ?? .data,
            .plainText,
            .data,
        ]
    }

    var signatureFileName: String? {
        importedSignature.fileName
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

    var canGenerateAndSave: Bool {
        contactsAvailability.allowsProtectedCertificationPersistence &&
            selectedKeyRecord != nil &&
            selectedKey != nil &&
            selectedUserId != nil &&
            selectedSigner != nil &&
            !isLoading &&
            !isOperationLocked
    }

    var canVerifyImport: Bool {
        guard currentSignatureData != nil,
              selectedKey != nil,
              selectedKeyRecord != nil,
              !isLoading,
              !isOperationLocked else {
            return false
        }
        return importMode == .directKey || selectedUserId != nil
    }

    var canSavePendingArtifact: Bool {
        contactsAvailability.allowsProtectedCertificationPersistence &&
            pendingArtifact != nil &&
            !isOperationLocked
    }

    func loadIfNeeded() {
        guard case .idle = loadState else {
            return
        }
        ensureDefaultKeySelection()
        loadCatalog()
    }

    func handleContactsAvailabilityChange(
        from previousAvailability: ContactsAvailability,
        to currentAvailability: ContactsAvailability
    ) {
        guard !previousAvailability.isAvailable,
              currentAvailability.isAvailable else {
            return
        }

        switch loadState {
        case .idle:
            loadIfNeeded()
        case .failed:
            guard case .some(.contactsUnavailable) = loadError else {
                return
            }
            loadError = nil
            loadState = .idle
            loadIfNeeded()
        case .loading, .loaded:
            break
        }
    }

    func retry() {
        guard !isOperationLocked else {
            return
        }
        catalog = nil
        loadError = nil
        loadCatalog()
    }

    func selectKey(_ keyId: String?) {
        guard !isOperationLocked, selectedKeyId != keyId else {
            return
        }
        selectedKeyId = keyId
        selectedUserId = nil
        catalog = nil
        invalidatePreview()
        loadCatalog()
    }

    func selectUserId(_ userId: UserIdSelectionOption?) {
        guard !isOperationLocked else {
            return
        }
        selectedUserId = userId
        invalidatePreview()
    }

    func selectSigner(_ fingerprint: String?) {
        guard !isOperationLocked else {
            return
        }
        selectedSignerFingerprint = fingerprint
    }

    func selectCertificationKind(_ kind: CertificationKind) {
        guard !isOperationLocked else {
            return
        }
        selectedCertificationKind = kind
    }

    func selectImportMode(_ mode: ImportMode) {
        guard !isOperationLocked else {
            return
        }
        importMode = mode
        invalidatePreview()
    }

    func setSignatureInput(_ newValue: String) {
        guard signatureInput != newValue else {
            return
        }
        signatureInput = newValue
        _ = importedSignature.invalidateIfEditedTextDiffers(newValue)
        invalidatePreview()
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
            invalidatePreview()
        } catch {
            presentMappedError(error)
        }
    }

    func clearImportedSignature() {
        importedSignature.clear()
        signatureInput = ""
        invalidatePreview()
    }

    func clearTransientInput() {
        invalidateAsyncWork(resetLoadingState: true)
        importedSignature.clear()
        signatureInput = ""
        pendingArtifact = nil
        verification = nil
        showFileImporter = false
        exportController.finish()
    }

    func generateAndSaveCertification() {
        guard contactsAvailability.allowsProtectedCertificationPersistence else {
            return
        }
        guard let key = selectedKey,
              let keyRecord = selectedKeyRecord,
              let selectedUserId,
              let selectedSigner else {
            return
        }

        startOperation(.generateAndSave) { checkActive in
            let filename = self.certificationExportFilename(
                key: key,
                signer: selectedSigner,
                userId: selectedUserId
            )
            let armoredCertification = try await self.generateArmoredCertificationAction(
                selectedSigner.fingerprint,
                keyRecord.publicKeyData,
                selectedUserId,
                self.selectedCertificationKind
            )
            try checkActive()
            let validation = try await self.validateUserIdArtifactAction(
                armoredCertification,
                key,
                keyRecord.publicKeyData,
                selectedUserId,
                .generated,
                filename
            )
            try checkActive()
            guard let artifact = validation.artifact else {
                throw CypherAirError.invalidKeyData(
                    reason: String(
                        localized: "contactcertification.generated.invalid",
                        defaultValue: "The generated certification signature did not verify and was not saved."
                    )
                )
            }
            try checkActive()
            let saved = try self.saveArtifactAction(artifact)
            return (validation.verification, nil, saved)
        }
    }

    func verifyImportedSignature() {
        guard let signature = currentSignatureData,
              let key = selectedKey,
              let keyRecord = selectedKeyRecord else {
            return
        }

        startOperation(.verifyImport) { checkActive in
            let validation: ContactCertificationArtifactValidation
            switch self.importMode {
            case .directKey:
                validation = try await self.validateDirectKeyArtifactAction(
                    signature,
                    key,
                    keyRecord.publicKeyData,
                    .imported,
                    nil
                )
                try checkActive()
            case .userIdBinding:
                guard let selectedUserId = self.selectedUserId else {
                    throw CypherAirError.invalidKeyData(
                        reason: String(
                            localized: "contactcertification.import.userIdRequired",
                            defaultValue: "Choose the exact User ID before verifying this signature."
                        )
                    )
                }
                validation = try await self.validateUserIdArtifactAction(
                    signature,
                    key,
                    keyRecord.publicKeyData,
                    selectedUserId,
                    .imported,
                    nil
                )
                try checkActive()
            }
            return (validation.verification, validation.artifact, nil)
        }
    }

    func savePendingSignature() {
        guard contactsAvailability.allowsProtectedCertificationPersistence,
              let pendingArtifact else {
            return
        }

        startOperation(.savePending) { checkActive in
            try checkActive()
            let saved = try self.saveArtifactAction(pendingArtifact)
            return (self.verification, nil, saved)
        }
    }

    func exportArtifact(_ artifact: ContactCertificationArtifactReference) {
        startOperation(.exportArtifact(artifact.artifactId)) { checkActive in
            let export = try self.exportArtifactAction(artifact.artifactId)
            try checkActive()
            try self.prepareExport(export.data, filename: export.filename)
            return (self.verification, self.pendingArtifact, self.lastSavedArtifact)
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
        invalidateAsyncWork(resetLoadingState: true)
        showFileImporter = false
        exportController.finish()
    }

    private func invalidateAsyncWork(resetLoadingState: Bool) {
        loadGeneration &+= 1
        loadTask?.cancel()
        loadTask = nil
        if resetLoadingState, isLoading {
            loadState = .idle
        }

        operationGeneration &+= 1
        operationTask?.cancel()
        operationTask = nil
        activeOperation = nil
    }

    func title(for importMode: ImportMode) -> String {
        switch importMode {
        case .userIdBinding:
            String(localized: "contactcertification.import.mode.userId", defaultValue: "User ID")
        case .directKey:
            String(localized: "contactcertification.import.mode.directKey", defaultValue: "Direct Key")
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

    func title(for status: ContactCertificationValidationStatus) -> String {
        switch status {
        case .valid:
            String(localized: "contactcertification.status.valid", defaultValue: "Valid")
        case .invalidOrStale:
            String(localized: "contactcertification.status.invalid", defaultValue: "Invalid or Stale")
        case .revalidationNeeded:
            String(localized: "contactcertification.status.revalidationNeeded", defaultValue: "Revalidation Needed")
        }
    }

    func title(for status: CertificateSignatureStatus) -> String {
        switch status {
        case .valid:
            String(localized: "contactcertsig.status.valid", defaultValue: "Valid")
        case .invalid:
            String(localized: "contactcertsig.status.invalid", defaultValue: "Invalid")
        case .signerMissing:
            String(localized: "contactcertsig.status.signerMissing", defaultValue: "Signer Missing")
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

    private func ensureDefaultKeySelection() {
        guard selectedKeyId == nil else {
            return
        }
        if let preferredKey = contact?.preferredKey {
            selectedKeyId = preferredKey.keyId
        } else {
            selectedKeyId = contact?.keys.first?.keyId
        }
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

    private func loadCatalog() {
        guard contactsAvailability.isAvailable else {
            catalog = nil
            loadError = .contactsUnavailable(contactsAvailability)
            loadState = .failed
            return
        }

        guard let targetCert = selectedKeyRecord?.publicKeyData else {
            loadState = .loaded
            return
        }

        loadTask?.cancel()
        loadGeneration &+= 1
        let generation = loadGeneration
        let selectionCatalogAction = self.selectionCatalogAction
        loadState = .loading
        activeOperation = .load

        loadTask = Task { [weak self, generation] in
            defer {
                if let self, generation == self.loadGeneration {
                    self.loadTask = nil
                    self.activeOperation = nil
                }
            }

            do {
                await Task.yield()
                let catalog = try await selectionCatalogAction(targetCert)
                try Task.checkCancellation()

                guard let self, generation == self.loadGeneration else {
                    return
                }
                self.catalog = catalog
                self.selectedUserId = self.selectedUserId ?? catalog.userIds.first
                self.loadError = nil
                self.loadState = .loaded
                self.ensureDefaultSignerSelection()
            } catch {
                guard let self else {
                    return
                }
                guard !Self.shouldIgnore(error), generation == self.loadGeneration else {
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
        work: @escaping @MainActor (@escaping @MainActor () throws -> Void) async throws -> (
            CertificateSignatureVerification?,
            VerifiedContactCertificationArtifact?,
            ContactCertificationArtifactReference?
        )
    ) {
        operationTask?.cancel()
        operationGeneration &+= 1
        let generation = operationGeneration
        activeOperation = operation
        switch operation {
        case .savePending, .exportArtifact:
            break
        default:
            invalidatePreview()
        }

        operationTask = Task { [weak self, generation] in
            defer {
                if let self, generation == self.operationGeneration {
                    self.activeOperation = nil
                    self.operationTask = nil
                }
            }

            do {
                let checkActive: @MainActor () throws -> Void = { [weak self, generation] in
                    try Task.checkCancellation()
                    guard let self, generation == self.operationGeneration else {
                        throw CancellationError()
                    }
                }
                try checkActive()
                let (verification, pendingArtifact, savedArtifact) = try await work(checkActive)
                try checkActive()

                guard let self, generation == self.operationGeneration else {
                    return
                }
                self.verification = verification
                self.pendingArtifact = pendingArtifact
                self.lastSavedArtifact = savedArtifact
                if savedArtifact != nil {
                    self.pendingArtifact = nil
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

    private func certificationExportFilename(
        key: ContactKeySummary,
        signer: PGPKeyIdentity,
        userId: UserIdSelectionOption
    ) -> String {
        "userid-certification-\(key.shortKeyId)-\(userId.occurrenceIndex + 1)-by-\(signer.shortKeyId).asc"
    }

    private func invalidatePreview() {
        verification = nil
        pendingArtifact = nil
        lastSavedArtifact = nil
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
