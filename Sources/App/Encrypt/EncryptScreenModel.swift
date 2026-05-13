import Foundation

private struct InitialRecipientSelectionSignature: Equatable {
    let contactIds: [String]

    init(configuration: EncryptView.Configuration) {
        contactIds = configuration.initialRecipientContactIds
    }
}

struct RecipientTagSelectionOption: Identifiable, Hashable, Sendable {
    var id: String { tagId }

    let tagId: String
    let displayName: String
    let contactCount: Int
    let selectableContactIds: [String]
    let skippedContactCount: Int
}

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
    ) async throws -> AppTemporaryArtifact
    typealias ClipboardNoticeDecision = @MainActor () async -> Bool
    typealias ClipboardWriter = @MainActor (String, Bool) -> Void

    private(set) var configuration: EncryptView.Configuration
    let operation: OperationController
    let exportController: FileExportController

    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let appConfiguration: AppConfiguration
    private let protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator
    private let authLifecycleTraceStore: AuthLifecycleTraceStore?
    private let protectedSettingsHost: ProtectedSettingsHost?
    private let textEncryptionAction: TextEncryptionAction
    private let fileEncryptionAction: FileEncryptionAction
    private let clipboardNoticeDecision: ClipboardNoticeDecision
    private let clipboardWriter: ClipboardWriter
    @ObservationIgnored private var encryptedFileArtifact: AppTemporaryArtifact?
    @ObservationIgnored private var lastAppliedInitialRecipientSelectionSignature: InitialRecipientSelectionSignature?
    @ObservationIgnored private var clipboardTask: Task<Void, Never>?
    private var clipboardToken: UInt64 = 0
    private var fileImportRequestGate = FileImportRequestGate()

    var encryptMode: EncryptView.EncryptMode = .text
    var plaintext = ""
    var recipientSearchText = ""
    var selectedRecipients: Set<String> = []
    var signMessage = true
    var signerFingerprint: String?
    var ciphertext: Data?
    var encryptToSelf: Bool?
    var encryptToSelfFingerprint: String?
    var showFileImporter = false
    var selectedFileURL: URL?
    var selectedFileName: String?
    var encryptedFileURL: URL? {
        didSet {
            if encryptedFileURL != encryptedFileArtifact?.fileURL {
                encryptedFileArtifact = encryptedFileURL.map { AppTemporaryArtifact(fileURL: $0) }
            }
        }
    }
    var showUnverifiedRecipientsWarning = false
    var tagSelectionSkippedContactCount = 0
    var tagSelectionSkippedTagName: String?
    var textInputSectionEpoch = 0

    init(
        encryptionService: EncryptionService,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        config: AppConfiguration,
        protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator,
        authLifecycleTraceStore: AuthLifecycleTraceStore? = nil,
        protectedSettingsHost: ProtectedSettingsHost? = nil,
        configuration: EncryptView.Configuration,
        operation: OperationController = OperationController(),
        exportController: FileExportController = FileExportController(),
        textEncryptionAction: TextEncryptionAction? = nil,
        fileEncryptionAction: FileEncryptionAction? = nil,
        clipboardNoticeDecision: ClipboardNoticeDecision? = nil,
        clipboardWriter: ClipboardWriter? = nil
    ) {
        let operationController = operation
        self.configuration = configuration
        self.operation = operationController
        self.exportController = exportController
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.appConfiguration = config
        self.protectedOrdinarySettings = protectedOrdinarySettings
        self.authLifecycleTraceStore = authLifecycleTraceStore
        self.protectedSettingsHost = protectedSettingsHost
        self.clipboardNoticeDecision = clipboardNoticeDecision ?? {
            await protectedSettingsHost?.clipboardNoticeDecision() ?? true
        }
        self.clipboardWriter = clipboardWriter ?? { string, shouldShowNotice in
            operationController.copyToClipboard(string, shouldShowNotice: shouldShowNotice)
        }
        self.textEncryptionAction = textEncryptionAction ?? {
            plaintext,
            recipients,
            signerFingerprint,
            encryptToSelf,
            encryptToSelfFingerprint in
            try await encryptionService.encryptText(
                plaintext,
                recipientContactIds: recipients,
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
                    recipientContactIds: recipients,
                    signWithFingerprint: signerFingerprint,
                    encryptToSelf: encryptToSelf,
                    encryptToSelfFingerprint: encryptToSelfFingerprint,
                    progress: progress
                )
            }
        }
    }

    var encryptableContacts: [ContactRecipientSummary] {
        contactService.recipientContacts(matching: recipientSearchText)
    }

    var effectiveRecipientContactIds: [String] {
        dedupedContactIds(Array(selectedRecipients))
    }

    var contactsAvailability: ContactsAvailability {
        contactService.contactsAvailability
    }

    var ownKeys: [PGPKeyIdentity] {
        keyManagement.keys
    }

    var defaultKeyVersion: UInt8? {
        keyManagement.defaultKey.map(\.keyVersion)
    }

    var selectedUnverifiedContacts: [ContactRecipientSummary] {
        unverifiedContacts(for: effectiveRecipientContactIds)
    }

    var recipientTagOptions: [RecipientTagSelectionOption] {
        guard contactsAvailability.isAvailable else {
            return []
        }
        let recipientContactIdsByTagId = contactService.recipientContacts(matching: "")
            .reduce(into: [String: [String]]()) { partialResult, contact in
                for tagId in contact.tagIds {
                    partialResult[tagId, default: []].append(contact.contactId)
                }
            }
        return contactService.contactTagSummaries().map { tag in
            let selectableContactIds = dedupedContactIds(recipientContactIdsByTagId[tag.tagId] ?? [])
            return RecipientTagSelectionOption(
                tagId: tag.tagId,
                displayName: tag.displayName,
                contactCount: tag.contactCount,
                selectableContactIds: selectableContactIds,
                skippedContactCount: max(tag.contactCount - selectableContactIds.count, 0)
            )
        }
    }

    var encryptButtonDisabled: Bool {
        if operation.isRunning {
            return true
        }
        if effectiveRecipientContactIds.isEmpty {
            return true
        }
        if !contactsAvailability.isAvailable {
            return true
        }
        if resolvedEncryptToSelf == nil {
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

    var fileImportRequestToken: FileImportRequestGate.Token? {
        fileImportRequestGate.currentToken
    }

    var resolvedEncryptToSelf: Bool? {
        encryptToSelf ?? protectedOrdinarySettings.encryptToSelf
    }

    var encryptToSelfToggleValue: Bool {
        resolvedEncryptToSelf ?? false
    }

    var isEncryptToSelfControlEnabled: Bool {
        if configuration.encryptToSelfPolicy.isLocked {
            return false
        }
        return resolvedEncryptToSelf != nil
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

    var tagSelectionSkipMessage: String? {
        guard tagSelectionSkippedContactCount > 0,
              let tagSelectionSkippedTagName else {
            return nil
        }
        return String.localizedStringWithFormat(
            String(
                localized: "encrypt.tagSelection.skipped",
                defaultValue: "%1$@ added available recipients. %2$d contacts were skipped because they need a preferred encryption key."
            ),
            tagSelectionSkippedTagName,
            tagSelectionSkippedContactCount
        )
    }

    func handleAppear() {
        applyPrefilledPlaintextIfNeeded(from: configuration)
        let initialRecipientSelectionSignature = InitialRecipientSelectionSignature(configuration: configuration)
        if lastAppliedInitialRecipientSelectionSignature != initialRecipientSelectionSignature {
            applyInitialRecipientSelection(from: configuration)
            lastAppliedInitialRecipientSelectionSignature = initialRecipientSelectionSignature
        }
        applyInitialSignerSelection(from: configuration)
        applySigningPolicy(from: configuration)
        applyEncryptToSelfPolicy(from: configuration)
    }

    func updateConfiguration(_ configuration: EncryptView.Configuration) {
        let previousConfiguration = self.configuration
        self.configuration = configuration

        if previousConfiguration.prefilledPlaintext != configuration.prefilledPlaintext {
            applyPrefilledPlaintextIfNeeded(from: configuration)
        }

        if previousConfiguration.initialRecipientContactIds != configuration.initialRecipientContactIds {
            syncRuntimeRecipientSelection(from: configuration)
            lastAppliedInitialRecipientSelectionSignature = InitialRecipientSelectionSignature(
                configuration: configuration
            )
        }

        if previousConfiguration.initialSignerFingerprint != configuration.initialSignerFingerprint {
            applyInitialSignerSelection(from: configuration)
        }

        if previousConfiguration.signingPolicy != configuration.signingPolicy {
            applySigningPolicy(from: configuration)
        }

        if previousConfiguration.encryptToSelfPolicy != configuration.encryptToSelfPolicy {
            applyEncryptToSelfPolicy(from: configuration)
        }
    }

    func toggleRecipient(_ contactId: String, isOn: Bool) {
        if isOn {
            selectedRecipients.insert(contactId)
        } else {
            selectedRecipients.remove(contactId)
        }
    }

    func selectRecipients(withTagId tagId: String) {
        guard let option = recipientTagOptions.first(where: { $0.tagId == tagId }) else {
            return
        }
        selectedRecipients.formUnion(option.selectableContactIds)
        tagSelectionSkippedContactCount = option.skippedContactCount
        tagSelectionSkippedTagName = option.displayName
    }

    func clearRecipients() {
        selectedRecipients.removeAll()
        tagSelectionSkippedContactCount = 0
        tagSelectionSkippedTagName = nil
    }

    func dismissTagSelectionSkipMessage() {
        tagSelectionSkippedContactCount = 0
        tagSelectionSkippedTagName = nil
    }

    func selectedRecipientCount(for tagOption: RecipientTagSelectionOption) -> Int {
        tagOption.selectableContactIds.reduce(0) { count, contactId in
            count + (selectedRecipients.contains(contactId) ? 1 : 0)
        }
    }

    func requestFileImport() {
        guard configuration.allowsFileInput else { return }
        fileImportRequestGate.begin()
        showFileImporter = true
    }

    func handleImportedFile(_ url: URL) {
        cleanupTemporaryEncryptedFile()
        selectedFileURL = url
        selectedFileName = url.lastPathComponent
    }

    func handleFileImporterResult(
        _ result: Result<[URL], Error>,
        token: FileImportRequestGate.Token?
    ) {
        guard fileImportRequestGate.consumeIfCurrent(token) else {
            return
        }

        if case .success(let urls) = result, let url = urls.first {
            handleImportedFile(url)
        }
    }

    func requestEncrypt() {
        guard contactsAvailability.isAvailable else {
            operation.present(error: .contactsUnavailable(contactsAvailability))
            return
        }

        let recipients: [String]
        do {
            recipients = try validatedEffectiveRecipientContactIdsForEncryption()
        } catch {
            operation.present(error: mapEncryptionError(error))
            return
        }

        if !unverifiedContacts(for: recipients).isEmpty {
            showUnverifiedRecipientsWarning = true
            return
        }

        performEncrypt(to: recipients)
    }

    func confirmEncryptWithUnverifiedRecipients() {
        showUnverifiedRecipientsWarning = false
        do {
            let recipients = try validatedEffectiveRecipientContactIdsForEncryption()
            performEncrypt(to: recipients)
        } catch {
            operation.present(error: mapEncryptionError(error))
        }
    }

    func dismissUnverifiedRecipientsWarning() {
        showUnverifiedRecipientsWarning = false
    }

    func encryptText(validatedRecipientContactIds: [String]? = nil) {
        let text = plaintext
        let recipients: [String]
        do {
            if let validatedRecipientContactIds {
                recipients = validatedRecipientContactIds
            } else {
                recipients = try validatedEffectiveRecipientContactIdsForEncryption()
            }
        } catch {
            operation.present(error: mapEncryptionError(error))
            return
        }
        let signerFingerprint = signMessage ? signerFingerprint : nil
        guard let encryptToSelf = resolvedEncryptToSelf else {
            presentProtectedOrdinarySettingsLockedError()
            return
        }
        let encryptToSelfFingerprint = encryptToSelf ? self.encryptToSelfFingerprint : nil
        let onEncrypted = configuration.onEncrypted

        ciphertext = nil
        authLifecycleTraceStore?.record(
            category: .operation,
            name: "encrypt.text.start",
            metadata: ["mode": "text", "signed": signerFingerprint == nil ? "false" : "true"]
        )

        operation.run(mapError: mapEncryptionError) { [self] in
            let result = try await self.textEncryptionAction(
                text,
                recipients,
                signerFingerprint,
                encryptToSelf,
                encryptToSelfFingerprint
            )
            try Task.checkCancellation()
            self.ciphertext = result
            self.textInputSectionEpoch &+= 1
            onEncrypted?(result)
            self.authLifecycleTraceStore?.record(
                category: .operation,
                name: "encrypt.text.finish",
                metadata: ["result": "success"]
            )
        }
    }

    func encryptFile(validatedRecipientContactIds: [String]? = nil) {
        guard let fileURL = selectedFileURL else { return }

        let recipients: [String]
        do {
            if let validatedRecipientContactIds {
                recipients = validatedRecipientContactIds
            } else {
                recipients = try validatedEffectiveRecipientContactIdsForEncryption()
            }
        } catch {
            operation.present(error: mapEncryptionError(error))
            return
        }
        let signerFingerprint = signMessage ? signerFingerprint : nil
        guard let encryptToSelf = resolvedEncryptToSelf else {
            presentProtectedOrdinarySettingsLockedError()
            return
        }
        let encryptToSelfFingerprint = encryptToSelf ? self.encryptToSelfFingerprint : nil

        cleanupTemporaryEncryptedFile()
        authLifecycleTraceStore?.record(
            category: .operation,
            name: "encrypt.file.start",
            metadata: ["mode": "file", "signed": signerFingerprint == nil ? "false" : "true"]
        )

        operation.runFileOperation(mapError: mapEncryptionError) { [self] progress in
            let artifact = try await self.fileEncryptionAction(
                fileURL,
                recipients,
                signerFingerprint,
                encryptToSelf,
                encryptToSelfFingerprint,
                progress
            )
            var pendingArtifact: AppTemporaryArtifact? = artifact
            defer {
                pendingArtifact?.cleanup()
            }
            try Task.checkCancellation()
            self.adoptEncryptedFileArtifact(artifact)
            pendingArtifact = nil
            self.authLifecycleTraceStore?.record(
                category: .operation,
                name: "encrypt.file.finish",
                metadata: ["result": "success"]
            )
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
            clipboardTask?.cancel()
            clipboardToken &+= 1
            let token = clipboardToken
            let noticeDecision = clipboardNoticeDecision
            let writer = clipboardWriter
            clipboardTask = Task { @MainActor [weak self, token, ciphertextString, noticeDecision, writer] in
                guard let self else { return }
                defer {
                    if token == self.clipboardToken {
                        self.clipboardTask = nil
                    }
                }
                do {
                    let shouldShowNotice = await noticeDecision()
                    try Task.checkCancellation()
                    guard token == self.clipboardToken else {
                        return
                    }
                    writer(ciphertextString, shouldShowNotice)
                } catch {
                    return
                }
            }
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

    func handleDisappear() {
        fileImportRequestGate.invalidate()
        cleanupTemporaryEncryptedFile()
    }

    func handleContentClearGenerationChange() {
        operation.cancelAndInvalidate()
        cancelClipboardCopy()
        cleanupTemporaryEncryptedFile()
        clearTransientInput()
    }

    private func cancelClipboardCopy() {
        clipboardTask?.cancel()
        clipboardToken &+= 1
        clipboardTask = nil
    }

    func clearTransientInput() {
        fileImportRequestGate.invalidate()
        plaintext = ""
        recipientSearchText = ""
        selectedRecipients.removeAll()
        ciphertext = nil
        selectedFileURL = nil
        selectedFileName = nil
        showFileImporter = false
        showUnverifiedRecipientsWarning = false
        tagSelectionSkippedContactCount = 0
        tagSelectionSkippedTagName = nil
        exportController.finish()
        textInputSectionEpoch &+= 1
    }

    func handleExportError(_ error: Error) {
        operation.present(error: mapEncryptionError(error))
    }

    func refreshProtectedOrdinarySettings() {
        guard configuration.encryptToSelfPolicy == .appDefault else { return }
        encryptToSelf = protectedOrdinarySettings.encryptToSelf
    }

    private func performEncrypt(to recipientContactIds: [String]) {
        switch encryptMode {
        case .text:
            encryptText(validatedRecipientContactIds: recipientContactIds)
        case .file:
            encryptFile(validatedRecipientContactIds: recipientContactIds)
        }
    }

    private func validatedEffectiveRecipientContactIdsForEncryption() throws -> [String] {
        guard contactsAvailability.isAvailable else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }

        let availableRecipientIds = Set(contactService.recipientContacts(matching: "").map(\.contactId))
        let staleDirectRecipientIds = selectedRecipients.subtracting(availableRecipientIds)

        if !staleDirectRecipientIds.isEmpty {
            selectedRecipients.subtract(staleDirectRecipientIds)
            throw CypherAirError.encryptionFailed(
                reason: String(
                    localized: "encrypt.recipients.staleSelection",
                    defaultValue: "Recipient selection changed. Review recipients and try again."
                )
            )
        }

        let recipientContactIds = dedupedContactIds(Array(selectedRecipients))
        guard !recipientContactIds.isEmpty else {
            throw CypherAirError.noRecipientsSelected
        }
        return recipientContactIds
    }

    private func unverifiedContacts(for contactIds: [String]) -> [ContactRecipientSummary] {
        let contactIds = Set(contactIds)
        return contactService.recipientContacts(matching: "").filter { contact in
            contactIds.contains(contact.contactId) && !contact.isPreferredKeyVerified
        }
    }

    private func adoptEncryptedFileArtifact(_ artifact: AppTemporaryArtifact) {
        cleanupTemporaryEncryptedFile()
        encryptedFileArtifact = artifact
        encryptedFileURL = artifact.fileURL
    }

    private func cleanupTemporaryEncryptedFile() {
        encryptedFileArtifact?.cleanup()
        encryptedFileArtifact = nil
        encryptedFileURL = nil
    }

    private func applyPrefilledPlaintextIfNeeded(from configuration: EncryptView.Configuration) {
        if plaintext.isEmpty,
           let prefilledPlaintext = configuration.prefilledPlaintext {
            plaintext = prefilledPlaintext
        }
    }

    private func applyInitialRecipientSelection(from configuration: EncryptView.Configuration) {
        if !configuration.initialRecipientContactIds.isEmpty {
            selectedRecipients = Set(initialRecipientContactIds(from: configuration))
        }
    }

    private func syncRuntimeRecipientSelection(from configuration: EncryptView.Configuration) {
        selectedRecipients = Set(initialRecipientContactIds(from: configuration))
    }

    private func initialRecipientContactIds(from configuration: EncryptView.Configuration) -> [String] {
        guard !configuration.initialRecipientContactIds.isEmpty else {
            return []
        }
        guard contactsAvailability.isAvailable else {
            return configuration.initialRecipientContactIds
        }
        let availableRecipientIds = Set(contactService.recipientContacts(matching: "").map(\.contactId))
        return configuration.initialRecipientContactIds.filter {
            availableRecipientIds.contains($0)
        }
    }

    private func dedupedContactIds(_ contactIds: [String]) -> [String] {
        let presentationOrder = contactService.availableContactIdentities.map(\.contactId)
        let presentationOrderByContactId = Dictionary(
            uniqueKeysWithValues: presentationOrder.enumerated().map { ($0.element, $0.offset) }
        )
        return Array(Set(contactIds)).sorted { lhs, rhs in
            let lhsOrder = presentationOrderByContactId[lhs] ?? .max
            let rhsOrder = presentationOrderByContactId[rhs] ?? .max
            if lhsOrder != rhsOrder {
                return lhsOrder < rhsOrder
            }
            return lhs < rhs
        }
    }

    private func applyInitialSignerSelection(from configuration: EncryptView.Configuration) {
        let defaultSigner = configuration.initialSignerFingerprint ?? keyManagement.defaultKey?.fingerprint
        signerFingerprint = defaultSigner
        encryptToSelfFingerprint = defaultSigner
    }

    private func applySigningPolicy(from configuration: EncryptView.Configuration) {
        signMessage = configuration.signingPolicy.initialValue(appDefault: true)
    }

    private func applyEncryptToSelfPolicy(from configuration: EncryptView.Configuration) {
        encryptToSelf = configuration.encryptToSelfPolicy.optionalInitialValue(
            appDefault: protectedOrdinarySettings.encryptToSelf
        )
    }

    private func presentProtectedOrdinarySettingsLockedError() {
        operation.present(
            error: .encryptionFailed(
                reason: String(
                    localized: "encrypt.protectedPreferencesLocked",
                    defaultValue: "Unlock CypherAir before encrypting with app defaults."
                )
            )
        )
    }

    private func mapEncryptionError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .encryptionFailed(reason: $0) }
    }
}
