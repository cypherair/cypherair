import Foundation

private struct InitialRecipientSelectionSignature: Equatable {
    let contactIds: [String]

    init(configuration: EncryptView.Configuration) {
        contactIds = configuration.initialRecipientContactIds
    }
}

struct EncryptFileRequest {
    let fileURL: URL
    let recipientContactIds: [String]
    let signerFingerprint: String?
    let encryptToSelf: Bool
    let encryptToSelfFingerprint: String?
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
        EncryptFileRequest
    ) async throws -> TemporaryFileOutput
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
    private let fileEncryptionAction: FileOperationAction<EncryptFileRequest, TemporaryFileOutput>
    private let clipboardNoticeDecision: ClipboardNoticeDecision
    private let clipboardWriter: ClipboardWriter
    @ObservationIgnored private var encryptedFileOutput: TemporaryFileOutput?
    @ObservationIgnored private var lastAppliedInitialRecipientSelectionSignature: InitialRecipientSelectionSignature?
    @ObservationIgnored private var clipboardTask: Task<Void, Never>?
    private var clipboardToken: UInt64 = 0
    private var fileImportRequestGate = FileImportRequestGate()

    var encryptMode: EncryptView.EncryptMode = .text
    var plaintext = ""
    var recipientSearchText = ""
    var selectedRecipients: Set<String> = []
    private var rawSelectedRecipientTagFilterIds: Set<String> = []
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
            if encryptedFileURL != encryptedFileOutput?.fileURL {
                encryptedFileOutput?.cleanup()
                encryptedFileOutput = encryptedFileURL.map { TemporaryFileOutput(fileURL: $0) }
            }
        }
    }
    var showUnverifiedRecipientsWarning = false
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
        self.fileEncryptionAction = FileOperationAction(injectedAction: fileEncryptionAction) { request, progress in
            try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: request.fileURL,
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
                    inputURL: request.fileURL,
                    recipientContactIds: request.recipientContactIds,
                    signWithFingerprint: request.signerFingerprint,
                    encryptToSelf: request.encryptToSelf,
                    encryptToSelfFingerprint: request.encryptToSelfFingerprint,
                    progress: progress
                ).temporaryFileOutput
            }
        }
    }

    /// Candidate recipients matching the active search text and the selected tag
    /// filters (any-of). This is the list the chooser shows; tags + search refine
    /// it but never gate whether recipients appear at all.
    var filteredRecipientContacts: [ContactRecipientSummary] {
        contactService.recipientContacts(
            matching: recipientSearchText,
            tagFilterIds: selectedRecipientTagFilterIds
        )
    }

    /// Filtered candidates that are not already selected — the rows the user can add.
    var addableRecipientContacts: [ContactRecipientSummary] {
        filteredRecipientContacts.filter { !selectedRecipients.contains($0.contactId) }
    }

    /// The current selection resolved to summaries, in presentation order, dropping
    /// ids that no longer resolve to an available recipient. Single source of truth
    /// for the "Selected" group; kept consistent with `effectiveRecipientContactIds`.
    var selectedRecipientSummaries: [ContactRecipientSummary] {
        guard contactsAvailability.isAvailable else {
            return []
        }
        let summariesByContactId = Dictionary(
            uniqueKeysWithValues: contactService.availableRecipientContacts.map { ($0.contactId, $0) }
        )
        return effectiveRecipientContactIds.compactMap { summariesByContactId[$0] }
    }

    /// True when any recipient is available to choose from — used to tell
    /// "no contacts yet" apart from "no matches for the current filter".
    var hasAvailableRecipients: Bool {
        guard contactsAvailability.isAvailable else {
            return false
        }
        return !contactService.availableRecipientContacts.isEmpty
    }

    /// True when a search query or any tag filter is currently narrowing the list.
    var hasActiveRecipientSearchOrFilter: Bool {
        !ContactsSearchIndex.normalizedSearchText(recipientSearchText).isEmpty ||
            !selectedRecipientTagFilterIds.isEmpty
    }

    /// The selected recipient ids resolved against live contacts: stale ids (whose
    /// contact was deleted) are dropped while contacts are available, so display,
    /// count, the unverified check, and `encryptButtonDisabled` all reflect reality.
    /// While contacts are locked the raw selection is preserved — it cannot be
    /// resolved yet and must survive a transient lock.
    var effectiveRecipientContactIds: [String] {
        guard contactsAvailability.isAvailable else {
            return dedupedContactIds(Array(selectedRecipients))
        }
        let availableIds = Set(contactService.availableRecipientContacts.map(\.contactId))
        return dedupedContactIds(Array(selectedRecipients.intersection(availableIds)))
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

    /// Tags available as quick filters for the candidate list (mirrors the Contacts
    /// screen's tag strip).
    var recipientTagFilters: [ContactTagSummary] {
        guard contactsAvailability.isAvailable else {
            return []
        }
        return contactService.contactTagSummaries()
    }

    /// The active tag filters, pruned to tags that still exist so a deleted tag
    /// silently leaves the filter instead of stranding the list on a dead filter.
    var selectedRecipientTagFilterIds: Set<String> {
        get {
            ContactTagSummary.prunedTagFilterIds(rawSelectedRecipientTagFilterIds, availableTags: recipientTagFilters)
        }
        set {
            rawSelectedRecipientTagFilterIds = ContactTagSummary.prunedTagFilterIds(newValue, availableTags: recipientTagFilters)
        }
    }

    /// The currently selected tag filters as summaries (for the "Clear" affordance).
    var selectedRecipientTagFilters: [ContactTagSummary] {
        let selectedIds = selectedRecipientTagFilterIds
        return recipientTagFilters.filter { selectedIds.contains($0.tagId) }
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
            selectedUnverifiedContacts
                .map { IdentityDisplayPresentation.displayName($0.displayName) }
                .joined(separator: ", ")
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

    /// Toggles a tag in the multi-select filter (browse only — does not change the
    /// selected recipients). Mirrors the Contacts screen's tag-filter behavior.
    func toggleRecipientTagFilter(_ tagId: String) {
        let availableTagIds = Set(recipientTagFilters.map(\.tagId))
        var selectedIds = selectedRecipientTagFilterIds
        if selectedIds.contains(tagId) {
            selectedIds.remove(tagId)
        } else if availableTagIds.contains(tagId) {
            selectedIds.insert(tagId)
        }
        selectedRecipientTagFilterIds = selectedIds
    }

    func isRecipientTagFilterSelected(_ tagId: String) -> Bool {
        selectedRecipientTagFilterIds.contains(tagId)
    }

    func clearRecipientTagFilters() {
        rawSelectedRecipientTagFilterIds.removeAll()
    }

    /// Adds every currently-visible candidate (search ∩ tag-filtered, already
    /// encryptable, not yet selected) to the selection. Scoped to what is shown so
    /// it can never add a recipient hidden by the active filter.
    func addAllVisibleRecipients() {
        selectedRecipients.formUnion(addableRecipientContacts.map(\.contactId))
    }

    func clearRecipients() {
        selectedRecipients.removeAll()
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
            let output = try await self.fileEncryptionAction(
                EncryptFileRequest(
                    fileURL: fileURL,
                    recipientContactIds: recipients,
                    signerFingerprint: signerFingerprint,
                    encryptToSelf: encryptToSelf,
                    encryptToSelfFingerprint: encryptToSelfFingerprint
                ),
                progress: progress
            )
            var pendingOutput: TemporaryFileOutput? = output
            defer {
                pendingOutput?.cleanup()
            }
            try Task.checkCancellation()
            self.adoptEncryptedFileOutput(output)
            pendingOutput = nil
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
        rawSelectedRecipientTagFilterIds.removeAll()
        ciphertext = nil
        selectedFileURL = nil
        selectedFileName = nil
        showFileImporter = false
        showUnverifiedRecipientsWarning = false
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

    private func adoptEncryptedFileOutput(_ output: TemporaryFileOutput) {
        cleanupTemporaryEncryptedFile()
        encryptedFileOutput = output
        encryptedFileURL = output.fileURL
    }

    private func cleanupTemporaryEncryptedFile() {
        encryptedFileOutput?.cleanup()
        encryptedFileOutput = nil
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
                    defaultValue: "Unlock CypherAir X before encrypting with app defaults."
                )
            )
        )
    }

    private func mapEncryptionError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .encryptionFailed(reason: $0) }
    }
}
