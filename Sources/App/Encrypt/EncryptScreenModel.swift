import Foundation

private struct InitialRecipientSelectionSignature: Equatable {
    let contactIds: [String]

    init(configuration: EncryptView.Configuration) {
        contactIds = configuration.initialRecipientContactIds
    }
}

/// Everything the engine is given when asked what format a message will take.
///
/// Identity is the certificates themselves, not the contact ids they were
/// resolved from: a contact whose certificate is replaced keeps its id, and an
/// answer remembered against ids would go on describing the certificate that is
/// no longer there. Keyed this way, a remembered answer cannot be stale — it
/// answers a question that is byte-for-byte the one being asked.
private struct OutgoingFormatQuestion: Equatable {
    let recipientKeys: [Data]
    let encryptToSelfKey: Data?
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
    typealias MessageQuantumSafetyAction = @MainActor (Data) throws -> MessageQuantumSafety

    private(set) var configuration: EncryptView.Configuration
    let operation: OperationController
    let exportController: FileExportController

    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let appConfiguration: AppConfiguration
    private let protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator
    private let protectedSettingsHost: ProtectedSettingsHost?
    private let textEncryptionAction: TextEncryptionAction
    private let messageQuantumSafetyAction: MessageQuantumSafetyAction
    private let fileEncryptionAction: FileOperationAction<EncryptFileRequest, TemporaryFileOutput>
    private let clipboardNoticeDecision: ClipboardNoticeDecision
    private let clipboardWriter: ClipboardWriter
    @ObservationIgnored private var lastAppliedInitialRecipientSelectionSignature: InitialRecipientSelectionSignature?
    /// The last question put to the engine and the answer it gave. Observation
    /// ignores it: it is a record of work already done, never a reason to render.
    @ObservationIgnored private var lastOutgoingFormatAnswer: (
        question: OutgoingFormatQuestion,
        decision: OutgoingFormatDecision?
    )?
    private var clipboardToken: UInt64 = 0
    private var fileImportRequestGate = FileImportRequestGate()

    var encryptMode: EncryptView.EncryptMode = .text
    var plaintext = ""
    var recipientSearchText = ""
    var selectedRecipients: Set<String> = []
    private var recipientTagFilterState = TagFilterState()
    var signMessage: Bool?
    var signerFingerprint: String?
    var ciphertext: Data?
    var encryptToSelf: Bool?
    var encryptToSelfFingerprint: String?
    var showFileImporter = false
    var selectedFileURL: URL?
    var selectedFileName: String?
    /// The encrypted file the last run produced, carrying both where it is and
    /// the name saving it offers. The output is the stored fact; there is no
    /// second place to put a URL that would then need a name derived for it.
    private var encryptedFileOutput: TemporaryFileOutput?

    var encryptedFileURL: URL? { encryptedFileOutput?.fileURL }
    var showUnverifiedRecipientsWarning = false
    var textInputSectionEpoch = 0

    /// Quantum-safety of the currently displayed result, classified from the
    /// produced artifact's PKESK algorithms — never from the live selection,
    /// which can change after encryption (the quantum-safe claim is never shown
    /// for a mixed message). nil = no result, or the
    /// artifact could not be classified (no claim either way).
    var resultQuantumSafety: MessageQuantumSafety?

    init(
        encryptionService: EncryptionService,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        config: AppConfiguration,
        protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator,
        protectedSettingsHost: ProtectedSettingsHost? = nil,
        configuration: EncryptView.Configuration,
        operation: OperationController = OperationController(),
        exportController: FileExportController = FileExportController(),
        textEncryptionAction: TextEncryptionAction? = nil,
        fileEncryptionAction: FileEncryptionAction? = nil,
        clipboardNoticeDecision: ClipboardNoticeDecision? = nil,
        clipboardWriter: ClipboardWriter? = nil,
        messageQuantumSafetyAction: MessageQuantumSafetyAction? = nil
    ) {
        let operationController = operation
        self.configuration = configuration
        self.operation = operationController
        self.exportController = exportController
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.appConfiguration = config
        self.protectedOrdinarySettings = protectedOrdinarySettings
        self.protectedSettingsHost = protectedSettingsHost
        self.clipboardNoticeDecision = clipboardNoticeDecision ?? {
            await protectedSettingsHost?.clipboardNoticeDecision() ?? true
        }
        self.clipboardWriter = clipboardWriter ?? { string, shouldShowNotice in
            operationController.copyToClipboard(string, shouldShowNotice: shouldShowNotice)
        }
        // Public-data packet inspection on an already-produced artifact; the
        // engine is stateless, so a transient instance needs no custody wiring.
        self.messageQuantumSafetyAction = messageQuantumSafetyAction ?? { ciphertext in
            try PgpEngine().messageQuantumSafety(ciphertext: ciphertext)
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

    /// The displayed result is quantum-safe: every session-key packet in the
    /// produced message targets an RFC 9980 composite KEM.
    var showsQuantumSafeBadge: Bool {
        resultQuantumSafety == .fullyPostQuantum
    }

    /// The displayed result is mixed: some, but not all, of its session-key
    /// packets target a composite KEM. Never shown together with the badge.
    var showsMixedQuantumSafetyCaption: Bool {
        resultQuantumSafety == .mixed
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

    /// How many selected recipients the active search/tag filter is hiding from the
    /// list (their row isn't shown because they don't match the filter). `0` when no
    /// filter is active — every selected recipient appears then. Built from
    /// `selectedRecipientSummaries`, so stale selections are already excluded (those
    /// are surfaced separately via `hasStaleSelectedRecipients`) and the two notices
    /// never double-count.
    var hiddenSelectedRecipientCount: Int {
        guard hasActiveRecipientSearchOrFilter else {
            return 0
        }
        let visibleIds = Set(filteredRecipientContacts.map(\.contactId))
        return selectedRecipientSummaries.reduce(into: 0) { count, contact in
            count += visibleIds.contains(contact.contactId) ? 0 : 1
        }
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

    /// What the engine will produce for the current selection: the message
    /// format, whether AEAD is being given up, and which recipients decide it.
    ///
    /// Built from the very arguments the encrypt call would receive — the
    /// resolved recipient selection plus the Encrypt to Self copy — and answered
    /// by the engine, so the preview and the message cannot describe different
    /// things. `nil` when there is no message to describe: nothing addressed
    /// yet, or a selection the encrypt path would refuse, both of which the
    /// chooser already reports in their own terms.
    ///
    /// The engine parses every addressed certificate to answer, so the answer is
    /// kept until the question changes rather than re-asked per render — the
    /// chooser re-renders on things that leave the message identical, a keystroke
    /// in the recipient search field among them.
    var outgoingFormatDecision: OutgoingFormatDecision? {
        guard let recipientKeys = try? contactService.publicKeysForRecipientContactIDs(
            effectiveRecipientContactIds
        ) else {
            return nil
        }
        let question = OutgoingFormatQuestion(
            recipientKeys: recipientKeys,
            encryptToSelfKey: encryptToSelfPublicKeyData
        )
        if let lastOutgoingFormatAnswer, lastOutgoingFormatAnswer.question == question {
            return lastOutgoingFormatAnswer.decision
        }
        let decision = try? PGPMessageFormatAdapter.decision(
            recipientKeys: question.recipientKeys,
            encryptToSelfKey: question.encryptToSelfKey
        )
        lastOutgoingFormatAnswer = (question, decision)
        return decision
    }

    /// The self copy's certificate, or nil when no copy is being made. A chosen
    /// key that no longer resolves is omitted rather than replaced: the send path
    /// fails loudly on it, and quietly describing a message addressed to some
    /// other key of the user's would be worse than describing none.
    private var encryptToSelfPublicKeyData: Data? {
        guard encryptToSelfToggleValue else {
            return nil
        }
        return try? keyManagement.encryptToSelfIdentity(
            fingerprint: encryptToSelfFingerprint
        ).publicKeyData
    }

    var selectedUnverifiedContacts: [ContactRecipientSummary] {
        unverifiedContacts(for: effectiveRecipientContactIds)
    }

    /// True when the selection still holds an id that no longer resolves to a live
    /// encryptable recipient (its contact was deleted, or its key was revoked /
    /// expired). The chooser surfaces this and `encryptButtonDisabled` gates on it,
    /// so the Encrypt button is never enabled-yet-erroring; the encryption path keeps
    /// its own `staleSelection` throw as a backstop for a contact removed mid-flow.
    /// `false` while contacts are locked — the raw selection is intentionally
    /// preserved and cannot be resolved yet.
    var hasStaleSelectedRecipients: Bool {
        guard contactsAvailability.isAvailable else {
            return false
        }
        let availableIds = Set(contactService.availableRecipientContacts.map(\.contactId))
        return !selectedRecipients.isSubset(of: availableIds)
    }

    /// Tags available as quick filters for the recipient list. Restricted to tags
    /// that have at least one encryptable recipient, so every chip resolves to a
    /// non-empty list and a tag whose members are all non-encryptable never appears.
    var recipientTagFilters: [ContactTagSummary] {
        guard contactsAvailability.isAvailable else {
            return []
        }
        let encryptableTagIds = Set(contactService.availableRecipientContacts.flatMap(\.tagIds))
        return contactService.contactTagSummaries().filter { encryptableTagIds.contains($0.tagId) }
    }

    /// The active tag filters, pruned to tags that still exist so a deleted tag
    /// silently leaves the filter instead of stranding the list on a dead filter.
    var selectedRecipientTagFilterIds: Set<String> {
        get {
            recipientTagFilterState.selectedIds(availableTags: recipientTagFilters)
        }
        set {
            recipientTagFilterState.replace(with: newValue, availableTags: recipientTagFilters)
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
        if hasStaleSelectedRecipients {
            return true
        }
        if resolvedEncryptToSelf == nil || resolvedSignMessage == nil {
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

    /// The two message-composition defaults resolve the same way: the value this
    /// message carries, falling back to the live app default so a domain that
    /// unlocks mid-screen is picked up without waiting for a refresh. `nil` means
    /// the app default is still unreadable — the screen states no value rather
    /// than inventing one, and encryption stays blocked until it can.
    var resolvedEncryptToSelf: Bool? {
        encryptToSelf ?? protectedOrdinarySettings.encryptToSelf
    }

    var resolvedSignMessage: Bool? {
        signMessage ?? protectedOrdinarySettings.signMessages
    }

    var encryptToSelfToggleValue: Bool {
        resolvedEncryptToSelf ?? false
    }

    var signMessageToggleValue: Bool {
        resolvedSignMessage ?? false
    }

    var isEncryptToSelfControlEnabled: Bool {
        if configuration.encryptToSelfPolicy.isLocked {
            return false
        }
        return resolvedEncryptToSelf != nil
    }

    var isSignMessageControlEnabled: Bool {
        if configuration.signingPolicy.isLocked {
            return false
        }
        return resolvedSignMessage != nil
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
        recipientTagFilterState.toggle(tagId, availableTags: recipientTagFilters)
    }

    func clearRecipientTagFilters() {
        recipientTagFilterState.clear()
    }

    /// Clears the active search text and tag filters without touching the selection,
    /// so selected recipients hidden by the filter become visible again ("Show All").
    func clearRecipientSearchAndFilters() {
        recipientSearchText = ""
        recipientTagFilterState.clear()
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

    /// Drops selected ids that no longer resolve to a live encryptable recipient,
    /// reconciling the selection with what the chooser shows (see
    /// `hasStaleSelectedRecipients`). No-op while contacts are locked.
    func removeStaleRecipients() {
        guard contactsAvailability.isAvailable else {
            return
        }
        let availableIds = Set(contactService.availableRecipientContacts.map(\.contactId))
        selectedRecipients.formIntersection(availableIds)
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
        guard let signMessage = resolvedSignMessage,
              let encryptToSelf = resolvedEncryptToSelf else {
            presentProtectedOrdinarySettingsLockedError()
            return
        }
        let signerFingerprint = signMessage ? self.signerFingerprint : nil
        let encryptToSelfFingerprint = encryptToSelf ? self.encryptToSelfFingerprint : nil
        let onEncrypted = configuration.onEncrypted

        ciphertext = nil
        resultQuantumSafety = nil

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
            self.resultQuantumSafety = try? self.messageQuantumSafetyAction(result)
            self.textInputSectionEpoch &+= 1
            onEncrypted?(result)
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
        guard let signMessage = resolvedSignMessage,
              let encryptToSelf = resolvedEncryptToSelf else {
            presentProtectedOrdinarySettingsLockedError()
            return
        }
        let signerFingerprint = signMessage ? self.signerFingerprint : nil
        let encryptToSelfFingerprint = encryptToSelf ? self.encryptToSelfFingerprint : nil

        cleanupTemporaryEncryptedFile()

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
        }
    }

    /// Copies the ciphertext and reports whether it reached the clipboard.
    ///
    /// The write waits on the clipboard-notice decision, which is a protected
    /// setting and may take a while to answer, so this suspends and the caller
    /// confirms only once the copy has landed. A copy this screen forbids, one
    /// the interception policy takes, and one superseded while it waited all
    /// report `false`.
    func copyCiphertextToClipboard() async -> Bool {
        guard configuration.allowsClipboardWrite,
              let ciphertextString else {
            return false
        }

        guard configuration.outputInterceptionPolicy.interceptClipboardCopy?(
            ciphertextString,
            appConfiguration,
            .ciphertext
        ) != true else {
            return false
        }

        clipboardToken &+= 1
        let token = clipboardToken

        let shouldShowNotice = await clipboardNoticeDecision()

        guard token == clipboardToken else {
            return false
        }

        clipboardWriter(ciphertextString, shouldShowNotice)
        return true
    }

    func exportCiphertext() {
        guard configuration.allowsResultExport,
              let ciphertext else {
            return
        }

        let filename = ExportFilename("encrypted.asc")
        do {
            if try configuration.outputInterceptionPolicy.interceptDataExport?(
                ciphertext,
                filename,
                .ciphertext
            ) != true {
                try exportController.prepareDataExport(ciphertext, filename: filename)
            }
        } catch {
            operation.present(error: mapEncryptionError(error))
        }
    }

    func exportEncryptedFile() {
        guard configuration.allowsFileResultExport,
              let output = encryptedFileOutput else {
            return
        }
        let url = output.fileURL

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

        if configuration.outputInterceptionPolicy.interceptFileExport?(
            url,
            output.exportFilename,
            .ciphertext
        ) != true {
            exportController.prepareFileExport(output)
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

    func handleDisappear() {
        fileImportRequestGate.invalidate()
        cleanupTemporaryEncryptedFile()
    }

    func handleContentClearGenerationChange() {
        operation.cancelAndInvalidate()
        supersedePendingClipboardCopy()
        cleanupTemporaryEncryptedFile()
        clearTransientInput()
    }

    /// Supersedes a copy still waiting on the clipboard-notice decision, so a
    /// late answer cannot write ciphertext the user has already cleared.
    private func supersedePendingClipboardCopy() {
        clipboardToken &+= 1
    }

    func clearTransientInput() {
        fileImportRequestGate.invalidate()
        plaintext = ""
        recipientSearchText = ""
        selectedRecipients.removeAll()
        recipientTagFilterState.clear()
        ciphertext = nil
        resultQuantumSafety = nil
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

    /// Re-seeds the toggles the ordinary-settings domain owns after it unlocks,
    /// relocks, or is edited. Each policy gates only its own assignment: a host
    /// that pins one toggle must keep receiving refreshes for the other, which a
    /// single shared guard would deny it.
    func refreshProtectedOrdinarySettings() {
        if configuration.signingPolicy == .appDefault {
            signMessage = protectedOrdinarySettings.signMessages
        }
        if configuration.encryptToSelfPolicy == .appDefault {
            encryptToSelf = protectedOrdinarySettings.encryptToSelf
        }
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
        resultQuantumSafety = classifyEncryptedFileQuantumSafety(at: output.fileURL)
    }

    /// PKESK packets precede the encrypted container, so a bounded prefix of
    /// the streamed output is enough to classify the whole file; any read or
    /// parse failure means no claim (nil), never a wrong one.
    private func classifyEncryptedFileQuantumSafety(at url: URL) -> MessageQuantumSafety? {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return nil
        }
        defer { try? handle.close() }
        guard let prefix = try? handle.read(upToCount: 262_144), !prefix.isEmpty else {
            return nil
        }
        return try? messageQuantumSafetyAction(prefix)
    }

    private func cleanupTemporaryEncryptedFile() {
        encryptedFileOutput?.cleanup()
        encryptedFileOutput = nil
        resultQuantumSafety = nil
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
        signMessage = configuration.signingPolicy.initialValue(
            appDefault: protectedOrdinarySettings.signMessages
        )
    }

    private func applyEncryptToSelfPolicy(from configuration: EncryptView.Configuration) {
        encryptToSelf = configuration.encryptToSelfPolicy.initialValue(
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
