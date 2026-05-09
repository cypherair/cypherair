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
    ) async throws -> AppTemporaryArtifact

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
    @ObservationIgnored private var encryptedFileArtifact: AppTemporaryArtifact?
    private var pendingInitialRecipientFingerprints: Set<String> = []

    var encryptMode: EncryptView.EncryptMode = .text
    var plaintext = ""
    var recipientSearchText = ""
    var selectedRecipients: Set<String> = []
    var selectedRecipientListIds: Set<String> = []
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
        fileEncryptionAction: FileEncryptionAction? = nil
    ) {
        self.configuration = configuration
        self.operation = operation
        self.exportController = exportController
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.appConfiguration = config
        self.protectedOrdinarySettings = protectedOrdinarySettings
        self.authLifecycleTraceStore = authLifecycleTraceStore
        self.protectedSettingsHost = protectedSettingsHost
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

    var recipientLists: [RecipientListSummary] {
        contactService.recipientListSummaries()
    }

    var effectiveRecipientContactIds: [String] {
        let selectedListMemberIds = recipientLists
            .filter { selectedRecipientListIds.contains($0.recipientListId) }
            .flatMap(\.memberContactIds)
        return dedupedContactIds(Array(selectedRecipients) + selectedListMemberIds)
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

    var selectedRecipientListsContainInvalidMembers: Bool {
        recipientLists.contains { list in
            selectedRecipientListIds.contains(list.recipientListId) && !list.canEncryptToAll
        }
    }

    var encryptButtonDisabled: Bool {
        if operation.isRunning {
            return true
        }
        if effectiveRecipientContactIds.isEmpty {
            return true
        }
        if selectedRecipientListsContainInvalidMembers {
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

    func handleAppear() {
        applyPrefilledPlaintextIfNeeded(from: configuration)
        applyInitialRecipientSelection(from: configuration)
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

        if previousConfiguration.initialRecipientContactIds != configuration.initialRecipientContactIds ||
            previousConfiguration.initialRecipientFingerprints != configuration.initialRecipientFingerprints {
            syncRuntimeRecipientSelection(from: configuration)
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

    func handleContactsAvailabilityChange(
        from previousAvailability: ContactsAvailability,
        to currentAvailability: ContactsAvailability
    ) {
        guard !previousAvailability.isAvailable,
              currentAvailability.isAvailable,
              !pendingInitialRecipientFingerprints.isEmpty else {
            return
        }

        let resolvedContactIds = pendingInitialRecipientFingerprints.compactMap { fingerprint in
            contactService.contactId(forFingerprint: fingerprint)
        }
        if !resolvedContactIds.isEmpty {
            selectedRecipients.formUnion(resolvedContactIds)
        }
        pendingInitialRecipientFingerprints = []
    }

    func toggleRecipient(_ contactId: String, isOn: Bool) {
        if isOn {
            selectedRecipients.insert(contactId)
        } else {
            selectedRecipients.remove(contactId)
        }
    }

    func toggleRecipientList(_ recipientListId: String, isOn: Bool) {
        if isOn {
            guard recipientLists.first(where: { $0.recipientListId == recipientListId })?.canEncryptToAll == true else {
                selectedRecipientListIds.remove(recipientListId)
                return
            }
            selectedRecipientListIds.insert(recipientListId)
        } else {
            selectedRecipientListIds.remove(recipientListId)
        }
    }

    func requestFileImport() {
        guard configuration.allowsFileInput else { return }
        showFileImporter = true
    }

    func handleImportedFile(_ url: URL) {
        cleanupTemporaryEncryptedFile()
        selectedFileURL = url
        selectedFileName = url.lastPathComponent
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
            Task { @MainActor [weak self] in
                guard let self else { return }
                let shouldShowNotice = await self.protectedSettingsHost?.clipboardNoticeDecision() ?? true
                self.operation.copyToClipboard(
                    ciphertextString,
                    shouldShowNotice: shouldShowNotice
                )
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
        cleanupTemporaryEncryptedFile()
    }

    func handleContentClearGenerationChange() {
        cleanupTemporaryEncryptedFile()
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

        let currentRecipientLists = recipientLists
        let currentRecipientListIds = Set(currentRecipientLists.map(\.recipientListId))
        let staleRecipientListIds = selectedRecipientListIds.subtracting(currentRecipientListIds)

        if !staleDirectRecipientIds.isEmpty || !staleRecipientListIds.isEmpty {
            selectedRecipients.subtract(staleDirectRecipientIds)
            selectedRecipientListIds.subtract(staleRecipientListIds)
            throw CypherAirError.encryptionFailed(
                reason: String(
                    localized: "encrypt.recipients.staleSelection",
                    defaultValue: "Recipient selection changed. Review recipients and try again."
                )
            )
        }

        let selectedLists = currentRecipientLists.filter {
            selectedRecipientListIds.contains($0.recipientListId)
        }
        guard !selectedLists.contains(where: { !$0.canEncryptToAll }) else {
            throw CypherAirError.encryptionFailed(
                reason: String(
                    localized: "encrypt.recipientLists.invalidSelection",
                    defaultValue: "A selected list now needs preferred keys before it can be used."
                )
            )
        }

        let selectedListMemberIds = selectedLists.flatMap(\.memberContactIds)
        let recipientContactIds = dedupedContactIds(Array(selectedRecipients) + selectedListMemberIds)
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
        let resolution = initialRecipientResolution(from: configuration)
        pendingInitialRecipientFingerprints = resolution.pendingFingerprints
        selectedRecipientListIds.removeAll()
        if !configuration.initialRecipientContactIds.isEmpty {
            selectedRecipients = Set(resolution.contactIds)
        } else if !configuration.initialRecipientFingerprints.isEmpty,
                  resolution.pendingFingerprints.isEmpty {
            selectedRecipients = Set(resolution.contactIds)
        }
    }

    private func syncRuntimeRecipientSelection(from configuration: EncryptView.Configuration) {
        let resolution = initialRecipientResolution(from: configuration)
        pendingInitialRecipientFingerprints = resolution.pendingFingerprints
        selectedRecipients = Set(resolution.contactIds)
        selectedRecipientListIds.removeAll()
    }

    private func initialRecipientResolution(
        from configuration: EncryptView.Configuration
    ) -> (contactIds: [String], pendingFingerprints: Set<String>) {
        if !configuration.initialRecipientContactIds.isEmpty {
            guard contactsAvailability.isAvailable else {
                return (configuration.initialRecipientContactIds, [])
            }
            let availableRecipientIds = Set(contactService.recipientContacts(matching: "").map(\.contactId))
            let contactIds = configuration.initialRecipientContactIds.filter {
                availableRecipientIds.contains($0)
            }
            return (contactIds, [])
        }
        guard !configuration.initialRecipientFingerprints.isEmpty else {
            return ([], [])
        }
        guard contactsAvailability.isAvailable else {
            return ([], Set(configuration.initialRecipientFingerprints))
        }
        let contactIds = configuration.initialRecipientFingerprints.compactMap { fingerprint in
            contactService.contactId(forFingerprint: fingerprint)
        }
        return (contactIds, [])
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
