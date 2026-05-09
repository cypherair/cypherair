import Foundation

/// Result of attempting to add a contact.
enum AddContactResult {
    /// Contact was added successfully.
    case added(Contact)
    /// Contact was added as a new person-centered identity, and the imported
    /// key appears related to one or more existing identities.
    case addedWithCandidate(Contact, ContactCandidateMatch)
    /// Contact already exists (same fingerprint). No material changes were needed.
    case duplicate(Contact)
    /// Existing same-fingerprint contact absorbed new public update material.
    case updated(Contact)
    /// Legacy flat Contacts only: same userId but different fingerprint detected.
    /// The caller must confirm before the old key is replaced. Protected-domain
    /// Contacts import different fingerprints as separate identities instead.
    case keyUpdateDetected(newContact: Contact, existingContact: Contact, keyData: Data)
}

/// Manages contacts (imported public keys).
/// Production persistence lives in the protected contacts app-data domain after post-auth unlock.
/// The legacy Documents/contacts repository is retained only for migration, compatibility fallback,
/// quarantine, and cleanup.
@Observable
final class ContactService: @unchecked Sendable {
    /// All imported contacts.
    private var contacts: [Contact] = []

    private let engine: PgpEngine
    private let repository: ContactRepository
    private let domainRepository: ContactsDomainRepository
    private let legacyMigrationSource: ContactsLegacyMigrationSource
    private let contactsDomainStore: ContactsDomainStore?
    private let importMatcher = ContactImportMatcher()
    private let recipientResolver = ContactRecipientResolver()
    private let summaryProjector = ContactSummaryProjector()
    private let snapshotMutator: ContactSnapshotMutator
    private(set) var contactsAvailability: ContactsAvailability = .locked
    private var verificationStates: [String: ContactVerificationState] = [:]
    private var runtimeSnapshot: ContactsDomainSnapshot?
    private var contactsSearchIndex: ContactsSearchIndex?
    private(set) var protectedDomainMigrationWarning: String?

    init(
        engine: PgpEngine,
        contactsDirectory: URL? = nil,
        contactsDomainStore: ContactsDomainStore? = nil
    ) {
        self.engine = engine
        let resolvedContactsDirectory: URL
        if let contactsDirectory {
            resolvedContactsDirectory = contactsDirectory
        } else {
            let documentsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            resolvedContactsDirectory = documentsDir.appendingPathComponent(
                "contacts",
                isDirectory: true
            )
        }
        repository = ContactRepository(contactsDirectory: resolvedContactsDirectory)
        domainRepository = ContactsDomainRepository()
        legacyMigrationSource = ContactsLegacyMigrationSource(
            engine: engine,
            repository: repository
        )
        snapshotMutator = ContactSnapshotMutator(engine: engine)
        self.contactsDomainStore = contactsDomainStore
    }

    // MARK: - Post-Auth Contacts Gate

    @discardableResult
    func openContactsAfterPostUnlock(
        gateResult: ContactsPostAuthGateResult,
        wrappingRootKey: () throws -> Data
    ) async -> ContactsAvailability {
        guard let contactsDomainStore else {
            return openLegacyCompatibilityAfterPostUnlock(gateResult: gateResult)
        }
        guard gateResult.allowsProtectedDomainOpen else {
            clearContactsRuntimeState(availability: gateResult.availability)
            return contactsAvailability
        }

        clearContactsRuntimeState(availability: .opening)
        let activeLegacyExistedAtOpenStart = repository.activeLegacySourceExists()
        let quarantineExistedAtOpenStart = repository.quarantineExists()
        var contactsDomainCommittedAtOpenStart = true
        do {
            var wrappingKey = try wrappingRootKey()
            defer {
                wrappingKey.protectedDataZeroize()
            }
            contactsDomainCommittedAtOpenStart = try contactsDomainStore.hasCommittedDomain()
            try await contactsDomainStore.ensureCommittedIfNeeded(
                wrappingRootKey: wrappingKey,
                initialSnapshotProvider: {
                    try legacyMigrationSource.makeInitialSnapshot()
                }
            )
            let openedSnapshot = try await contactsDomainStore.openDomainIfNeeded(
                wrappingRootKey: wrappingKey
            )
            var reconciledSnapshot = openedSnapshot
            if try snapshotMutator.recomputeCertificationProjections(in: &reconciledSnapshot) {
                try contactsDomainStore.replaceSnapshot(reconciledSnapshot)
            }
            try applyProtectedRuntimeSnapshot(reconciledSnapshot)
            retireLegacySourceAfterProtectedOpen(
                activeLegacyExistedAtOpenStart: activeLegacyExistedAtOpenStart,
                quarantineExistedAtOpenStart: quarantineExistedAtOpenStart
            )
            return contactsAvailability
        } catch {
            let contactsDomainCommittedAfterFailure = (try? contactsDomainStore.hasCommittedDomain()) ?? true
            if !contactsDomainCommittedAtOpenStart,
               !contactsDomainCommittedAfterFailure,
               activeLegacyExistedAtOpenStart,
               !quarantineExistedAtOpenStart,
               gateResult.allowsLegacyCompatibilityLoad {
                return openLegacyCompatibilityAfterPostUnlock(gateResult: gateResult)
            }
            clearContactsRuntimeState(availability: .recoveryNeeded)
            return contactsAvailability
        }
    }

    // MARK: - Post-Auth Legacy Compatibility Gate

    @discardableResult
    func openLegacyCompatibilityAfterPostUnlock(
        gateResult: ContactsPostAuthGateResult
    ) -> ContactsAvailability {
        guard gateResult.allowsLegacyCompatibilityLoad else {
            clearContactsRuntimeState(availability: gateResult.availability)
            return contactsAvailability
        }

        clearContactsRuntimeState(availability: .opening)
        do {
            let runtime = try loadLegacyCompatibilityRuntimeValues()
            contacts = runtime.contacts
            verificationStates = runtime.verificationStates
            try refreshCompatibilityProjection()
            return contactsAvailability
        } catch {
            clearContactsRuntimeState(availability: .recoveryNeeded)
            return contactsAvailability
        }
    }

    @discardableResult
    func openLegacyCompatibilityForTests() throws -> ContactsAvailability {
        clearContactsRuntimeState(availability: .opening)
        do {
            let runtime = try loadLegacyCompatibilityRuntimeValues()
            contacts = runtime.contacts
            verificationStates = runtime.verificationStates
            try refreshCompatibilityProjection()
            return contactsAvailability
        } catch {
            clearContactsRuntimeState(availability: .recoveryNeeded)
            throw error
        }
    }

    func resetInMemoryStateAfterLocalDataReset() {
        clearContactsRuntimeState(availability: .locked)
    }

    // MARK: - Add Contact

    /// Import a public key and add it as a contact.
    /// Handles both binary and ASCII-armored input.
    ///
    /// In legacy flat Contacts runtime, returns `.keyUpdateDetected` if the parsed
    /// userId conflicts with another contact's fingerprint, including after a
    /// same-fingerprint merge/update. Protected-domain runtime imports related
    /// different-fingerprint keys as separate identities and returns candidates
    /// for optional later merge.
    ///
    /// - Parameter publicKeyData: The public key data (binary or armored).
    /// - Returns: The result of the add operation.
    @discardableResult
    func addContact(
        publicKeyData: Data,
        verificationState: ContactVerificationState = .verified
    ) throws -> AddContactResult {
        try requireContactsAvailable()
        if contactsAvailability == .availableProtectedDomain {
            return try withProtectedRuntimeRollback {
                try performProtectedAddContact(
                    publicKeyData: publicKeyData,
                    verificationState: verificationState
                )
            }
        }
        return try performAddContact(
            publicKeyData: publicKeyData,
            verificationState: verificationState
        )
    }

    @discardableResult
    private func performAddContact(
        publicKeyData: Data,
        verificationState: ContactVerificationState = .verified
    ) throws -> AddContactResult {
        let validation = try ContactImportPublicCertificateValidator.validate(
            publicKeyData,
            using: engine
        )
        let binaryData = validation.publicCertData
        var contact = makeContact(from: validation, verificationState: verificationState)

        // Check for same-fingerprint duplicate/update
        if let existingIndex = contacts.firstIndex(where: { $0.fingerprint == contact.fingerprint }) {
            let existingContact = contacts[existingIndex]
            let mergedResult: CertificateMergeResult
            do {
                mergedResult = try engine.mergePublicCertificateUpdate(
                    existingCert: existingContact.publicKeyData,
                    incomingCertOrUpdate: binaryData
                )
            } catch {
                throw ContactImportPublicCertificateValidator.mapError(error)
            }
            let resolvedVerificationState: ContactVerificationState =
                (existingContact.isVerified || verificationState == .verified)
                ? .verified
                : existingContact.verificationState

            switch mergedResult.outcome {
            case .noOp:
                if contacts[existingIndex].verificationState != resolvedVerificationState {
                    contacts[existingIndex].verificationState = resolvedVerificationState
                    verificationStates[contact.fingerprint] = resolvedVerificationState
                    try saveVerificationStatesIfLegacy(verificationStates)
                }
                try refreshRuntimeProjectionAfterMutation()
                return .duplicate(contacts[existingIndex])

            case .updated:
                let updatedValidation = try ContactImportPublicCertificateValidator.validate(
                    mergedResult.mergedCertData,
                    using: engine
                )
                let updatedContact = makeContact(
                    from: updatedValidation,
                    verificationState: resolvedVerificationState
                )

                if let conflictingContact = importMatcher.conflictingLegacyContact(
                    forUserId: updatedContact.userId,
                    excludingFingerprint: updatedContact.fingerprint,
                    contacts: contacts
                ) {
                    var replacementContact = updatedContact
                    replacementContact.verificationState = .verified
                    return .keyUpdateDetected(
                        newContact: replacementContact,
                        existingContact: conflictingContact,
                        keyData: mergedResult.mergedCertData
                    )
                }

                try savePublicKeyIfLegacy(
                    mergedResult.mergedCertData,
                    fingerprint: existingContact.fingerprint
                )
                verificationStates[updatedContact.fingerprint] = updatedContact.verificationState
                try saveVerificationStatesIfLegacy(verificationStates)
                contacts[existingIndex] = updatedContact
                try refreshRuntimeProjectionAfterMutation()
                return .updated(updatedContact)
            }
        }

        // Check for same userId but different fingerprint (key update)
        if let existingContact = importMatcher.conflictingLegacyContact(
            forUserId: contact.userId,
            excludingFingerprint: contact.fingerprint,
            contacts: contacts
        ) {
            contact.verificationState = .verified
            // Different fingerprint = key regenerated — caller must confirm before replacing.
            return .keyUpdateDetected(
                newContact: contact,
                existingContact: existingContact,
                keyData: binaryData
            )
        }

        try savePublicKeyIfLegacy(binaryData, fingerprint: contact.fingerprint)
        verificationStates[contact.fingerprint] = contact.verificationState
        try saveVerificationStatesIfLegacy(verificationStates)
        contacts.append(contact)
        try refreshRuntimeProjectionAfterMutation()
        return .added(contact)
    }

    @discardableResult
    private func performProtectedAddContact(
        publicKeyData: Data,
        verificationState: ContactVerificationState = .verified
    ) throws -> AddContactResult {
        var snapshot = try mutableRuntimeSnapshot()
        let mutation = try snapshotMutator.addContact(
            publicKeyData: publicKeyData,
            verificationState: verificationState,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistProtectedRuntimeSnapshot(snapshot)
        }

        switch mutation.output {
        case .duplicate(let fingerprint):
            let contact = try compatibilityContact(forFingerprint: fingerprint, in: snapshot)
            return .duplicate(contact)
        case .updated(let fingerprint):
            let contact = try compatibilityContact(forFingerprint: fingerprint, in: snapshot)
            return .updated(contact)
        case .added(let fingerprint, let candidateMatch):
            let contact = try compatibilityContact(forFingerprint: fingerprint, in: snapshot)
            if let candidateMatch {
                return .addedWithCandidate(contact, candidateMatch)
            }
            return .added(contact)
        }
    }

    /// Legacy flat Contacts compatibility only: apply a user-confirmed key
    /// replacement after `addContact` returns `.keyUpdateDetected`. Protected-domain
    /// Contacts does not support replacement; import the new key separately and
    /// merge identities if needed.
    ///
    /// - Parameters:
    ///   - existingFingerprint: Fingerprint of the contact being removed/replaced.
    ///   - keyData: Binary public key data for the new contact.
    /// - Returns: The authoritative verified contact rebuilt from validated public bytes.
    @discardableResult
    func confirmKeyUpdate(existingFingerprint: String, keyData: Data) throws -> Contact {
        try requireContactsAvailable()
        if contactsAvailability == .availableProtectedDomain {
            throw CypherAirError.contactKeyReplacementUnsupported
        }
        return try performConfirmKeyUpdate(
            existingFingerprint: existingFingerprint,
            keyData: keyData
        )
    }

    @discardableResult
    private func performConfirmKeyUpdate(existingFingerprint: String, keyData: Data) throws -> Contact {
        let validation = try ContactImportPublicCertificateValidator.validate(keyData, using: engine)
        let verifiedContact = makeContact(from: validation, verificationState: .verified)

        // Write new key first — if this fails, the old contact remains intact
        try savePublicKeyIfLegacy(
            validation.publicCertData,
            fingerprint: verifiedContact.fingerprint
        )

        if existingFingerprint != verifiedContact.fingerprint {
            try removePublicKeyIfLegacy(fingerprint: existingFingerprint)
            contacts.removeAll { $0.fingerprint == existingFingerprint }
            verificationStates.removeValue(forKey: existingFingerprint)
        }

        verificationStates[verifiedContact.fingerprint] = .verified

        if let existingIndex = contacts.firstIndex(where: { $0.fingerprint == verifiedContact.fingerprint }) {
            contacts[existingIndex] = verifiedContact
        } else {
            contacts.append(verifiedContact)
        }

        try saveVerificationStatesIfLegacy(verificationStates)
        try refreshRuntimeProjectionAfterMutation()
        return verifiedContact
    }

    // MARK: - Remove Contact

    /// Remove a contact and delete their public key file.
    func removeContact(fingerprint: String) throws {
        try requireContactsAvailable()
        if contactsAvailability == .availableProtectedDomain {
            try withProtectedRuntimeRollback {
                try performProtectedRemoveKey(fingerprint: fingerprint)
            }
            return
        }
        try performRemoveContact(fingerprint: fingerprint)
    }

    func removeContactIdentity(contactId: String) throws {
        try requireContactsAvailable()
        if contactsAvailability == .availableProtectedDomain {
            try withProtectedRuntimeRollback {
                var snapshot = try mutableRuntimeSnapshot()
                let mutation = try snapshotMutator.removeContactIdentity(
                    contactId: contactId,
                    in: &snapshot
                )
                if mutation.didMutate {
                    try persistProtectedRuntimeSnapshot(snapshot)
                }
            }
            return
        }

        let fingerprints = contacts
            .filter { $0.contactId == contactId || "legacy-contact-\($0.fingerprint)" == contactId }
            .map(\.fingerprint)
        for fingerprint in fingerprints {
            try performRemoveContact(fingerprint: fingerprint)
        }
    }

    private func performRemoveContact(fingerprint: String) throws {
        try removePublicKeyIfLegacy(fingerprint: fingerprint)
        contacts.removeAll { $0.fingerprint == fingerprint }
        verificationStates.removeValue(forKey: fingerprint)
        try saveVerificationStatesIfLegacy(verificationStates)
        try refreshRuntimeProjectionAfterMutation()
    }

    func setVerificationState(
        _ verificationState: ContactVerificationState,
        for fingerprint: String
    ) throws {
        try requireContactsAvailable()
        if contactsAvailability == .availableProtectedDomain {
            try withProtectedRuntimeRollback {
                try performProtectedSetVerificationState(verificationState, for: fingerprint)
            }
            return
        }
        try performSetVerificationState(verificationState, for: fingerprint)
    }

    private func performSetVerificationState(
        _ verificationState: ContactVerificationState,
        for fingerprint: String
    ) throws {
        guard let index = contacts.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }

        contacts[index].verificationState = verificationState
        verificationStates[fingerprint] = verificationState
        try saveVerificationStatesIfLegacy(verificationStates)
        try refreshRuntimeProjectionAfterMutation()
    }

    private func performProtectedSetVerificationState(
        _ verificationState: ContactVerificationState,
        for fingerprint: String
    ) throws {
        var snapshot = try mutableRuntimeSnapshot()
        let mutation = try snapshotMutator.setVerificationState(
            verificationState,
            for: fingerprint,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistProtectedRuntimeSnapshot(snapshot)
        }
    }

    private func performProtectedRemoveKey(fingerprint: String) throws {
        var snapshot = try mutableRuntimeSnapshot()
        let mutation = try snapshotMutator.removeKey(
            fingerprint: fingerprint,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistProtectedRuntimeSnapshot(snapshot)
        }
    }

    var availableContacts: [Contact] {
        guard contactsAvailability.isAvailable else {
            return []
        }
        return contacts
    }

    var availableContactIdentities: [ContactIdentitySummary] {
        contactIdentities(matching: "", tagFilterIds: [])
    }

    var availableRecipientContacts: [ContactRecipientSummary] {
        recipientContacts(matching: "", tagFilterIds: [])
    }

    func contactIdentities(
        matching query: String,
        tagFilterIds: Set<String> = []
    ) -> [ContactIdentitySummary] {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return []
        }
        let summaries = summaryProjector.identitySummaries(from: runtimeSnapshot)
        return searchIndex(for: runtimeSnapshot).filterContacts(
            summaries,
            matching: query,
            tagFilterIds: tagFilterIds,
            contactId: \.contactId
        )
    }

    func recipientContacts(
        matching query: String,
        tagFilterIds: Set<String> = []
    ) -> [ContactRecipientSummary] {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return []
        }
        let summaries = summaryProjector.recipientSummaries(from: runtimeSnapshot)
        return searchIndex(for: runtimeSnapshot).filterContacts(
            summaries,
            matching: query,
            tagFilterIds: tagFilterIds,
            contactId: \.contactId
        )
    }

    func contactTagSummaries() -> [ContactTagSummary] {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return []
        }
        return summaryProjector.tagSummaries(from: runtimeSnapshot)
    }

    func recipientListSummaries() -> [RecipientListSummary] {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return []
        }
        return summaryProjector.recipientListSummaries(from: runtimeSnapshot)
    }

    func tagSuggestions(matching query: String) -> [ContactTagSummary] {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return []
        }
        return searchIndex(for: runtimeSnapshot).tagSuggestions(matching: query)
    }

    var runtimeContactCountForDiagnostics: Int {
        contacts.count
    }

    func requireContactsAvailable() throws {
        guard contactsAvailability.isAvailable else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
    }

    func currentCompatibilitySnapshot() throws -> ContactsDomainSnapshot {
        try requireContactsAvailable()
        if let runtimeSnapshot {
            try runtimeSnapshot.validateContract()
            return runtimeSnapshot
        }
        return try domainRepository.makeCompatibilitySnapshot(from: contacts)
    }

    func compatibilityContacts(
        from snapshot: ContactsDomainSnapshot
    ) throws -> [Contact] {
        try domainRepository.makeCompatibilityContacts(from: snapshot)
    }

    func seedContactsDomainRuntimeStateForTests() {
        domainRepository.seedRuntimeStateForTests()
    }

    var contactsDomainRuntimeStateIsClearedForTests: Bool {
        contacts.isEmpty &&
        verificationStates.isEmpty &&
        runtimeSnapshot == nil &&
        contactsSearchIndex == nil &&
        contactsAvailability == .locked &&
        domainRepository.runtimeStateIsClearedForTests
    }

    // MARK: - Lookup

    /// Find a contact by fingerprint.
    func availableContact(forFingerprint fingerprint: String) -> Contact? {
        guard contactsAvailability.isAvailable else {
            return nil
        }

        return contacts.first { $0.fingerprint == fingerprint }
    }

    func availableContactIdentity(forContactID contactId: String) -> ContactIdentitySummary? {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return nil
        }
        return summaryProjector.identitySummary(contactId: contactId, in: runtimeSnapshot)
    }

    func contactId(forFingerprint fingerprint: String) -> String? {
        guard contactsAvailability.isAvailable else {
            return nil
        }
        if let runtimeSnapshot,
           let keyRecord = runtimeSnapshot.keyRecords.first(where: { $0.fingerprint == fingerprint }) {
            return keyRecord.contactId
        }
        guard let contact = contacts.first(where: { $0.fingerprint == fingerprint }) else {
            return nil
        }
        return contact.contactId ?? "legacy-contact-\(fingerprint)"
    }

    func availableKey(fingerprint: String) -> ContactKeySummary? {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return nil
        }
        return summaryProjector.keySummary(fingerprint: fingerprint, in: runtimeSnapshot)
    }

    func availableKey(keyId: String) -> ContactKeySummary? {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot,
              let keyRecord = runtimeSnapshot.keyRecords.first(where: { $0.keyId == keyId }) else {
            return nil
        }
        return summaryProjector.keySummary(from: keyRecord)
    }

    func availableContactKeyRecord(keyId: String) -> ContactKeyRecord? {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return nil
        }
        return runtimeSnapshot.keyRecords.first { $0.keyId == keyId }
    }

    func availableContactKeyRecord(
        contactId: String,
        preferredKeyId: String?
    ) -> ContactKeyRecord? {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return nil
        }
        let keyRecords = runtimeSnapshot.keyRecords.filter { $0.contactId == contactId }
        if let preferredKeyId,
           let record = keyRecords.first(where: { $0.keyId == preferredKeyId }) {
            return record
        }
        return keyRecords.first { $0.usageState == .preferred } ?? keyRecords.first
    }

    func certificationArtifacts(
        for keyId: String
    ) -> [ContactCertificationArtifactReference] {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return []
        }
        return runtimeSnapshot.certificationArtifacts
            .filter { $0.keyId == keyId }
            .sorted { lhs, rhs in
                if lhs.createdAt != rhs.createdAt {
                    return lhs.createdAt > rhs.createdAt
                }
                return lhs.artifactId < rhs.artifactId
            }
    }

    func certificationArtifacts(
        forContactId contactId: String
    ) -> [ContactCertificationArtifactReference] {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return []
        }
        let keyIds = Set(
            runtimeSnapshot.keyRecords
                .filter { $0.contactId == contactId }
                .map(\.keyId)
        )
        return runtimeSnapshot.certificationArtifacts
            .filter { keyIds.contains($0.keyId) }
            .sorted { lhs, rhs in
                if lhs.createdAt != rhs.createdAt {
                    return lhs.createdAt > rhs.createdAt
                }
                return lhs.artifactId < rhs.artifactId
            }
    }

    @discardableResult
    func saveCertificationArtifact(
        _ artifact: VerifiedContactCertificationArtifact
    ) throws -> ContactCertificationArtifactReference {
        try requireContactsAvailable()
        guard contactsAvailability == .availableProtectedDomain else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }

        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.saveCertificationArtifact(
                artifact.reference,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return mutation.output
        }
    }

    @discardableResult
    func updateCertificationArtifactValidation(
        artifactId: String,
        status: ContactCertificationValidationStatus
    ) throws -> ContactCertificationArtifactReference {
        try requireContactsAvailable()
        guard contactsAvailability == .availableProtectedDomain else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
        guard status != .valid else {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contactcertification.update.validRequiresVerification",
                    defaultValue: "Certification signatures must be revalidated before they can be marked valid."
                )
            )
        }

        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.updateCertificationArtifactValidation(
                artifactId: artifactId,
                status: status,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return mutation.output
        }
    }

    func exportCertificationArtifact(
        artifactId: String
    ) throws -> (data: Data, filename: String) {
        try requireContactsAvailable()
        guard let runtimeSnapshot,
              let artifact = runtimeSnapshot.certificationArtifacts.first(where: { $0.artifactId == artifactId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        guard !artifact.canonicalSignatureData.isEmpty else {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contactcertification.export.empty",
                    defaultValue: "The saved certification signature cannot be exported because its signature bytes are missing."
                )
            )
        }

        do {
            return (
                try engine.armor(data: artifact.canonicalSignatureData, kind: .signature),
                artifact.resolvedExportFilename
            )
        } catch {
            throw CypherAirError.from(error) { .armorError(reason: $0) }
        }
    }

    func refreshCertificationProjections() throws {
        try requireContactsAvailable()
        guard contactsAvailability == .availableProtectedDomain else {
            return
        }
        try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            if try snapshotMutator.recomputeCertificationProjections(in: &snapshot) {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
        }
    }

    func requireAvailableContact(forFingerprint fingerprint: String) throws -> Contact? {
        try requireContactsAvailable()
        return contacts.first { $0.fingerprint == fingerprint }
    }

    /// Find contacts whose fingerprints match the given key IDs.
    /// Key IDs may be short (last 16 hex chars) or full fingerprints.
    ///
    /// WARNING: This method uses suffix/equality matching which does NOT work
    /// for PKESK subkey IDs (which differ from primary fingerprints). For
    /// matching ciphertext recipients against contacts, use PgpEngine.matchRecipients()
    /// instead, which performs correct subkey-to-certificate resolution via Sequoia.
    /// This method currently has zero callers and is retained for potential future use
    /// with pre-resolved primary fingerprints only.
    func availableContacts(matchingKeyIds keyIds: [String]) -> [Contact] {
        guard contactsAvailability.isAvailable else {
            return []
        }

        return contacts.filter { contact in
            keyIds.contains { keyId in
                contact.fingerprint.hasSuffix(keyId.lowercased()) ||
                contact.fingerprint == keyId.lowercased()
            }
        }
    }

    /// Get public key data for a list of contacts.
    func publicKeys(for selectedContacts: [Contact]) throws -> [Data] {
        try requireContactsAvailable()
        return selectedContacts.map { $0.publicKeyData }
    }

    @available(*, deprecated, message: "Use contact ID recipient APIs; this remains only for legacy compatibility.")
    func publicKeysForRecipientFingerprints(_ recipientFingerprints: [String]) throws -> [Data] {
        try legacyPublicKeysForRecipientFingerprints(recipientFingerprints)
    }

    func legacyPublicKeysForRecipientFingerprints(_ recipientFingerprints: [String]) throws -> [Data] {
        try requireContactsAvailable()
        return try recipientResolver.legacyPublicKeysForRecipientFingerprints(
            recipientFingerprints,
            contacts: contacts
        )
    }

    func publicKeysForRecipientContactIDs(_ recipientContactIds: [String]) throws -> [Data] {
        try requireContactsAvailable()
        guard let runtimeSnapshot else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
        return try recipientResolver.publicKeysForRecipientContactIDs(
            recipientContactIds,
            in: runtimeSnapshot
        )
    }

    func contactsForVerificationContext() -> (contacts: [Contact], availability: ContactsAvailability) {
        let availability = contactsAvailability
        guard availability.allowsContactsVerification else {
            return ([], availability)
        }
        return (contacts, availability)
    }

    func setPreferredKey(fingerprint: String, for contactId: String) throws {
        try requireContactsAvailable()
        if contactsAvailability == .availableProtectedDomain {
            try withProtectedRuntimeRollback {
                var snapshot = try mutableRuntimeSnapshot()
                let mutation = try snapshotMutator.setPreferredKey(
                    fingerprint: fingerprint,
                    for: contactId,
                    in: &snapshot
                )
                if mutation.didMutate {
                    try persistProtectedRuntimeSnapshot(snapshot)
                }
            }
        } else {
            try requireContactsAvailable()
        }
    }

    func setKeyUsageState(
        _ usageState: ContactKeyUsageState,
        fingerprint: String
    ) throws {
        try requireContactsAvailable()
        if contactsAvailability == .availableProtectedDomain {
            try withProtectedRuntimeRollback {
                var snapshot = try mutableRuntimeSnapshot()
                let mutation = try snapshotMutator.setKeyUsageState(
                    usageState,
                    fingerprint: fingerprint,
                    in: &snapshot
                )
                if mutation.didMutate {
                    try persistProtectedRuntimeSnapshot(snapshot)
                }
            }
        } else {
            try requireContactsAvailable()
        }
    }

    @discardableResult
    func addTag(
        named name: String,
        toContactId contactId: String
    ) throws -> ContactTagSummary {
        try requireProtectedContactsAvailableForOrganization()
        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.addTag(
                named: name,
                toContactId: contactId,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return try tagSummaryOrThrow(mutation.output.tagId, in: snapshot)
        }
    }

    func removeTag(
        tagId: String,
        fromContactId contactId: String
    ) throws {
        try requireProtectedContactsAvailableForOrganization()
        try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.removeTag(
                tagId: tagId,
                fromContactId: contactId,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
        }
    }

    @discardableResult
    func createRecipientList(
        named name: String,
        memberContactIds: [String] = []
    ) throws -> RecipientListSummary {
        try requireProtectedContactsAvailableForOrganization()
        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.createRecipientList(
                named: name,
                memberContactIds: memberContactIds,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return try recipientListSummaryOrThrow(mutation.output.recipientListId, in: snapshot)
        }
    }

    @discardableResult
    func renameRecipientList(
        _ recipientListId: String,
        to name: String
    ) throws -> RecipientListSummary {
        try requireProtectedContactsAvailableForOrganization()
        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.renameRecipientList(
                recipientListId,
                to: name,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return try recipientListSummaryOrThrow(mutation.output.recipientListId, in: snapshot)
        }
    }

    func deleteRecipientList(_ recipientListId: String) throws {
        try requireProtectedContactsAvailableForOrganization()
        try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.deleteRecipientList(
                recipientListId,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
        }
    }

    @discardableResult
    func setRecipientListMembers(
        _ recipientListId: String,
        memberContactIds: [String]
    ) throws -> RecipientListSummary {
        try requireProtectedContactsAvailableForOrganization()
        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.setRecipientListMembers(
                recipientListId,
                memberContactIds: memberContactIds,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return try recipientListSummaryOrThrow(mutation.output.recipientListId, in: snapshot)
        }
    }

    @discardableResult
    func addContact(
        _ contactId: String,
        toRecipientList recipientListId: String
    ) throws -> RecipientListSummary {
        try requireProtectedContactsAvailableForOrganization()
        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.addContact(
                contactId,
                toRecipientList: recipientListId,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return try recipientListSummaryOrThrow(mutation.output.recipientListId, in: snapshot)
        }
    }

    @discardableResult
    func removeContact(
        _ contactId: String,
        fromRecipientList recipientListId: String
    ) throws -> RecipientListSummary {
        try requireProtectedContactsAvailableForOrganization()
        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.removeContact(
                contactId,
                fromRecipientList: recipientListId,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return try recipientListSummaryOrThrow(mutation.output.recipientListId, in: snapshot)
        }
    }

    func recipientContactIds(forRecipientListId recipientListId: String) throws -> [String] {
        try requireContactsAvailable()
        guard let runtimeSnapshot,
              let recipientList = runtimeSnapshot.recipientLists.first(where: {
                  $0.recipientListId == recipientListId
              }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.recipientList.notFound", defaultValue: "The selected recipient list could not be found.")
            )
        }
        return recipientList.memberContactIds
    }

    @discardableResult
    func mergeContact(
        sourceContactId: String,
        into targetContactId: String
    ) throws -> ContactMergeResult {
        try requireContactsAvailable()
        guard sourceContactId != targetContactId else {
            throw CypherAirError.internalError(
                reason: String(
                    localized: "contacts.merge.sameContact",
                    defaultValue: "Choose two different contacts to merge."
                )
            )
        }

        if contactsAvailability == .availableProtectedDomain {
            return try withProtectedRuntimeRollback {
                var snapshot = try mutableRuntimeSnapshot()
                let mutation = try snapshotMutator.mergeContact(
                    sourceContactId: sourceContactId,
                    into: targetContactId,
                    in: &snapshot
                )
                if mutation.didMutate {
                    try persistProtectedRuntimeSnapshot(snapshot)
                }
                let surviving = try contactSummaryOrThrow(
                    mutation.output.targetContactId,
                    in: snapshot
                )
                return ContactMergeResult(
                    survivingContact: surviving,
                    removedContactId: mutation.output.sourceContactId,
                    preferredKeyNeedsSelection: surviving.preferredKey == nil
                        && surviving.keys.contains(where: { $0.usageState == .additionalActive })
                )
            }
        }

        let sourceFingerprints = contacts
            .filter { $0.contactId == sourceContactId || "legacy-contact-\($0.fingerprint)" == sourceContactId }
            .map(\.fingerprint)
        guard !sourceFingerprints.isEmpty,
              let targetFingerprint = contacts.first(where: {
                  $0.contactId == targetContactId || "legacy-contact-\($0.fingerprint)" == targetContactId
              })?.fingerprint else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        _ = sourceFingerprints
        let target = try contactSummaryOrThrow(
            "legacy-contact-\(targetFingerprint)",
            in: try currentCompatibilitySnapshot()
        )
        return ContactMergeResult(
            survivingContact: target,
            removedContactId: sourceContactId,
            preferredKeyNeedsSelection: false
        )
    }

    // MARK: - Private

    private func mutableRuntimeSnapshot() throws -> ContactsDomainSnapshot {
        if let runtimeSnapshot {
            try runtimeSnapshot.validateContract()
            return runtimeSnapshot
        }
        return try domainRepository.makeCompatibilitySnapshot(from: contacts)
    }

    private func persistProtectedRuntimeSnapshot(
        _ snapshot: ContactsDomainSnapshot
    ) throws {
        guard let contactsDomainStore else {
            throw ProtectedDataError.authorizingUnavailable
        }
        try snapshot.validateContract()
        try contactsDomainStore.replaceSnapshot(snapshot)
        try applyProtectedRuntimeSnapshot(snapshot)
    }

    private func compatibilityContact(
        forFingerprint fingerprint: String,
        in snapshot: ContactsDomainSnapshot
    ) throws -> Contact {
        let projected = try domainRepository.makeCompatibilityContacts(from: snapshot)
        guard let contact = projected.first(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        return contact
    }

    private func contactSummaryOrThrow(
        _ contactId: String,
        in snapshot: ContactsDomainSnapshot
    ) throws -> ContactIdentitySummary {
        guard let summary = summaryProjector.identitySummary(contactId: contactId, in: snapshot) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        return summary
    }

    private func tagSummaryOrThrow(
        _ tagId: String,
        in snapshot: ContactsDomainSnapshot
    ) throws -> ContactTagSummary {
        guard let summary = summaryProjector.tagSummaries(from: snapshot).first(where: {
            $0.tagId == tagId
        }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        return summary
    }

    private func recipientListSummaryOrThrow(
        _ recipientListId: String,
        in snapshot: ContactsDomainSnapshot
    ) throws -> RecipientListSummary {
        guard let summary = summaryProjector.recipientListSummaries(from: snapshot).first(where: {
            $0.recipientListId == recipientListId
        }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.recipientList.notFound", defaultValue: "The selected recipient list could not be found.")
            )
        }
        return summary
    }

    private func requireProtectedContactsAvailableForOrganization() throws {
        try requireContactsAvailable()
        guard contactsAvailability == .availableProtectedDomain else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
    }

    private func searchIndex(for snapshot: ContactsDomainSnapshot) -> ContactsSearchIndex {
        if let contactsSearchIndex {
            return contactsSearchIndex
        }
        let index = ContactsSearchIndex(snapshot: snapshot)
        contactsSearchIndex = index
        return index
    }

    private func loadLegacyCompatibilityRuntimeValues() throws -> ContactsLegacyRuntimeValues {
        try repository.ensureDirectoryExists()
        return try legacyMigrationSource.loadRuntimeValues(repairMetadata: true)
    }

    private func parseContact(
        from binaryData: Data,
        verificationState: ContactVerificationState? = nil
    ) throws -> Contact {
        let keyInfo = try engine.parseKeyInfo(keyData: binaryData)
        let profile = try engine.detectProfile(certData: binaryData)
        let resolvedVerificationState = verificationState
            ?? verificationStates[keyInfo.fingerprint]
            ?? .verified

        return Contact(
            fingerprint: keyInfo.fingerprint,
            keyVersion: keyInfo.keyVersion,
            profile: profile,
            userId: keyInfo.userId,
            isRevoked: keyInfo.isRevoked,
            isExpired: keyInfo.isExpired,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            verificationState: resolvedVerificationState,
            publicKeyData: binaryData,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo
        )
    }

    private func makeContact(
        from validation: PublicCertificateValidationResult,
        verificationState: ContactVerificationState? = nil
    ) -> Contact {
        let resolvedVerificationState = verificationState
            ?? verificationStates[validation.keyInfo.fingerprint]
            ?? .verified

        return Contact(
            fingerprint: validation.keyInfo.fingerprint,
            keyVersion: validation.keyInfo.keyVersion,
            profile: validation.profile,
            userId: validation.keyInfo.userId,
            isRevoked: validation.keyInfo.isRevoked,
            isExpired: validation.keyInfo.isExpired,
            hasEncryptionSubkey: validation.keyInfo.hasEncryptionSubkey,
            verificationState: resolvedVerificationState,
            publicKeyData: validation.publicCertData,
            primaryAlgo: validation.keyInfo.primaryAlgo,
            subkeyAlgo: validation.keyInfo.subkeyAlgo
        )
    }

    private func refreshCompatibilityProjection() throws {
        runtimeSnapshot = try domainRepository.updateCompatibilityRuntime(from: contacts)
        contactsSearchIndex = runtimeSnapshot.map(ContactsSearchIndex.init(snapshot:))
        contactsAvailability = .availableLegacyCompatibility
    }

    private func refreshRuntimeProjectionAfterMutation() throws {
        if contactsAvailability == .availableProtectedDomain {
            try persistProtectedRuntimeContacts()
        } else {
            try refreshCompatibilityProjection()
        }
    }

    private func applyProtectedRuntimeSnapshot(_ snapshot: ContactsDomainSnapshot) throws {
        let projectedContacts = try domainRepository.updateProtectedRuntime(from: snapshot)
        contacts = projectedContacts
        runtimeSnapshot = snapshot
        contactsSearchIndex = ContactsSearchIndex(snapshot: snapshot)
        verificationStates = Dictionary(
            uniqueKeysWithValues: projectedContacts.map {
                ($0.fingerprint, $0.verificationState)
            }
        )
        contactsAvailability = .availableProtectedDomain
    }

    private func persistProtectedRuntimeContacts() throws {
        guard let contactsDomainStore else {
            throw ProtectedDataError.authorizingUnavailable
        }
        let snapshot: ContactsDomainSnapshot
        if let runtimeSnapshot {
            snapshot = runtimeSnapshot
        } else {
            snapshot = try domainRepository.makeCompatibilitySnapshot(from: contacts)
        }
        try contactsDomainStore.replaceSnapshot(snapshot)
        try applyProtectedRuntimeSnapshot(snapshot)
    }

    private func retireLegacySourceAfterProtectedOpen(
        activeLegacyExistedAtOpenStart: Bool,
        quarantineExistedAtOpenStart: Bool
    ) {
        protectedDomainMigrationWarning = nil
        do {
            if quarantineExistedAtOpenStart {
                try repository.deleteQuarantineIfPresent()
            }
            if activeLegacyExistedAtOpenStart || repository.activeLegacySourceExists() {
                try repository.moveActiveLegacySourceToQuarantine()
            }
        } catch {
            protectedDomainMigrationWarning = Self.protectedDomainMigrationWarningMessage()
        }
    }

    private func savePublicKeyIfLegacy(_ data: Data, fingerprint: String) throws {
        guard contactsAvailability != .availableProtectedDomain else {
            return
        }
        try repository.savePublicKey(data, fingerprint: fingerprint)
    }

    private func removePublicKeyIfLegacy(fingerprint: String) throws {
        guard contactsAvailability != .availableProtectedDomain else {
            return
        }
        try repository.removePublicKey(fingerprint: fingerprint)
    }

    private func saveVerificationStatesIfLegacy(
        _ verificationStates: [String: ContactVerificationState]
    ) throws {
        guard contactsAvailability != .availableProtectedDomain else {
            return
        }
        try repository.saveVerificationStates(verificationStates)
    }

    private func withProtectedRuntimeRollback<T>(_ operation: () throws -> T) throws -> T {
        let previousContacts = contacts
        let previousVerificationStates = verificationStates
        let previousAvailability = contactsAvailability
        let previousRuntimeSnapshot = runtimeSnapshot
        let previousSearchIndex = contactsSearchIndex
        let previousMigrationWarning = protectedDomainMigrationWarning

        do {
            return try operation()
        } catch {
            contacts = previousContacts
            verificationStates = previousVerificationStates
            contactsAvailability = previousAvailability
            runtimeSnapshot = previousRuntimeSnapshot
            contactsSearchIndex = previousSearchIndex
            protectedDomainMigrationWarning = previousMigrationWarning
            if let snapshot = contactsDomainStore?.snapshot {
                try? applyProtectedRuntimeSnapshot(snapshot)
            }
            throw error
        }
    }

    private func clearContactsRuntimeState(availability: ContactsAvailability = .locked) {
        contacts = []
        verificationStates = [:]
        contactsAvailability = availability
        runtimeSnapshot = nil
        contactsSearchIndex = nil
        protectedDomainMigrationWarning = nil
        domainRepository.clearRuntimeState()
    }

    private static func protectedDomainMigrationWarningMessage() -> String {
        String(
            localized: "app.loadWarning.contactsMigration",
            defaultValue: "Contacts were opened from protected app data, but legacy contact files could not be fully retired. Restart CypherAir and unlock again to retry cleanup."
        )
    }
}

extension ContactService: ProtectedDataRelockParticipant {
    func relockProtectedData() async throws {
        clearContactsRuntimeState()
        try await contactsDomainStore?.relockProtectedData()
    }
}
