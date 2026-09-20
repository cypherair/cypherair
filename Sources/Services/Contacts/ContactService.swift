import Foundation

/// Contacts for the current session: the vault's contacts domain, reconciled
/// against the owner's keys when it opens, plus the search index over it.
@Observable
final class ContactService: @unchecked Sendable {
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let vault: AppVault
    private let recipientResolver = ContactRecipientResolver()
    private let summaryProjector = ContactSummaryProjector()
    private let snapshotMutator: ContactSnapshotMutator

    private(set) var contactsAvailability: ContactsAvailability = .locked
    private var contactsSearchIndex: ContactsSearchIndex?
    private var openGeneration = 0

    init(
        contactImportAdapter: PGPContactImportAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        vault: AppVault
    ) {
        self.certificateAdapter = certificateAdapter
        self.vault = vault
        snapshotMutator = ContactSnapshotMutator(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter
        )
    }

    /// Opens the contacts domain the unlock produced. Certificate lifecycle
    /// state and certification artifacts are reconciled against
    /// `ownSignerKeys` first; a snapshot that fails its contract is damage.
    @discardableResult
    func openContacts(ownSignerKeys: [PGPKeyIdentity]) async -> ContactsAvailability {
        guard let opened = vault.contacts else {
            clearContactsRuntimeState(availability: vault.isUnlocked ? .damaged : .locked)
            return contactsAvailability
        }
        clearContactsRuntimeState(availability: .opening)
        let generation = openGeneration
        do {
            var reconciled = opened
            let refreshedLifecycleState = try snapshotMutator.refreshCertificateLifecycleState(in: &reconciled)
            let revalidatedCertifications = await snapshotMutator.revalidateCertificationArtifacts(
                in: &reconciled,
                ownSignerCertificates: Dictionary(
                    ownSignerKeys.map { ($0.fingerprint, $0.publicKeyData) },
                    uniquingKeysWith: { first, _ in first }
                )
            )
            let recomputedProjections = try snapshotMutator.recomputeCertificationProjections(in: &reconciled)
            guard generation == openGeneration, vault.isUnlocked else {
                return contactsAvailability
            }
            if refreshedLifecycleState || revalidatedCertifications || recomputedProjections {
                try reconciled.validateContract()
                try vault.saveContacts(reconciled)
            }
            adoptOpenContactsDomain(reconciled)
        } catch {
            guard generation == openGeneration else {
                return contactsAvailability
            }
            clearContactsRuntimeState(availability: .damaged)
        }
        return contactsAvailability
    }

    func resetInMemoryStateAfterLocalDataReset() {
        clearContactsRuntimeState(availability: .locked)
    }

    @discardableResult
    func importContact(
        publicKeyData: Data,
        verificationState: ContactVerificationState = .verified
    ) throws -> ContactImportResult {
        try requireContactsAvailable()
        var snapshot = try currentContactsDomainSnapshot()
        return try applyImportContactMutation(
            publicKeyData: publicKeyData,
            verificationState: verificationState,
            in: &snapshot
        )
    }

    func previewImportCandidateMatch(
        publicKeyData: Data
    ) throws -> ContactCandidateMatch? {
        try requireContactsAvailable()
        return try snapshotMutator.importCandidateMatch(
            publicKeyData: publicKeyData,
            in: currentContactsDomainSnapshot()
        )
    }

    @discardableResult
    func importContactAfterConfirmation(
        publicKeyData: Data,
        verificationState: ContactVerificationState = .verified,
        displayedCandidateMatch: ContactCandidateMatch?
    ) throws -> ContactImportResult {
        try requireContactsAvailable()
        var snapshot = try currentContactsDomainSnapshot()
        let currentCandidateMatch = try snapshotMutator.importCandidateMatch(
            publicKeyData: publicKeyData,
            in: snapshot
        )
        guard currentCandidateMatch == displayedCandidateMatch else {
            throw CypherAirError.contactImportConfirmationStale
        }
        return try applyImportContactMutation(
            publicKeyData: publicKeyData,
            verificationState: verificationState,
            in: &snapshot
        )
    }

    @discardableResult
    private func applyImportContactMutation(
        publicKeyData: Data,
        verificationState: ContactVerificationState,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> ContactImportResult {
        let mutation = try snapshotMutator.addContact(
            publicKeyData: publicKeyData,
            verificationState: verificationState,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
        switch mutation.output {
        case .duplicate(let fingerprint):
            return try importResult(.duplicate, fingerprint: fingerprint, in: snapshot)
        case .updated(let fingerprint):
            return try importResult(.updated, fingerprint: fingerprint, in: snapshot)
        case .added(let fingerprint, let candidateMatch):
            return try importResult(.added(candidate: candidateMatch), fingerprint: fingerprint, in: snapshot)
        }
    }

    func removeContactIdentity(contactId: String) throws {
        try mutate { snapshot in
            try snapshotMutator.removeContactIdentity(contactId: contactId, in: &snapshot).didMutate
        }
    }

    func setVerificationState(
        _ verificationState: ContactVerificationState,
        for fingerprint: String
    ) throws {
        try mutate { snapshot in
            try snapshotMutator.setVerificationState(verificationState, for: fingerprint, in: &snapshot).didMutate
        }
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
        guard let snapshot = openContactsSnapshot,
              let contactsSearchIndex else {
            return []
        }
        let summaries = summaryProjector.identitySummaries(from: snapshot)
        return contactsSearchIndex.filterContacts(
            summaries,
            matching: query,
            tagFilterIds: tagFilterIds,
            scope: .identity,
            contactId: \.contactId
        )
    }

    func recipientContacts(
        matching query: String,
        tagFilterIds: Set<String> = []
    ) -> [ContactRecipientSummary] {
        guard let snapshot = openContactsSnapshot,
              let contactsSearchIndex else {
            return []
        }
        let summaries = summaryProjector.recipientSummaries(from: snapshot)
        return contactsSearchIndex.filterContacts(
            summaries,
            matching: query,
            tagFilterIds: tagFilterIds,
            scope: .recipient,
            contactId: \.contactId
        )
    }

    func contactTagSummaries() -> [ContactTagSummary] {
        guard let snapshot = openContactsSnapshot else {
            return []
        }
        return summaryProjector.tagSummaries(from: snapshot)
    }

    func tagSuggestions(matching query: String) -> [ContactTagSummary] {
        guard contactsAvailability.isAvailable,
              let contactsSearchIndex else {
            return []
        }
        return contactsSearchIndex.tagSuggestions(matching: query)
    }

    var runtimeContactCountForDiagnostics: Int {
        vault.contacts?.keyRecords.count ?? 0
    }

    func requireContactsAvailable() throws {
        guard contactsAvailability.isAvailable else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
    }

    func currentContactsDomainSnapshot() throws -> ContactsDomainSnapshot {
        guard let snapshot = openContactsSnapshot else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
        try snapshot.validateContract()
        return snapshot
    }

    func availableContactIdentity(forContactID contactId: String) -> ContactIdentitySummary? {
        guard let snapshot = openContactsSnapshot else {
            return nil
        }
        return summaryProjector.identitySummary(contactId: contactId, in: snapshot)
    }

    func contactId(forFingerprint fingerprint: String) -> String? {
        availableContactKeyRecord(fingerprint: fingerprint)?.contactId
    }

    func availableKey(fingerprint: String) -> ContactKeySummary? {
        guard let snapshot = openContactsSnapshot else {
            return nil
        }
        return summaryProjector.keySummary(fingerprint: fingerprint, in: snapshot)
    }

    func availableKey(keyId: String) -> ContactKeySummary? {
        guard let keyRecord = availableContactKeyRecord(keyId: keyId) else {
            return nil
        }
        return summaryProjector.keySummary(from: keyRecord)
    }

    func availableContactKeyRecord(fingerprint: String) -> ContactKeyRecord? {
        openContactsSnapshot?.keyRecords.first { $0.fingerprint == fingerprint }
    }

    func availableContactKeyRecord(keyId: String) -> ContactKeyRecord? {
        openContactsSnapshot?.keyRecords.first { $0.keyId == keyId }
    }

    func availableContactKeyRecord(
        contactId: String,
        preferredKeyId: String?
    ) -> ContactKeyRecord? {
        guard let snapshot = openContactsSnapshot else {
            return nil
        }
        let keyRecords = snapshot.keyRecords.filter { $0.contactId == contactId }
        if let preferredKeyId,
           let record = keyRecords.first(where: { $0.keyId == preferredKeyId }) {
            return record
        }
        return keyRecords.first { $0.usageState == .preferred } ?? keyRecords.first
    }

    func certificationArtifacts(
        for keyId: String
    ) -> [ContactCertificationArtifactReference] {
        guard let snapshot = openContactsSnapshot else {
            return []
        }
        return snapshot.certificationArtifacts
            .filter { $0.keyId == keyId }
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
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.saveCertificationArtifact(
            artifact.reference,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
        return mutation.output
    }

    func exportCertificationArtifact(
        artifactId: String
    ) throws -> (data: Data, filename: ExportFilename) {
        try requireContactsAvailable()
        guard let snapshot = openContactsSnapshot,
              let artifact = snapshot.certificationArtifacts.first(where: { $0.artifactId == artifactId }) else {
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
        return (
            try certificateAdapter.armorSignatureForExport(artifact.canonicalSignatureData),
            artifact.resolvedExportFilename
        )
    }

    func requireContactPublicKeyData(fingerprint: String) throws -> Data {
        try requireContactsAvailable()
        guard let publicKeyData = availableContactKeyRecord(fingerprint: fingerprint)?.publicKeyData else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        return publicKeyData
    }

    func requireContactPublicKeyData(keyId: String) throws -> Data {
        try requireContactsAvailable()
        guard let publicKeyData = availableContactKeyRecord(keyId: keyId)?.publicKeyData else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        return publicKeyData
    }

    func candidateSignerPublicKeyData() throws -> [Data] {
        try requireContactsAvailable()
        return contactsVerificationContext().verificationKeys
    }

    func publicKeysForRecipientContactIDs(_ recipientContactIds: [String]) throws -> [Data] {
        try requireContactsAvailable()
        guard let snapshot = openContactsSnapshot else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
        return try recipientResolver.publicKeysForRecipientContactIDs(
            recipientContactIds,
            in: snapshot
        )
    }

    func contactsVerificationContext() -> ContactsVerificationContext {
        let availability = contactsAvailability
        guard availability.allowsContactsVerification,
              let snapshot = openContactsSnapshot else {
            return ContactsVerificationContext(contactKeys: [], availability: availability)
        }
        return ContactsVerificationContext(
            contactKeys: snapshot.keyRecords,
            availability: availability
        )
    }

    func setPreferredKey(fingerprint: String, for contactId: String) throws {
        try mutate { snapshot in
            try snapshotMutator.setPreferredKey(fingerprint: fingerprint, for: contactId, in: &snapshot).didMutate
        }
    }

    func setKeyUsageState(
        _ usageState: ContactKeyUsageState,
        fingerprint: String
    ) throws {
        try mutate { snapshot in
            try snapshotMutator.setKeyUsageState(usageState, fingerprint: fingerprint, in: &snapshot).didMutate
        }
    }

    @discardableResult
    func createTag(named name: String) throws -> ContactTagSummary {
        try mutateReturningTag { snapshot in
            try snapshotMutator.createTag(named: name, in: &snapshot)
        }
    }

    @discardableResult
    func renameTag(
        tagId: String,
        to name: String
    ) throws -> ContactTagSummary {
        try mutateReturningTag { snapshot in
            try snapshotMutator.renameTag(tagId: tagId, to: name, in: &snapshot)
        }
    }

    func deleteTag(tagId: String) throws {
        try mutate { snapshot in
            try snapshotMutator.deleteTag(tagId: tagId, in: &snapshot).didMutate
        }
    }

    @discardableResult
    func addTag(
        named name: String,
        toContactId contactId: String
    ) throws -> ContactTagSummary {
        try mutateReturningTag { snapshot in
            try snapshotMutator.addTag(named: name, toContactId: contactId, in: &snapshot)
        }
    }

    @discardableResult
    func assignTag(
        tagId: String,
        toContactId contactId: String
    ) throws -> ContactTagSummary {
        try mutateReturningTag { snapshot in
            try snapshotMutator.assignTag(tagId: tagId, toContactId: contactId, in: &snapshot)
        }
    }

    func removeTag(
        tagId: String,
        fromContactId contactId: String
    ) throws {
        try mutate { snapshot in
            try snapshotMutator.removeTag(tagId: tagId, fromContactId: contactId, in: &snapshot).didMutate
        }
    }

    func replaceTagMembership(
        tagId: String,
        contactIds: Set<String>
    ) throws {
        try mutate { snapshot in
            try snapshotMutator.replaceTagMembership(tagId: tagId, contactIds: contactIds, in: &snapshot).didMutate
        }
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
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.mergeContact(
            sourceContactId: sourceContactId,
            into: targetContactId,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
        let surviving = try contactSummaryOrThrow(
            mutation.output.targetContactId,
            in: snapshot
        )
        return ContactMergeResult(
            survivingContact: surviving,
            preferredKeyNeedsSelection: surviving.preferredKey == nil
                && surviving.keys.contains(where: { $0.usageState == .additionalActive })
        )
    }

    // MARK: - Mutation plumbing

    private func mutate(_ change: (inout ContactsDomainSnapshot) throws -> Bool) throws {
        try requireContactsAvailable()
        var snapshot = try currentContactsDomainSnapshot()
        if try change(&snapshot) {
            try persistContactsSnapshot(snapshot)
        }
    }

    private func mutateReturningTag(
        _ change: (inout ContactsDomainSnapshot) throws -> ContactSnapshotMutator.Mutation<ContactTag>
    ) throws -> ContactTagSummary {
        try requireContactsAvailable()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try change(&snapshot)
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
        return try tagSummaryOrThrow(mutation.output.tagId, in: snapshot)
    }

    private enum ContactImportResultKind {
        case added(candidate: ContactCandidateMatch?)
        case duplicate
        case updated
    }

    private func importResult(
        _ kind: ContactImportResultKind,
        fingerprint: String,
        in snapshot: ContactsDomainSnapshot
    ) throws -> ContactImportResult {
        let key = try keySummaryOrThrow(fingerprint: fingerprint, in: snapshot)
        let contact = try contactSummaryOrThrow(key.contactId, in: snapshot)
        switch kind {
        case .added(let candidate):
            if let candidate {
                return .addedWithCandidate(
                    contact: contact,
                    key: key,
                    candidate: candidate
                )
            }
            return .added(contact: contact, key: key)
        case .duplicate:
            return .duplicate(contact: contact, key: key)
        case .updated:
            return .updated(contact: contact, key: key)
        }
    }

    private var openContactsSnapshot: ContactsDomainSnapshot? {
        guard contactsAvailability.isAvailable else {
            return nil
        }
        return vault.contacts
    }

    private func persistContactsSnapshot(
        _ snapshot: ContactsDomainSnapshot
    ) throws {
        try snapshot.validateContract()
        try vault.saveContacts(snapshot)
        adoptOpenContactsDomain(snapshot)
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

    private func keySummaryOrThrow(
        fingerprint: String,
        in snapshot: ContactsDomainSnapshot
    ) throws -> ContactKeySummary {
        guard let summary = summaryProjector.keySummary(fingerprint: fingerprint, in: snapshot) else {
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

    private func adoptOpenContactsDomain(_ snapshot: ContactsDomainSnapshot) {
        contactsSearchIndex = ContactsSearchIndex(snapshot: snapshot)
        contactsAvailability = .available
    }

    private func clearContactsRuntimeState(availability: ContactsAvailability) {
        openGeneration &+= 1
        contactsAvailability = availability
        contactsSearchIndex = nil
    }
}

extension ContactService: VaultRelockParticipant {
    func relockVault() async throws {
        clearContactsRuntimeState(availability: .locked)
    }
}
