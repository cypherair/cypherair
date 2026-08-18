import Foundation

/// Manages contacts (imported public keys).
/// Production persistence lives in the protected contacts app-data domain after post-auth unlock.
///
/// The decrypted contacts payload has one in-memory owner, `ContactsDomainStore`,
/// which holds exactly what its database contains. This service keeps only state
/// derived from that snapshot — the search index and the availability the UI
/// observes — and advances it after a write commits, so a failed mutation cannot
/// leave a second copy of the payload disagreeing with the database.
@Observable
final class ContactService: @unchecked Sendable {
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let contactsDomainStore: ContactsDomainStore?
    private let recipientResolver = ContactRecipientResolver()
    private let summaryProjector = ContactSummaryProjector()
    private let snapshotMutator: ContactSnapshotMutator
    private(set) var contactsAvailability: ContactsAvailability = .locked
    private var contactsSearchIndex: ContactsSearchIndex?

    init(
        contactImportAdapter: PGPContactImportAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        contactsDomainStore: ContactsDomainStore? = nil
    ) {
        self.certificateAdapter = certificateAdapter
        snapshotMutator = ContactSnapshotMutator(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter
        )
        self.contactsDomainStore = contactsDomainStore
    }

    // MARK: - Post-Auth Contacts Gate

    /// Open the contacts domain and reconcile everything cached in it against
    /// the engine before any of it reaches the UI.
    ///
    /// - Parameter ownSignerKeys: the user's own key identities. A certification
    ///   the user made themselves is signed by a key the contacts domain does
    ///   not hold, so without them every self-made certification would come back
    ///   unverifiable. Callers read this on the actor that owns key state and
    ///   pass the values in.
    @discardableResult
    func openContactsAfterPostUnlock(
        gateDecision: ContactsPostAuthGateDecision,
        wrappingRootKey: () throws -> Data,
        ownSignerKeys: [PGPKeyIdentity] = []
    ) async -> ContactsAvailability {
        guard gateDecision.allowsProtectedDomainOpen else {
            clearContactsRuntimeState(availability: gateDecision.availability)
            return contactsAvailability
        }
        guard let contactsDomainStore else {
            clearContactsRuntimeState(availability: .recoveryNeeded)
            return contactsAvailability
        }

        clearContactsRuntimeState(availability: .opening)
        do {
            var wrappingKey = try wrappingRootKey()
            defer {
                wrappingKey.protectedDataZeroize()
            }
            try await contactsDomainStore.ensureCommittedIfNeeded(
                wrappingRootKey: wrappingKey,
                initialSnapshotProvider: {
                    ContactsDomainSnapshot.empty()
                }
            )
            let openedSnapshot = try await contactsDomainStore.openDomainIfNeeded(
                wrappingRootKey: wrappingKey
            )
            var reconciledSnapshot = openedSnapshot
            let refreshedLifecycleState = try snapshotMutator.refreshCertificateLifecycleState(
                in: &reconciledSnapshot
            )
            // After the lifecycle refresh, so certifications are re-checked
            // against settled key records, and before the projections are
            // recomputed, so the badges the UI reads are built from this
            // unlock's verdicts rather than the ones cached last time.
            let revalidatedCertifications = await snapshotMutator.revalidateCertificationArtifacts(
                in: &reconciledSnapshot,
                ownSignerCertificates: Dictionary(
                    ownSignerKeys.map { ($0.fingerprint, $0.publicKeyData) },
                    uniquingKeysWith: { first, _ in first }
                )
            )
            let recomputedProjections = try snapshotMutator.recomputeCertificationProjections(
                in: &reconciledSnapshot
            )
            if refreshedLifecycleState || revalidatedCertifications || recomputedProjections {
                try contactsDomainStore.replaceSnapshot(reconciledSnapshot)
            }
            adoptOpenContactsDomain(reconciledSnapshot)
            return contactsAvailability
        } catch {
            clearContactsRuntimeState(availability: .recoveryNeeded)
            return contactsAvailability
        }
    }

    /// Drop every in-memory trace of the contacts domain after a local data reset.
    /// The decrypted payload is the store's, so clearing this service's derived
    /// state alone would leave the plaintext resident behind a locked façade.
    func resetInMemoryStateAfterLocalDataReset() async {
        clearContactsRuntimeState(availability: .locked)
        try? await contactsDomainStore?.relockProtectedData()
    }

    // MARK: - Import Contact

    /// Import a public key and add it as a contact.
    /// Handles both binary and ASCII-armored input.
    ///
    /// - Parameter publicKeyData: The public key data (binary or armored).
    /// - Returns: The result of the add operation.
    @discardableResult
    func importContact(
        publicKeyData: Data,
        verificationState: ContactVerificationState = .verified
    ) throws -> ContactImportResult {
        try requireContactsAvailable()
        guard contactsAvailability == .availableProtectedDomain else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
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
        guard contactsAvailability == .availableProtectedDomain else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
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
        guard contactsAvailability == .availableProtectedDomain else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
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

    // MARK: - Remove Contact

    func removeContactIdentity(contactId: String) throws {
        try requireContactsAvailable()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.removeContactIdentity(
            contactId: contactId,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
    }

    func setVerificationState(
        _ verificationState: ContactVerificationState,
        for fingerprint: String
    ) throws {
        try requireContactsAvailable()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.setVerificationState(
            verificationState,
            for: fingerprint,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
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

    /// Decrypted contact records still resident in memory, reported regardless of
    /// availability: the local-data-reset post-conditions use this to detect
    /// residue, so it reads the owner directly rather than the gated accessor.
    var runtimeContactCountForDiagnostics: Int {
        contactsDomainStore?.snapshot?.keyRecords.count ?? 0
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

    var contactsDomainRuntimeStateIsClearedForTests: Bool {
        contactsDomainStore?.snapshot == nil &&
        contactsSearchIndex == nil &&
        contactsAvailability == .locked
    }

    // MARK: - Lookup

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
        guard contactsAvailability == .availableProtectedDomain else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }

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
        try requireContactsAvailable()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.setPreferredKey(
            fingerprint: fingerprint,
            for: contactId,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
    }

    func setKeyUsageState(
        _ usageState: ContactKeyUsageState,
        fingerprint: String
    ) throws {
        try requireContactsAvailable()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.setKeyUsageState(
            usageState,
            fingerprint: fingerprint,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
    }

    @discardableResult
    func createTag(named name: String) throws -> ContactTagSummary {
        try requireProtectedContactsAvailableForOrganization()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.createTag(named: name, in: &snapshot)
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
        return try tagSummaryOrThrow(mutation.output.tagId, in: snapshot)
    }

    @discardableResult
    func renameTag(
        tagId: String,
        to name: String
    ) throws -> ContactTagSummary {
        try requireProtectedContactsAvailableForOrganization()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.renameTag(
            tagId: tagId,
            to: name,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
        return try tagSummaryOrThrow(mutation.output.tagId, in: snapshot)
    }

    func deleteTag(tagId: String) throws {
        try requireProtectedContactsAvailableForOrganization()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.deleteTag(tagId: tagId, in: &snapshot)
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
    }

    @discardableResult
    func addTag(
        named name: String,
        toContactId contactId: String
    ) throws -> ContactTagSummary {
        try requireProtectedContactsAvailableForOrganization()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.addTag(
            named: name,
            toContactId: contactId,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
        return try tagSummaryOrThrow(mutation.output.tagId, in: snapshot)
    }

    @discardableResult
    func assignTag(
        tagId: String,
        toContactId contactId: String
    ) throws -> ContactTagSummary {
        try requireProtectedContactsAvailableForOrganization()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.assignTag(
            tagId: tagId,
            toContactId: contactId,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
        return try tagSummaryOrThrow(mutation.output.tagId, in: snapshot)
    }

    func removeTag(
        tagId: String,
        fromContactId contactId: String
    ) throws {
        try requireProtectedContactsAvailableForOrganization()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.removeTag(
            tagId: tagId,
            fromContactId: contactId,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
        }
    }

    func replaceTagMembership(
        tagId: String,
        contactIds: Set<String>
    ) throws {
        try requireProtectedContactsAvailableForOrganization()
        var snapshot = try currentContactsDomainSnapshot()
        let mutation = try snapshotMutator.replaceTagMembership(
            tagId: tagId,
            contactIds: contactIds,
            in: &snapshot
        )
        if mutation.didMutate {
            try persistContactsSnapshot(snapshot)
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

    // MARK: - Private

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

    /// The open domain's decrypted snapshot, read from its owner. `nil` whenever
    /// contacts are not available, so no reader can serve a payload that outlived
    /// the unlocked session.
    private var openContactsSnapshot: ContactsDomainSnapshot? {
        guard contactsAvailability.isAvailable else {
            return nil
        }
        return contactsDomainStore?.snapshot
    }

    /// Commit a mutated snapshot, then move this service's derived state onto it.
    /// The order is the invariant that makes rollback unnecessary: nothing the app
    /// can observe advances until the database write has succeeded.
    private func persistContactsSnapshot(
        _ snapshot: ContactsDomainSnapshot
    ) throws {
        guard let contactsDomainStore else {
            throw ProtectedDataError.authorizingUnavailable
        }
        try snapshot.validateContract()
        try contactsDomainStore.replaceSnapshot(snapshot)
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

    private func requireProtectedContactsAvailableForOrganization() throws {
        try requireContactsAvailable()
        guard contactsAvailability == .availableProtectedDomain else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
    }

    /// Rebuild the derived state for the snapshot the store now holds, and open
    /// contacts to readers.
    private func adoptOpenContactsDomain(_ snapshot: ContactsDomainSnapshot) {
        contactsSearchIndex = ContactsSearchIndex(snapshot: snapshot)
        contactsAvailability = .availableProtectedDomain
    }

    private func clearContactsRuntimeState(availability: ContactsAvailability = .locked) {
        contactsAvailability = availability
        contactsSearchIndex = nil
    }
}

extension ContactService: ProtectedDataRelockParticipant {
    func relockProtectedData() async throws {
        clearContactsRuntimeState()
        try await contactsDomainStore?.relockProtectedData()
    }
}
