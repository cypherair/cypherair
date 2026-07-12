import Foundation

/// Manages contacts (imported public keys).
/// Production persistence lives in the protected contacts app-data domain after post-auth unlock.
@Observable
final class ContactService: @unchecked Sendable {
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let contactsDomainStore: ContactsDomainStore?
    private let recipientResolver = ContactRecipientResolver()
    private let summaryProjector = ContactSummaryProjector()
    private let snapshotMutator: ContactSnapshotMutator
    private(set) var contactsAvailability: ContactsAvailability = .locked
    private var runtimeSnapshot: ContactsDomainSnapshot?
    private var contactsSearchIndex: ContactsSearchIndex?

    init(
        contactImportAdapter: PGPContactImportAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        contactsDomainStore: ContactsDomainStore? = nil
    ) {
        self.certificateAdapter = certificateAdapter
        snapshotMutator = ContactSnapshotMutator(contactImportAdapter: contactImportAdapter)
        self.contactsDomainStore = contactsDomainStore
    }

    // MARK: - Post-Auth Contacts Gate

    @discardableResult
    func openContactsAfterPostUnlock(
        gateDecision: ContactsPostAuthGateDecision,
        wrappingRootKey: () throws -> Data
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
            if try snapshotMutator.recomputeCertificationProjections(in: &reconciledSnapshot) {
                try contactsDomainStore.replaceSnapshot(reconciledSnapshot)
            }
            try applyProtectedRuntimeSnapshot(reconciledSnapshot)
            return contactsAvailability
        } catch {
            clearContactsRuntimeState(availability: .recoveryNeeded)
            return contactsAvailability
        }
    }

    func resetInMemoryStateAfterLocalDataReset() {
        clearContactsRuntimeState(availability: .locked)
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
        return try withProtectedRuntimeRollback {
            try performProtectedImportContact(
                publicKeyData: publicKeyData,
                verificationState: verificationState
            )
        }
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
            in: mutableRuntimeSnapshot()
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
        return try withProtectedRuntimeRollback {
            try performProtectedImportContactAfterConfirmation(
                publicKeyData: publicKeyData,
                verificationState: verificationState,
                displayedCandidateMatch: displayedCandidateMatch
            )
        }
    }

    @discardableResult
    private func performProtectedImportContact(
        publicKeyData: Data,
        verificationState: ContactVerificationState = .verified
    ) throws -> ContactImportResult {
        var snapshot = try mutableRuntimeSnapshot()
        return try applyImportContactMutation(
            publicKeyData: publicKeyData,
            verificationState: verificationState,
            in: &snapshot
        )
    }

    @discardableResult
    private func performProtectedImportContactAfterConfirmation(
        publicKeyData: Data,
        verificationState: ContactVerificationState,
        displayedCandidateMatch: ContactCandidateMatch?
    ) throws -> ContactImportResult {
        var snapshot = try mutableRuntimeSnapshot()
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
            try persistProtectedRuntimeSnapshot(snapshot)
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
    }

    func setVerificationState(
        _ verificationState: ContactVerificationState,
        for fingerprint: String
    ) throws {
        try requireContactsAvailable()
        try withProtectedRuntimeRollback {
            try performProtectedSetVerificationState(verificationState, for: fingerprint)
        }
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
            scope: .identity,
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
            scope: .recipient,
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

    func tagSuggestions(matching query: String) -> [ContactTagSummary] {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return []
        }
        return searchIndex(for: runtimeSnapshot).tagSuggestions(matching: query)
    }

    var runtimeContactCountForDiagnostics: Int {
        runtimeSnapshot?.keyRecords.count ?? 0
    }

    func requireContactsAvailable() throws {
        guard contactsAvailability.isAvailable else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
    }

    func currentContactsDomainSnapshot() throws -> ContactsDomainSnapshot {
        try requireContactsAvailable()
        if let runtimeSnapshot {
            try runtimeSnapshot.validateContract()
            return runtimeSnapshot
        }
        throw CypherAirError.contactsUnavailable(contactsAvailability)
    }

    var contactsDomainRuntimeStateIsClearedForTests: Bool {
        runtimeSnapshot == nil &&
        contactsSearchIndex == nil &&
        contactsAvailability == .locked
    }

    // MARK: - Lookup

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
        if let keyRecord = runtimeSnapshot?.keyRecords.first(where: { $0.fingerprint == fingerprint }) {
            return keyRecord.contactId
        }
        return nil
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

    func availableContactKeyRecord(fingerprint: String) -> ContactKeyRecord? {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return nil
        }
        return runtimeSnapshot.keyRecords.first { $0.fingerprint == fingerprint }
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
        guard let runtimeSnapshot else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
        return try recipientResolver.publicKeysForRecipientContactIDs(
            recipientContactIds,
            in: runtimeSnapshot
        )
    }

    func contactsVerificationContext() -> ContactsVerificationContext {
        let availability = contactsAvailability
        guard availability.allowsContactsVerification,
              let runtimeSnapshot else {
            return ContactsVerificationContext(contactKeys: [], availability: availability)
        }
        return ContactsVerificationContext(
            contactKeys: runtimeSnapshot.keyRecords,
            availability: availability
        )
    }

    func setPreferredKey(fingerprint: String, for contactId: String) throws {
        try requireContactsAvailable()
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
    }

    func setKeyUsageState(
        _ usageState: ContactKeyUsageState,
        fingerprint: String
    ) throws {
        try requireContactsAvailable()
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
    }

    @discardableResult
    func createTag(named name: String) throws -> ContactTagSummary {
        try requireProtectedContactsAvailableForOrganization()
        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.createTag(named: name, in: &snapshot)
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return try tagSummaryOrThrow(mutation.output.tagId, in: snapshot)
        }
    }

    @discardableResult
    func renameTag(
        tagId: String,
        to name: String
    ) throws -> ContactTagSummary {
        try requireProtectedContactsAvailableForOrganization()
        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.renameTag(
                tagId: tagId,
                to: name,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
            return try tagSummaryOrThrow(mutation.output.tagId, in: snapshot)
        }
    }

    func deleteTag(tagId: String) throws {
        try requireProtectedContactsAvailableForOrganization()
        try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.deleteTag(tagId: tagId, in: &snapshot)
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
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

    @discardableResult
    func assignTag(
        tagId: String,
        toContactId contactId: String
    ) throws -> ContactTagSummary {
        try requireProtectedContactsAvailableForOrganization()
        return try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.assignTag(
                tagId: tagId,
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

    func replaceTagMembership(
        tagId: String,
        contactIds: Set<String>
    ) throws {
        try requireProtectedContactsAvailableForOrganization()
        try withProtectedRuntimeRollback {
            var snapshot = try mutableRuntimeSnapshot()
            let mutation = try snapshotMutator.replaceTagMembership(
                tagId: tagId,
                contactIds: contactIds,
                in: &snapshot
            )
            if mutation.didMutate {
                try persistProtectedRuntimeSnapshot(snapshot)
            }
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
                preferredKeyNeedsSelection: surviving.preferredKey == nil
                    && surviving.keys.contains(where: { $0.usageState == .additionalActive })
            )
        }
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

    private func mutableRuntimeSnapshot() throws -> ContactsDomainSnapshot {
        if let runtimeSnapshot {
            try runtimeSnapshot.validateContract()
            return runtimeSnapshot
        }
        throw CypherAirError.contactsUnavailable(contactsAvailability)
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

    private func searchIndex(for snapshot: ContactsDomainSnapshot) -> ContactsSearchIndex {
        if let contactsSearchIndex {
            return contactsSearchIndex
        }
        let index = ContactsSearchIndex(snapshot: snapshot)
        contactsSearchIndex = index
        return index
    }

    private func applyProtectedRuntimeSnapshot(_ snapshot: ContactsDomainSnapshot) throws {
        runtimeSnapshot = snapshot
        contactsSearchIndex = ContactsSearchIndex(snapshot: snapshot)
        contactsAvailability = .availableProtectedDomain
    }

    private func withProtectedRuntimeRollback<T>(_ operation: () throws -> T) throws -> T {
        let previousAvailability = contactsAvailability
        let previousRuntimeSnapshot = runtimeSnapshot
        let previousSearchIndex = contactsSearchIndex

        do {
            return try operation()
        } catch {
            contactsAvailability = previousAvailability
            runtimeSnapshot = previousRuntimeSnapshot
            contactsSearchIndex = previousSearchIndex
            if let snapshot = contactsDomainStore?.snapshot {
                try? applyProtectedRuntimeSnapshot(snapshot)
            }
            throw error
        }
    }

    private func clearContactsRuntimeState(availability: ContactsAvailability = .locked) {
        contactsAvailability = availability
        runtimeSnapshot = nil
        contactsSearchIndex = nil
    }
}

extension ContactService: ProtectedDataRelockParticipant {
    func relockProtectedData() async throws {
        clearContactsRuntimeState()
        try await contactsDomainStore?.relockProtectedData()
    }
}
