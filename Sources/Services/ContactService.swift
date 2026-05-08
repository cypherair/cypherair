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
    /// Same userId but different fingerprint detected. The caller must confirm
    /// before the old key is replaced. Call `confirmKeyUpdate` to proceed.
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
    private(set) var contactsAvailability: ContactsAvailability = .locked
    private var verificationStates: [String: ContactVerificationState] = [:]
    private var runtimeSnapshot: ContactsDomainSnapshot?
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
            try applyProtectedRuntimeSnapshot(openedSnapshot)
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
    /// Returns `.keyUpdateDetected` if the parsed userId conflicts with another
    /// contact's fingerprint, including after a same-fingerprint merge/update.
    /// In that case, the caller must present a warning and call `confirmKeyUpdate`
    /// if the user approves.
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

                if let conflictingContact = conflictingContact(
                    forUserId: updatedContact.userId,
                    excludingFingerprint: updatedContact.fingerprint
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
        if let existingContact = conflictingContact(
            forUserId: contact.userId,
            excludingFingerprint: contact.fingerprint
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
        let validation = try ContactImportPublicCertificateValidator.validate(
            publicKeyData,
            using: engine
        )
        let binaryData = validation.publicCertData
        var snapshot = try mutableRuntimeSnapshot()
        let now = Date()

        if let existingIndex = snapshot.keyRecords.firstIndex(where: {
            $0.fingerprint == validation.keyInfo.fingerprint
        }) {
            let existingRecord = snapshot.keyRecords[existingIndex]
            let mergedResult: CertificateMergeResult
            do {
                mergedResult = try engine.mergePublicCertificateUpdate(
                    existingCert: existingRecord.publicKeyData,
                    incomingCertOrUpdate: binaryData
                )
            } catch {
                throw ContactImportPublicCertificateValidator.mapError(error)
            }

            let resolvedVerificationState: ContactVerificationState =
                (existingRecord.manualVerificationState.isVerified || verificationState == .verified)
                ? .verified
                : existingRecord.manualVerificationState

            switch mergedResult.outcome {
            case .noOp:
                if snapshot.keyRecords[existingIndex].manualVerificationState != resolvedVerificationState {
                    snapshot.keyRecords[existingIndex].manualVerificationState = resolvedVerificationState
                    snapshot.keyRecords[existingIndex].updatedAt = now
                    snapshot.updatedAt = now
                    try normalizeKeyUsage(in: &snapshot, updatedAt: now)
                    try persistProtectedRuntimeSnapshot(snapshot)
                }
                let contact = try compatibilityContact(
                    forFingerprint: existingRecord.fingerprint,
                    in: snapshot
                )
                return .duplicate(contact)

            case .updated:
                let updatedValidation = try ContactImportPublicCertificateValidator.validate(
                    mergedResult.mergedCertData,
                    using: engine
                )
                snapshot.keyRecords[existingIndex] = updatedKeyRecord(
                    preserving: existingRecord,
                    from: updatedValidation,
                    publicKeyData: mergedResult.mergedCertData,
                    verificationState: resolvedVerificationState,
                    now: now
                )
                updateIdentityDisplayIfNeeded(
                    contactId: existingRecord.contactId,
                    from: snapshot.keyRecords[existingIndex],
                    in: &snapshot,
                    now: now
                )
                snapshot.updatedAt = now
                try normalizeKeyUsage(in: &snapshot, updatedAt: now)
                try persistProtectedRuntimeSnapshot(snapshot)
                let contact = try compatibilityContact(
                    forFingerprint: updatedValidation.keyInfo.fingerprint,
                    in: snapshot
                )
                return .updated(contact)
            }
        }

        let candidateMatch = candidateMatch(for: validation, in: snapshot)
        let identity = makeIdentity(from: validation, now: now)
        let keyRecord = makeKeyRecord(
            from: validation,
            contactId: identity.contactId,
            verificationState: verificationState,
            usageState: validation.keyInfo.hasEncryptionSubkey
                && !validation.keyInfo.isRevoked
                && !validation.keyInfo.isExpired
                ? .preferred
                : .historical,
            now: now
        )
        snapshot.identities.append(identity)
        snapshot.keyRecords.append(keyRecord)
        snapshot.updatedAt = now
        try normalizeKeyUsage(in: &snapshot, updatedAt: now)
        try persistProtectedRuntimeSnapshot(snapshot)

        let contact = try compatibilityContact(
            forFingerprint: validation.keyInfo.fingerprint,
            in: snapshot
        )
        if let candidateMatch {
            return .addedWithCandidate(contact, candidateMatch)
        }
        return .added(contact)
    }

    /// Apply a user-confirmed key replacement after `addContact` returns
    /// `.keyUpdateDetected`. Supports both classic different-fingerprint replacement
    /// and same-fingerprint merged updates that now conflict with another contact.
    ///
    /// - Parameters:
    ///   - existingFingerprint: Fingerprint of the contact being removed/replaced.
    ///   - keyData: Binary public key data for the new contact.
    /// - Returns: The authoritative verified contact rebuilt from validated public bytes.
    @discardableResult
    func confirmKeyUpdate(existingFingerprint: String, keyData: Data) throws -> Contact {
        try requireContactsAvailable()
        if contactsAvailability == .availableProtectedDomain {
            return try withProtectedRuntimeRollback {
                try performConfirmKeyUpdate(
                    existingFingerprint: existingFingerprint,
                    keyData: keyData
                )
            }
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
                let removedFingerprints = Set(
                    snapshot.keyRecords
                        .filter { $0.contactId == contactId }
                        .map(\.fingerprint)
                )
                snapshot.identities.removeAll { $0.contactId == contactId }
                snapshot.keyRecords.removeAll { $0.contactId == contactId }
                for listIndex in snapshot.recipientLists.indices {
                    snapshot.recipientLists[listIndex].memberContactIds.removeAll { $0 == contactId }
                    snapshot.recipientLists[listIndex].updatedAt = Date()
                }
                snapshot.updatedAt = Date()
                for fingerprint in removedFingerprints {
                    verificationStates.removeValue(forKey: fingerprint)
                }
                try persistProtectedRuntimeSnapshot(snapshot)
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
        guard let index = snapshot.keyRecords.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        snapshot.keyRecords[index].manualVerificationState = verificationState
        snapshot.keyRecords[index].updatedAt = Date()
        snapshot.updatedAt = Date()
        try persistProtectedRuntimeSnapshot(snapshot)
    }

    private func performProtectedRemoveKey(fingerprint: String) throws {
        var snapshot = try mutableRuntimeSnapshot()
        guard let keyRecord = snapshot.keyRecords.first(where: { $0.fingerprint == fingerprint }) else {
            return
        }
        snapshot.keyRecords.removeAll { $0.fingerprint == fingerprint }
        if !snapshot.keyRecords.contains(where: { $0.contactId == keyRecord.contactId }) {
            snapshot.identities.removeAll { $0.contactId == keyRecord.contactId }
            for listIndex in snapshot.recipientLists.indices {
                snapshot.recipientLists[listIndex].memberContactIds.removeAll { $0 == keyRecord.contactId }
                snapshot.recipientLists[listIndex].updatedAt = Date()
            }
        }
        verificationStates.removeValue(forKey: fingerprint)
        snapshot.updatedAt = Date()
        try normalizeKeyUsage(in: &snapshot, updatedAt: Date())
        try persistProtectedRuntimeSnapshot(snapshot)
    }

    var availableContacts: [Contact] {
        guard contactsAvailability.isAvailable else {
            return []
        }
        return contacts
    }

    var availableContactIdentities: [ContactIdentitySummary] {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot else {
            return []
        }
        return contactIdentitySummaries(from: runtimeSnapshot)
    }

    var availableRecipientContacts: [ContactIdentitySummary] {
        availableContactIdentities.filter(\.canEncryptTo)
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
        return contactIdentitySummaries(from: runtimeSnapshot)
            .first { $0.contactId == contactId }
    }

    func contactId(forFingerprint fingerprint: String) -> String? {
        guard contactsAvailability.isAvailable else {
            return nil
        }
        if let runtimeSnapshot,
           let keyRecord = runtimeSnapshot.keyRecords.first(where: { $0.fingerprint == fingerprint }) {
            return keyRecord.contactId
        }
        return contacts.first(where: { $0.fingerprint == fingerprint })?.contactId
            ?? "legacy-contact-\(fingerprint)"
    }

    func availableKey(fingerprint: String) -> ContactKeySummary? {
        guard contactsAvailability.isAvailable,
              let runtimeSnapshot,
              let keyRecord = runtimeSnapshot.keyRecords.first(where: { $0.fingerprint == fingerprint }) else {
            return nil
        }
        return makeKeySummary(from: keyRecord)
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

    func publicKeysForRecipientFingerprints(_ recipientFingerprints: [String]) throws -> [Data] {
        try requireContactsAvailable()
        let contactsByFingerprint = Dictionary(uniqueKeysWithValues: contacts.map { ($0.fingerprint, $0) })
        let recipientKeys = recipientFingerprints.compactMap { fingerprint in
            contactsByFingerprint[fingerprint]?.publicKeyData
        }

        guard recipientKeys.count == recipientFingerprints.count else {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "error.recipientNotFound",
                    defaultValue: "One or more recipients could not be found in contacts."
                )
            )
        }

        return recipientKeys
    }

    func publicKeysForRecipientContactIDs(_ recipientContactIds: [String]) throws -> [Data] {
        try requireContactsAvailable()
        guard let runtimeSnapshot else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }

        var recipientKeys: [Data] = []
        for contactId in recipientContactIds {
            guard let preferredKey = runtimeSnapshot.keyRecords.first(where: {
                $0.contactId == contactId
                    && $0.usageState == .preferred
                    && $0.canEncryptTo
            }) else {
                throw CypherAirError.invalidKeyData(
                    reason: String(
                        localized: "error.recipientPreferredKeyMissing",
                        defaultValue: "One or more selected contacts do not have a preferred encryption key."
                    )
                )
            }
            recipientKeys.append(preferredKey.publicKeyData)
        }

        return recipientKeys
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
                guard let preferredIndex = snapshot.keyRecords.firstIndex(where: {
                    $0.contactId == contactId && $0.fingerprint == fingerprint
                }) else {
                    throw CypherAirError.internalError(
                        reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
                    )
                }
                guard snapshot.keyRecords[preferredIndex].canEncryptTo else {
                    throw CypherAirError.invalidKeyData(
                        reason: String(
                            localized: "contacts.preferredKey.notEncryptable",
                            defaultValue: "The selected key cannot receive encrypted messages."
                        )
                    )
                }

                let now = Date()
                for index in snapshot.keyRecords.indices where snapshot.keyRecords[index].contactId == contactId {
                    if index == preferredIndex {
                        snapshot.keyRecords[index].usageState = .preferred
                    } else if snapshot.keyRecords[index].usageState == .preferred {
                        snapshot.keyRecords[index].usageState = snapshot.keyRecords[index].canEncryptTo
                            ? .additionalActive
                            : .historical
                    }
                    snapshot.keyRecords[index].updatedAt = now
                }
                snapshot.updatedAt = now
                try normalizeKeyUsage(in: &snapshot, updatedAt: now)
                try persistProtectedRuntimeSnapshot(snapshot)
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
                guard let index = snapshot.keyRecords.firstIndex(where: { $0.fingerprint == fingerprint }) else {
                    throw CypherAirError.internalError(
                        reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
                    )
                }
                if usageState != .historical && !snapshot.keyRecords[index].canEncryptTo {
                    throw CypherAirError.invalidKeyData(
                        reason: String(
                            localized: "contacts.activeKey.notEncryptable",
                            defaultValue: "The selected key cannot be active because it cannot receive encrypted messages."
                        )
                    )
                }
                snapshot.keyRecords[index].usageState = usageState
                snapshot.keyRecords[index].updatedAt = Date()
                snapshot.updatedAt = Date()
                try normalizeKeyUsage(in: &snapshot, updatedAt: Date())
                try persistProtectedRuntimeSnapshot(snapshot)
            }
        } else {
            try requireContactsAvailable()
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

        if contactsAvailability == .availableProtectedDomain {
            return try withProtectedRuntimeRollback {
                var snapshot = try mutableRuntimeSnapshot()
                guard snapshot.identities.contains(where: { $0.contactId == sourceContactId }),
                      snapshot.identities.contains(where: { $0.contactId == targetContactId }) else {
                    throw CypherAirError.internalError(
                        reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
                    )
                }

                let now = Date()
                let sourceIdentity = snapshot.identities.first { $0.contactId == sourceContactId }
                if let targetIndex = snapshot.identities.firstIndex(where: { $0.contactId == targetContactId }),
                   let sourceIdentity {
                    snapshot.identities[targetIndex].tagIds = Array(
                        Set(snapshot.identities[targetIndex].tagIds)
                            .union(sourceIdentity.tagIds)
                    ).sorted()
                    snapshot.identities[targetIndex].updatedAt = now
                }

                for index in snapshot.keyRecords.indices where snapshot.keyRecords[index].contactId == sourceContactId {
                    snapshot.keyRecords[index].contactId = targetContactId
                    if snapshot.keyRecords[index].usageState == .preferred {
                        snapshot.keyRecords[index].usageState = snapshot.keyRecords[index].canEncryptTo
                            ? .additionalActive
                            : .historical
                    }
                    snapshot.keyRecords[index].updatedAt = now
                }
                for listIndex in snapshot.recipientLists.indices {
                    if snapshot.recipientLists[listIndex].memberContactIds.contains(sourceContactId),
                       !snapshot.recipientLists[listIndex].memberContactIds.contains(targetContactId) {
                        snapshot.recipientLists[listIndex].memberContactIds.append(targetContactId)
                    }
                    snapshot.recipientLists[listIndex].memberContactIds.removeAll { $0 == sourceContactId }
                    snapshot.recipientLists[listIndex].updatedAt = now
                }
                snapshot.identities.removeAll { $0.contactId == sourceContactId }
                snapshot.updatedAt = now
                try normalizeKeyUsage(in: &snapshot, updatedAt: now)
                try persistProtectedRuntimeSnapshot(snapshot)

                let surviving = try contactSummaryOrThrow(targetContactId, in: snapshot)
                return ContactMergeResult(
                    survivingContact: surviving,
                    removedContactId: sourceContactId,
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

    private func makeIdentity(
        from validation: PublicCertificateValidationResult,
        now: Date
    ) -> ContactIdentity {
        ContactIdentity(
            contactId: "contact-\(UUID().uuidString)",
            displayName: IdentityPresentation.displayName(from: validation.keyInfo.userId),
            primaryEmail: IdentityPresentation.email(from: validation.keyInfo.userId),
            tagIds: [],
            notes: nil,
            createdAt: now,
            updatedAt: now
        )
    }

    private func makeKeyRecord(
        from validation: PublicCertificateValidationResult,
        contactId: String,
        verificationState: ContactVerificationState,
        usageState: ContactKeyUsageState,
        now: Date
    ) -> ContactKeyRecord {
        ContactKeyRecord(
            keyId: "key-\(UUID().uuidString)",
            contactId: contactId,
            fingerprint: validation.keyInfo.fingerprint,
            primaryUserId: validation.keyInfo.userId,
            displayName: IdentityPresentation.displayName(from: validation.keyInfo.userId),
            email: IdentityPresentation.email(from: validation.keyInfo.userId),
            keyVersion: validation.keyInfo.keyVersion,
            profile: validation.profile,
            primaryAlgo: validation.keyInfo.primaryAlgo,
            subkeyAlgo: validation.keyInfo.subkeyAlgo,
            hasEncryptionSubkey: validation.keyInfo.hasEncryptionSubkey,
            isRevoked: validation.keyInfo.isRevoked,
            isExpired: validation.keyInfo.isExpired,
            manualVerificationState: verificationState,
            usageState: usageState,
            certificationProjection: .empty,
            certificationArtifactIds: [],
            publicKeyData: validation.publicCertData,
            createdAt: now,
            updatedAt: now
        )
    }

    private func updatedKeyRecord(
        preserving existingRecord: ContactKeyRecord,
        from validation: PublicCertificateValidationResult,
        publicKeyData: Data,
        verificationState: ContactVerificationState,
        now: Date
    ) -> ContactKeyRecord {
        var updatedRecord = existingRecord
        updatedRecord.primaryUserId = validation.keyInfo.userId
        updatedRecord.displayName = IdentityPresentation.displayName(from: validation.keyInfo.userId)
        updatedRecord.email = IdentityPresentation.email(from: validation.keyInfo.userId)
        updatedRecord.keyVersion = validation.keyInfo.keyVersion
        updatedRecord.profile = validation.profile
        updatedRecord.primaryAlgo = validation.keyInfo.primaryAlgo
        updatedRecord.subkeyAlgo = validation.keyInfo.subkeyAlgo
        updatedRecord.hasEncryptionSubkey = validation.keyInfo.hasEncryptionSubkey
        updatedRecord.isRevoked = validation.keyInfo.isRevoked
        updatedRecord.isExpired = validation.keyInfo.isExpired
        updatedRecord.manualVerificationState = verificationState
        updatedRecord.publicKeyData = publicKeyData
        updatedRecord.updatedAt = now
        if !updatedRecord.canEncryptTo {
            updatedRecord.usageState = .historical
        }
        return updatedRecord
    }

    private func updateIdentityDisplayIfNeeded(
        contactId: String,
        from keyRecord: ContactKeyRecord,
        in snapshot: inout ContactsDomainSnapshot,
        now: Date
    ) {
        guard let identityIndex = snapshot.identities.firstIndex(where: {
            $0.contactId == contactId
        }) else {
            return
        }
        if snapshot.identities[identityIndex].displayName.isEmpty ||
            snapshot.identities[identityIndex].displayName == IdentityPresentation.displayName(from: nil) {
            snapshot.identities[identityIndex].displayName = keyRecord.displayName
        }
        if snapshot.identities[identityIndex].primaryEmail == nil {
            snapshot.identities[identityIndex].primaryEmail = keyRecord.email
        }
        snapshot.identities[identityIndex].updatedAt = now
    }

    private func normalizeKeyUsage(
        in snapshot: inout ContactsDomainSnapshot,
        updatedAt: Date
    ) throws {
        let contactIds = snapshot.identities.map(\.contactId)
        for contactId in contactIds {
            let keyIndices = snapshot.keyRecords.indices.filter {
                snapshot.keyRecords[$0].contactId == contactId
            }
            for index in keyIndices where snapshot.keyRecords[index].usageState != .historical
                && !snapshot.keyRecords[index].canEncryptTo {
                snapshot.keyRecords[index].usageState = .historical
                snapshot.keyRecords[index].updatedAt = updatedAt
            }

            let preferredIndices = keyIndices.filter {
                snapshot.keyRecords[$0].usageState == .preferred
            }
            if preferredIndices.count > 1 {
                for index in preferredIndices.dropFirst() {
                    snapshot.keyRecords[index].usageState = snapshot.keyRecords[index].canEncryptTo
                        ? .additionalActive
                        : .historical
                    snapshot.keyRecords[index].updatedAt = updatedAt
                }
            }

            let hasPreferred = keyIndices.contains {
                snapshot.keyRecords[$0].usageState == .preferred
                    && snapshot.keyRecords[$0].canEncryptTo
            }
            if !hasPreferred {
                let activeEncryptable = keyIndices.filter {
                    snapshot.keyRecords[$0].usageState == .additionalActive
                        && snapshot.keyRecords[$0].canEncryptTo
                }
                if activeEncryptable.count == 1, let index = activeEncryptable.first {
                    snapshot.keyRecords[index].usageState = .preferred
                    snapshot.keyRecords[index].updatedAt = updatedAt
                }
            }
        }
        try snapshot.validateContract()
    }

    private func candidateMatch(
        for validation: PublicCertificateValidationResult,
        in snapshot: ContactsDomainSnapshot
    ) -> ContactCandidateMatch? {
        let incomingEmail = normalizedEmail(validation.keyInfo.userId)
        if let incomingEmail {
            let strongMatches = snapshot.identities.filter {
                normalizedEmail($0.primaryEmail) == incomingEmail
            }
            if strongMatches.count == 1, let match = strongMatches.first {
                return ContactCandidateMatch(
                    strength: .strong,
                    contactIds: [match.contactId],
                    displayName: match.displayName,
                    primaryEmail: match.primaryEmail
                )
            }
            if strongMatches.count > 1 {
                return ContactCandidateMatch(
                    strength: .ambiguousStrong,
                    contactIds: strongMatches.map(\.contactId),
                    displayName: String(
                        localized: "contacts.candidate.multiple",
                        defaultValue: "Multiple Contacts"
                    ),
                    primaryEmail: incomingEmail
                )
            }
        }

        guard let incomingUserId = validation.keyInfo.userId else {
            return nil
        }
        if let weakKey = snapshot.keyRecords.first(where: {
            $0.primaryUserId == incomingUserId
                && $0.fingerprint != validation.keyInfo.fingerprint
        }),
           let identity = snapshot.identities.first(where: { $0.contactId == weakKey.contactId }) {
            return ContactCandidateMatch(
                strength: .weak,
                contactIds: [identity.contactId],
                displayName: identity.displayName,
                primaryEmail: identity.primaryEmail
            )
        }

        return nil
    }

    private func normalizedEmail(_ userIdOrEmail: String?) -> String? {
        let email = IdentityPresentation.email(from: userIdOrEmail) ?? userIdOrEmail
        guard let normalized = email?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased(),
              !normalized.isEmpty,
              normalized.contains("@") else {
            return nil
        }
        return normalized
    }

    private func contactIdentitySummaries(
        from snapshot: ContactsDomainSnapshot
    ) -> [ContactIdentitySummary] {
        let keysByContactId = Dictionary(grouping: snapshot.keyRecords, by: \.contactId)
        return snapshot.identities
            .sorted { lhs, rhs in
                let lhsName = lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName)
                if lhsName == .orderedSame {
                    return lhs.contactId < rhs.contactId
                }
                return lhsName == .orderedAscending
            }
            .map { identity in
                let keys = (keysByContactId[identity.contactId] ?? [])
                    .sorted(by: contactKeySort)
                    .map(makeKeySummary(from:))
                return ContactIdentitySummary(
                    contactId: identity.contactId,
                    displayName: identity.displayName,
                    primaryEmail: identity.primaryEmail,
                    tagIds: identity.tagIds,
                    notes: identity.notes,
                    keys: keys
                )
            }
    }

    private func contactKeySort(_ lhs: ContactKeyRecord, _ rhs: ContactKeyRecord) -> Bool {
        let lhsRank = usageSortRank(lhs.usageState)
        let rhsRank = usageSortRank(rhs.usageState)
        if lhsRank != rhsRank {
            return lhsRank < rhsRank
        }
        return lhs.fingerprint < rhs.fingerprint
    }

    private func usageSortRank(_ usageState: ContactKeyUsageState) -> Int {
        switch usageState {
        case .preferred:
            0
        case .additionalActive:
            1
        case .historical:
            2
        }
    }

    private func makeKeySummary(from keyRecord: ContactKeyRecord) -> ContactKeySummary {
        ContactKeySummary(
            keyId: keyRecord.keyId,
            contactId: keyRecord.contactId,
            fingerprint: keyRecord.fingerprint,
            primaryUserId: keyRecord.primaryUserId,
            displayName: keyRecord.displayName,
            email: keyRecord.email,
            keyVersion: keyRecord.keyVersion,
            profile: keyRecord.profile,
            primaryAlgo: keyRecord.primaryAlgo,
            subkeyAlgo: keyRecord.subkeyAlgo,
            hasEncryptionSubkey: keyRecord.hasEncryptionSubkey,
            isRevoked: keyRecord.isRevoked,
            isExpired: keyRecord.isExpired,
            manualVerificationState: keyRecord.manualVerificationState,
            usageState: keyRecord.usageState
        )
    }

    private func contactSummaryOrThrow(
        _ contactId: String,
        in snapshot: ContactsDomainSnapshot
    ) throws -> ContactIdentitySummary {
        guard let summary = contactIdentitySummaries(from: snapshot)
            .first(where: { $0.contactId == contactId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        return summary
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

    private func conflictingContact(
        forUserId userId: String?,
        excludingFingerprint fingerprint: String
    ) -> Contact? {
        guard let userId else {
            return nil
        }

        return contacts.first {
            $0.userId == userId && $0.fingerprint != fingerprint
        }
    }

    private func refreshCompatibilityProjection() throws {
        runtimeSnapshot = try domainRepository.updateCompatibilityRuntime(from: contacts)
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
        let previousMigrationWarning = protectedDomainMigrationWarning

        do {
            return try operation()
        } catch {
            contacts = previousContacts
            verificationStates = previousVerificationStates
            contactsAvailability = previousAvailability
            runtimeSnapshot = previousRuntimeSnapshot
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
