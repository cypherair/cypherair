import Foundation

/// Result of attempting to add a contact.
enum AddContactResult {
    /// Contact was added successfully.
    case added(Contact)
    /// Contact already exists (same fingerprint). No material changes were needed.
    case duplicate(Contact)
    /// Existing same-fingerprint contact absorbed new public update material.
    case updated(Contact)
    /// Same userId but different fingerprint detected. The caller must confirm
    /// before the old key is replaced. Call `confirmKeyUpdate` to proceed.
    case keyUpdateDetected(newContact: Contact, existingContact: Contact, keyData: Data)
}

/// Manages contacts (imported public keys).
/// Public keys are stored as binary .gpg files in the Documents/contacts/ directory.
///
/// No Keychain access needed — contacts are public keys only.
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
        do {
            var wrappingKey = try wrappingRootKey()
            defer {
                wrappingKey.protectedDataZeroize()
            }
            let initialSnapshot = try legacyMigrationSource.makeInitialSnapshot()
            try await contactsDomainStore.ensureCommittedIfNeeded(
                wrappingRootKey: wrappingKey,
                initialSnapshot: initialSnapshot
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
            if activeLegacyExistedAtOpenStart,
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
                try performAddContact(
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
                try performRemoveContact(fingerprint: fingerprint)
            }
            return
        }
        try performRemoveContact(fingerprint: fingerprint)
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
                try performSetVerificationState(verificationState, for: fingerprint)
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

    var contactsAvailabilityForContactsPR1: ContactsAvailability {
        contactsAvailability
    }

    var availableContacts: [Contact] {
        guard contactsAvailability.isAvailable else {
            return []
        }
        return contacts
    }

    var runtimeContactCountForDiagnostics: Int {
        contacts.count
    }

    func requireContactsAvailable() throws {
        guard contactsAvailability.isAvailable else {
            throw CypherAirError.contactsUnavailable(contactsAvailability)
        }
    }

    func currentCompatibilitySnapshotForContactsPR1() throws -> ContactsDomainSnapshot {
        try requireContactsAvailable()
        return try domainRepository.makeCompatibilitySnapshot(from: contacts)
    }

    func compatibilityContactsForContactsPR1(
        from snapshot: ContactsDomainSnapshot
    ) throws -> [Contact] {
        try domainRepository.makeCompatibilityContacts(from: snapshot)
    }

    func seedContactsDomainRuntimeStateForContactsPR1Tests() {
        domainRepository.seedRuntimeStateForContactsPR1Tests()
    }

    var contactsDomainRuntimeStateIsClearedForContactsPR1Tests: Bool {
        contacts.isEmpty &&
        verificationStates.isEmpty &&
        contactsAvailability == .locked &&
        domainRepository.runtimeStateIsClearedForContactsPR1Tests
    }

    // MARK: - Lookup

    /// Find a contact by fingerprint.
    func availableContact(forFingerprint fingerprint: String) -> Contact? {
        guard contactsAvailability.isAvailable else {
            return nil
        }

        return contacts.first { $0.fingerprint == fingerprint }
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

    func contactsForVerificationContext() -> (contacts: [Contact], availability: ContactsAvailability) {
        let availability = contactsAvailability
        guard availability.allowsContactsVerification else {
            return ([], availability)
        }
        return (contacts, availability)
    }

    // MARK: - Private

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
        _ = try domainRepository.updateCompatibilityRuntime(from: contacts)
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
        let snapshot = try domainRepository.makeCompatibilitySnapshot(from: contacts)
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
        let previousMigrationWarning = protectedDomainMigrationWarning

        do {
            return try operation()
        } catch {
            contacts = previousContacts
            verificationStates = previousVerificationStates
            contactsAvailability = previousAvailability
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
