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
final class ContactService {

    private struct ContactMetadataManifest: Codable {
        var verificationStates: [String: ContactVerificationState]
    }

    /// All imported contacts.
    private(set) var contacts: [Contact] = []

    private let engine: PgpEngine
    private let contactsDirectory: URL
    private var verificationStates: [String: ContactVerificationState] = [:]

    init(engine: PgpEngine, contactsDirectory: URL? = nil) {
        self.engine = engine
        if let dir = contactsDirectory {
            self.contactsDirectory = dir
        } else {
            let documentsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            self.contactsDirectory = documentsDir.appendingPathComponent("contacts", isDirectory: true)
        }
    }

    private var metadataURL: URL {
        contactsDirectory.appendingPathComponent("contact-metadata.json")
    }

    // MARK: - Load Contacts

    /// Load all contacts from the contacts directory.
    func loadContacts() throws {
        let fm = FileManager.default

        // Create directory if needed
        if !fm.fileExists(atPath: contactsDirectory.path) {
            try fm.createDirectory(at: contactsDirectory, withIntermediateDirectories: true)
        }

        verificationStates = loadVerificationStates()

        let files = try fm.contentsOfDirectory(
            at: contactsDirectory,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "gpg" }

        var loadedContacts: [Contact] = []
        for file in files {
            let data = try Data(contentsOf: file)
            if let validation = try? ContactImportPublicCertificateValidator.validate(data, using: engine) {
                let contact = makeContact(from: validation)
                loadedContacts.append(contact)
            }
        }

        contacts = loadedContacts

        let loadedFingerprints = Set(loadedContacts.map(\.fingerprint))
        let filteredStates = verificationStates.filter { loadedFingerprints.contains($0.key) }
        if filteredStates != verificationStates {
            verificationStates = filteredStates
            try saveVerificationStates()
        }
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
                    try saveVerificationStates()
                }
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

                if !FileManager.default.fileExists(atPath: contactsDirectory.path) {
                    try FileManager.default.createDirectory(
                        at: contactsDirectory,
                        withIntermediateDirectories: true
                    )
                }

                let filename = "\(existingContact.fingerprint).gpg"
                let fileURL = contactsDirectory.appendingPathComponent(filename)
                try mergedResult.mergedCertData.write(to: fileURL, options: .atomic)

                verificationStates[updatedContact.fingerprint] = updatedContact.verificationState
                try saveVerificationStates()
                contacts[existingIndex] = updatedContact
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

        // Save to filesystem
        if !FileManager.default.fileExists(atPath: contactsDirectory.path) {
            try FileManager.default.createDirectory(at: contactsDirectory, withIntermediateDirectories: true)
        }
        let filename = "\(contact.fingerprint).gpg"
        let fileURL = contactsDirectory.appendingPathComponent(filename)
        try binaryData.write(to: fileURL, options: .atomic)

        verificationStates[contact.fingerprint] = contact.verificationState
        try saveVerificationStates()
        contacts.append(contact)
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
        let validation = try ContactImportPublicCertificateValidator.validate(keyData, using: engine)
        let verifiedContact = makeContact(from: validation, verificationState: .verified)

        if !FileManager.default.fileExists(atPath: contactsDirectory.path) {
            try FileManager.default.createDirectory(at: contactsDirectory, withIntermediateDirectories: true)
        }

        // Write new key first — if this fails, the old contact remains intact
        let filename = "\(verifiedContact.fingerprint).gpg"
        let fileURL = contactsDirectory.appendingPathComponent(filename)
        try validation.publicCertData.write(to: fileURL, options: .atomic)

        if existingFingerprint != verifiedContact.fingerprint {
            let existingFileURL = contactsDirectory.appendingPathComponent("\(existingFingerprint).gpg")
            if FileManager.default.fileExists(atPath: existingFileURL.path) {
                try FileManager.default.removeItem(at: existingFileURL)
            }
            contacts.removeAll { $0.fingerprint == existingFingerprint }
            verificationStates.removeValue(forKey: existingFingerprint)
        }

        verificationStates[verifiedContact.fingerprint] = .verified

        if let existingIndex = contacts.firstIndex(where: { $0.fingerprint == verifiedContact.fingerprint }) {
            contacts[existingIndex] = verifiedContact
        } else {
            contacts.append(verifiedContact)
        }

        try saveVerificationStates()
        return verifiedContact
    }

    // MARK: - Remove Contact

    /// Remove a contact and delete their public key file.
    func removeContact(fingerprint: String) throws {
        let filename = "\(fingerprint).gpg"
        let fileURL = contactsDirectory.appendingPathComponent(filename)

        let fm = FileManager.default
        if fm.fileExists(atPath: fileURL.path) {
            try fm.removeItem(at: fileURL)
        }

        contacts.removeAll { $0.fingerprint == fingerprint }
        verificationStates.removeValue(forKey: fingerprint)
        try saveVerificationStates()
    }

    func setVerificationState(
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
        try saveVerificationStates()
    }

    // MARK: - Lookup

    /// Find a contact by fingerprint.
    func contact(forFingerprint fingerprint: String) -> Contact? {
        contacts.first { $0.fingerprint == fingerprint }
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
    func contacts(matchingKeyIds keyIds: [String]) -> [Contact] {
        contacts.filter { contact in
            keyIds.contains { keyId in
                contact.fingerprint.hasSuffix(keyId.lowercased()) ||
                contact.fingerprint == keyId.lowercased()
            }
        }
    }

    /// Get public key data for a list of contacts.
    func publicKeys(for selectedContacts: [Contact]) -> [Data] {
        selectedContacts.map { $0.publicKeyData }
    }

    // MARK: - Private

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

    private func loadVerificationStates() -> [String: ContactVerificationState] {
        guard let data = try? Data(contentsOf: metadataURL),
              let manifest = try? JSONDecoder().decode(ContactMetadataManifest.self, from: data) else {
            return [:]
        }
        return manifest.verificationStates
    }

    private func saveVerificationStates() throws {
        let manifest = ContactMetadataManifest(verificationStates: verificationStates)
        let data = try JSONEncoder().encode(manifest)
        try data.write(to: metadataURL, options: .atomic)
    }
}
