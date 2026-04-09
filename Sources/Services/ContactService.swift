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
            if let contact = try? parseContact(from: data) {
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
    /// Returns `.keyUpdateDetected` if the same userId has a different fingerprint.
    /// In that case, the caller must present a warning and call `confirmKeyUpdate` if the user approves.
    ///
    /// - Parameter publicKeyData: The public key data (binary or armored).
    /// - Returns: The result of the add operation.
    @discardableResult
    func addContact(
        publicKeyData: Data,
        verificationState: ContactVerificationState = .verified
    ) throws -> AddContactResult {
        // Try to dearmor if it looks like ASCII armor
        let binaryData: Data
        var contact: Contact
        do {
            if let firstChar = publicKeyData.first, firstChar == 0x2D { // '-' = ASCII armor header
                binaryData = try engine.dearmor(armored: publicKeyData)
            } else {
                binaryData = publicKeyData
            }
            contact = try parseContact(from: binaryData, verificationState: verificationState)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }

        // Check for same-fingerprint duplicate/update
        if let existingIndex = contacts.firstIndex(where: { $0.fingerprint == contact.fingerprint }) {
            let existingContact = contacts[existingIndex]
            let mergedResult = try engine.mergePublicCertificateUpdate(
                existingCert: existingContact.publicKeyData,
                incomingCertOrUpdate: binaryData
            )
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
                if !FileManager.default.fileExists(atPath: contactsDirectory.path) {
                    try FileManager.default.createDirectory(
                        at: contactsDirectory,
                        withIntermediateDirectories: true
                    )
                }

                let filename = "\(existingContact.fingerprint).gpg"
                let fileURL = contactsDirectory.appendingPathComponent(filename)
                try mergedResult.mergedCertData.write(to: fileURL, options: .atomic)

                let updatedContact = try parseContact(
                    from: mergedResult.mergedCertData,
                    verificationState: resolvedVerificationState
                )
                verificationStates[updatedContact.fingerprint] = updatedContact.verificationState
                try saveVerificationStates()
                contacts[existingIndex] = updatedContact
                return .updated(updatedContact)
            }
        }

        // Check for same userId but different fingerprint (key update)
        if let userId = contact.userId,
           let existingIndex = contacts.firstIndex(where: { $0.userId == userId && $0.fingerprint != contact.fingerprint }) {
            contact.verificationState = .verified
            // Different fingerprint = key regenerated — caller must confirm before replacing.
            return .keyUpdateDetected(
                newContact: contact,
                existingContact: contacts[existingIndex],
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

    /// Replace an existing contact's key after the user has confirmed the key update.
    /// Called when `addContact` returns `.keyUpdateDetected`.
    ///
    /// - Parameters:
    ///   - existingFingerprint: Fingerprint of the old contact to replace.
    ///   - newContact: The new contact parsed from the incoming key.
    ///   - keyData: Binary public key data for the new contact.
    func confirmKeyUpdate(existingFingerprint: String, newContact: Contact, keyData: Data) throws {
        // Write new key first — if this fails, the old contact remains intact
        let filename = "\(newContact.fingerprint).gpg"
        let fileURL = contactsDirectory.appendingPathComponent(filename)
        try keyData.write(to: fileURL, options: .atomic)

        // Now safe to remove old contact
        try removeContact(fingerprint: existingFingerprint)
        var verifiedContact = newContact
        verifiedContact.verificationState = .verified
        verificationStates[verifiedContact.fingerprint] = .verified
        try saveVerificationStates()
        contacts.append(verifiedContact)
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
