import Foundation

/// Result of attempting to add a contact.
enum AddContactResult {
    /// Contact was added successfully.
    case added(Contact)
    /// Contact already exists (same fingerprint). No changes made.
    case duplicate(Contact)
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

    /// All imported contacts.
    private(set) var contacts: [Contact] = []

    private let engine: PgpEngine
    private let contactsDirectory: URL

    init(engine: PgpEngine, contactsDirectory: URL? = nil) {
        self.engine = engine
        if let dir = contactsDirectory {
            self.contactsDirectory = dir
        } else {
            let documentsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            self.contactsDirectory = documentsDir.appendingPathComponent("contacts", isDirectory: true)
        }
    }

    // MARK: - Load Contacts

    /// Load all contacts from the contacts directory.
    func loadContacts() throws {
        let fm = FileManager.default

        // Create directory if needed
        if !fm.fileExists(atPath: contactsDirectory.path) {
            try fm.createDirectory(at: contactsDirectory, withIntermediateDirectories: true)
        }

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
    func addContact(publicKeyData: Data) throws -> AddContactResult {
        // Try to dearmor if it looks like ASCII armor
        let binaryData: Data
        let contact: Contact
        do {
            if let firstChar = publicKeyData.first, firstChar == 0x2D { // '-' = ASCII armor header
                binaryData = try engine.dearmor(armored: publicKeyData)
            } else {
                binaryData = publicKeyData
            }
            contact = try parseContact(from: binaryData)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }

        // Check for duplicate
        if let existingIndex = contacts.firstIndex(where: { $0.fingerprint == contact.fingerprint }) {
            // Same fingerprint = same key, no update needed
            return .duplicate(contacts[existingIndex])
        }

        // Check for same userId but different fingerprint (key update)
        if let userId = contact.userId,
           let existingIndex = contacts.firstIndex(where: { $0.userId == userId && $0.fingerprint != contact.fingerprint }) {
            // Different fingerprint = key regenerated — caller must confirm before replacing.
            return .keyUpdateDetected(
                newContact: contact,
                existingContact: contacts[existingIndex],
                keyData: binaryData
            )
        }

        // Save to filesystem
        let filename = "\(contact.fingerprint).gpg"
        let fileURL = contactsDirectory.appendingPathComponent(filename)
        try binaryData.write(to: fileURL, options: .atomic)

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
        contacts.append(newContact)
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

    private func parseContact(from binaryData: Data) throws -> Contact {
        let keyInfo = try engine.parseKeyInfo(keyData: binaryData)
        let profile = try engine.detectProfile(certData: binaryData)

        return Contact(
            fingerprint: keyInfo.fingerprint,
            keyVersion: keyInfo.keyVersion,
            profile: profile,
            userId: keyInfo.userId,
            isRevoked: keyInfo.isRevoked,
            isExpired: keyInfo.isExpired,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            publicKeyData: binaryData,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo
        )
    }
}
