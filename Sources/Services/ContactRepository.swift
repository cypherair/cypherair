import Foundation

struct StoredContactRecord {
    let fileURL: URL
    let data: Data
}

struct ContactRepository {
    private struct ContactMetadataManifest: Codable {
        var verificationStates: [String: ContactVerificationState]
    }

    let contactsDirectory: URL

    private let fileManager: FileManager

    init(
        contactsDirectory: URL,
        fileManager: FileManager = .default
    ) {
        self.contactsDirectory = contactsDirectory
        self.fileManager = fileManager
    }

    func ensureDirectoryExists() throws {
        guard !fileManager.fileExists(atPath: contactsDirectory.path) else {
            return
        }

        try fileManager.createDirectory(
            at: contactsDirectory,
            withIntermediateDirectories: true
        )
    }

    func activeLegacySourceExists() -> Bool {
        fileManager.fileExists(atPath: contactsDirectory.path)
    }

    func quarantineExists() -> Bool {
        fileManager.fileExists(atPath: quarantineDirectory.path)
    }

    func loadStoredContacts() throws -> [StoredContactRecord] {
        try fileManager.contentsOfDirectory(
            at: contactsDirectory,
            includingPropertiesForKeys: nil
        )
        .filter { $0.pathExtension == "gpg" }
        .map { url in
            StoredContactRecord(
                fileURL: url,
                data: try Data(contentsOf: url)
            )
        }
    }

    func loadStoredContactsIfDirectoryExists() throws -> [StoredContactRecord] {
        guard activeLegacySourceExists() else {
            return []
        }
        return try loadStoredContacts()
    }

    func loadVerificationStates() throws -> [String: ContactVerificationState] {
        guard fileManager.fileExists(atPath: metadataURL.path) else {
            return [:]
        }

        do {
            let data = try Data(contentsOf: metadataURL)
            return try JSONDecoder().decode(ContactMetadataManifest.self, from: data).verificationStates
        } catch {
            throw CypherAirError.corruptData(
                reason: String(
                    localized: "contacts.metadata.corrupt",
                    defaultValue: "Contacts metadata could not be read safely."
                )
            )
        }
    }

    func loadVerificationStatesIfDirectoryExists() throws -> [String: ContactVerificationState] {
        guard activeLegacySourceExists() else {
            return [:]
        }
        return try loadVerificationStates()
    }

    func saveVerificationStates(_ verificationStates: [String: ContactVerificationState]) throws {
        try ensureDirectoryExists()
        let manifest = ContactMetadataManifest(verificationStates: verificationStates)
        let data = try JSONEncoder().encode(manifest)
        try data.write(to: metadataURL, options: .atomic)
    }

    func savePublicKey(_ data: Data, fingerprint: String) throws {
        try ensureDirectoryExists()
        try data.write(
            to: publicKeyURL(for: fingerprint),
            options: .atomic
        )
    }

    func removePublicKey(fingerprint: String) throws {
        let fileURL = publicKeyURL(for: fingerprint)
        guard fileManager.fileExists(atPath: fileURL.path) else {
            return
        }

        try fileManager.removeItem(at: fileURL)
    }

    func moveActiveLegacySourceToQuarantine() throws {
        guard activeLegacySourceExists() else {
            return
        }
        guard !quarantineExists() else {
            throw CypherAirError.internalError(
                reason: String(
                    localized: "contacts.quarantine.exists",
                    defaultValue: "Contacts quarantine already exists."
                )
            )
        }
        try fileManager.moveItem(at: contactsDirectory, to: quarantineDirectory)
    }

    func deleteQuarantineIfPresent() throws {
        guard quarantineExists() else {
            return
        }
        try fileManager.removeItem(at: quarantineDirectory)
    }

    private var metadataURL: URL {
        contactsDirectory.appendingPathComponent("contact-metadata.json")
    }

    var quarantineDirectory: URL {
        contactsDirectory
            .deletingLastPathComponent()
            .appendingPathComponent("\(contactsDirectory.lastPathComponent).quarantine", isDirectory: true)
    }

    private func publicKeyURL(for fingerprint: String) -> URL {
        contactsDirectory.appendingPathComponent("\(fingerprint).gpg")
    }
}
