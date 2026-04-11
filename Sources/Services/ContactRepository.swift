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

    func loadVerificationStates() -> [String: ContactVerificationState] {
        guard let data = try? Data(contentsOf: metadataURL),
              let manifest = try? JSONDecoder().decode(ContactMetadataManifest.self, from: data) else {
            return [:]
        }

        return manifest.verificationStates
    }

    func saveVerificationStates(_ verificationStates: [String: ContactVerificationState]) throws {
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

    private var metadataURL: URL {
        contactsDirectory.appendingPathComponent("contact-metadata.json")
    }

    private func publicKeyURL(for fingerprint: String) -> URL {
        contactsDirectory.appendingPathComponent("\(fingerprint).gpg")
    }
}
