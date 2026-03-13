import Foundation

/// A contact whose public key has been imported.
struct Contact: Identifiable, Hashable {
    /// Unique identifier — the full fingerprint in lowercase hex.
    var id: String { fingerprint }

    /// Full key fingerprint (lowercase hex, no spaces).
    let fingerprint: String

    /// Key version (4 for Profile A, 6 for Profile B).
    let keyVersion: UInt8

    /// Encryption profile.
    let profile: KeyProfile

    /// Primary User ID (e.g., "Bob <bob@example.com>").
    let userId: String?

    /// Display name extracted from User ID.
    var displayName: String {
        guard let userId else { return String(localized: "contact.unknown", defaultValue: "Unknown") }
        // Extract name before '<' if present
        if let angleBracketIndex = userId.firstIndex(of: "<") {
            let name = userId[userId.startIndex..<angleBracketIndex].trimmingCharacters(in: .whitespaces)
            return name.isEmpty ? userId : name
        }
        return userId
    }

    /// Email extracted from User ID.
    var email: String? {
        guard let userId else { return nil }
        guard let start = userId.firstIndex(of: "<"),
              let end = userId.firstIndex(of: ">") else { return nil }
        let emailStart = userId.index(after: start)
        guard emailStart < end else { return nil }
        return String(userId[emailStart..<end])
    }

    /// Whether the key has been revoked.
    var isRevoked: Bool

    /// Whether the key has expired.
    var isExpired: Bool

    /// Whether the key has an encryption subkey.
    let hasEncryptionSubkey: Bool

    /// Public key data in binary OpenPGP format.
    let publicKeyData: Data

    /// Primary algorithm description.
    let primaryAlgo: String

    /// Subkey algorithm description.
    let subkeyAlgo: String?

    /// Short Key ID (last 16 hex chars).
    var shortKeyId: String {
        String(fingerprint.suffix(16))
    }

    /// Whether this contact's key can receive encrypted messages.
    var canEncryptTo: Bool {
        hasEncryptionSubkey && !isRevoked && !isExpired
    }

    /// Formatted fingerprint for display (groups of 4 characters).
    var formattedFingerprint: String {
        stride(from: 0, to: fingerprint.count, by: 4).map { offset in
            let start = fingerprint.index(fingerprint.startIndex, offsetBy: offset)
            let end = fingerprint.index(start, offsetBy: min(4, fingerprint.count - offset))
            return String(fingerprint[start..<end])
        }.joined(separator: " ")
    }
}
