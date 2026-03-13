import Foundation

/// Represents a user's own PGP key identity stored on this device.
/// The actual secret key bytes are SE-wrapped in Keychain — this model
/// holds only metadata and the public key data.
///
/// Conforms to `Codable` for serialization into a Keychain metadata item,
/// enabling key enumeration on cold launch without SE authentication.
struct PGPKeyIdentity: Identifiable, Hashable, Codable {
    /// Unique identifier — the full fingerprint in lowercase hex.
    var id: String { fingerprint }

    /// Full key fingerprint (lowercase hex, no spaces).
    let fingerprint: String

    /// Key version (4 for Profile A, 6 for Profile B).
    let keyVersion: UInt8

    /// Encryption profile.
    let profile: KeyProfile

    /// Primary User ID (e.g., "Alice <alice@example.com>").
    let userId: String?

    /// Whether this key has an encryption subkey.
    let hasEncryptionSubkey: Bool

    /// Whether the key has been revoked.
    var isRevoked: Bool

    /// Whether the key has expired.
    var isExpired: Bool

    /// Whether this is the user's default signing/encryption identity.
    var isDefault: Bool

    /// Whether the user has exported a backup of this key.
    var isBackedUp: Bool

    /// Public key data in binary OpenPGP format (for sharing).
    let publicKeyData: Data

    /// Revocation certificate data (auto-generated at key creation).
    let revocationCert: Data

    /// Primary algorithm description (e.g., "Ed25519", "Ed448").
    let primaryAlgo: String

    /// Subkey algorithm description (e.g., "X25519", "X448").
    let subkeyAlgo: String?

    /// Short Key ID (last 16 hex chars of fingerprint). De-emphasized in UI.
    var shortKeyId: String {
        String(fingerprint.suffix(16))
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
