import Foundation

/// Represents a user's own PGP key identity stored on this device.
/// The actual secret key bytes are SE-wrapped in Keychain — this model
/// holds only metadata and the public key data.
///
/// Conforms to `Codable` for serialization into the protected key-metadata
/// domain, with legacy Keychain decoding retained for migration.
struct PGPKeyIdentity: Identifiable, Hashable, Codable {
    /// Unique identifier — the full fingerprint in lowercase hex.
    var id: String { fingerprint }

    /// Full key fingerprint (lowercase hex, no spaces).
    let fingerprint: String

    /// Key version (4 for Profile A, 6 for Profile B).
    let keyVersion: UInt8

    /// Encryption profile.
    let profile: PGPKeyProfile

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
    /// Mutable because expiry modification creates new binding signatures.
    var publicKeyData: Data

    /// Binary revocation signature data used for export.
    /// Generated at key creation for local keys and backfilled on demand for
    /// imported keys that predate revocation-construction support.
    var revocationCert: Data

    /// Primary algorithm description (e.g., "Ed25519", "Ed448").
    let primaryAlgo: String

    /// Subkey algorithm description (e.g., "X25519", "X448").
    let subkeyAlgo: String?

    /// Expiration date, if set. Nil means the key does not expire.
    /// Populated from parsed key metadata expiry timestamp (seconds since Unix epoch).
    var expiryDate: Date?

    /// Short Key ID (last 16 hex chars of fingerprint). De-emphasized in UI.
    var shortKeyId: String {
        IdentityPresentation.shortKeyId(from: fingerprint)
    }

    /// Formatted fingerprint for display (groups of 4 characters).
    var formattedFingerprint: String {
        IdentityPresentation.formattedFingerprint(fingerprint)
    }

    /// Format a hex fingerprint string into groups of 4 characters separated by spaces.
    static func formatFingerprint(_ hex: String) -> String {
        IdentityPresentation.formattedFingerprint(hex)
    }
}
