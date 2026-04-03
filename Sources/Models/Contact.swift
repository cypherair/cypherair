import Foundation

enum ContactVerificationState: String, Codable, Hashable {
    case verified
    case unverified

    var isVerified: Bool {
        self == .verified
    }
}

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
        IdentityPresentation.displayName(from: userId)
    }

    /// Email extracted from User ID.
    var email: String? {
        IdentityPresentation.email(from: userId)
    }

    /// Whether the key has been revoked.
    var isRevoked: Bool

    /// Whether the key has expired.
    var isExpired: Bool

    /// Whether the key has an encryption subkey.
    let hasEncryptionSubkey: Bool

    /// Whether the user has verified the contact's fingerprint out-of-band.
    var verificationState: ContactVerificationState

    /// Public key data in binary OpenPGP format.
    let publicKeyData: Data

    /// Primary algorithm description.
    let primaryAlgo: String

    /// Subkey algorithm description.
    let subkeyAlgo: String?

    /// Short Key ID (last 16 hex chars).
    var shortKeyId: String {
        IdentityPresentation.shortKeyId(from: fingerprint)
    }

    /// Whether this contact's key can receive encrypted messages.
    var canEncryptTo: Bool {
        hasEncryptionSubkey && !isRevoked && !isExpired
    }

    var isVerified: Bool {
        verificationState.isVerified
    }

    /// Formatted fingerprint for display (groups of 4 characters).
    var formattedFingerprint: String {
        IdentityPresentation.formattedFingerprint(fingerprint)
    }
}
