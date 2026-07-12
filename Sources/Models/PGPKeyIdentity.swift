import Foundation

/// Represents a user's own PGP key identity stored on this device.
/// The actual secret key bytes are SE-wrapped in Keychain — this model
/// holds only metadata and the public key data.
///
/// Conforms to `Codable` for serialization into the protected key-metadata
/// domain. All fields are strict: records must persist explicit
/// configuration identity and custody kind.
struct PGPKeyIdentity: Identifiable, Hashable, Codable {
    /// Unique identifier — the full fingerprint in lowercase hex.
    var id: String { fingerprint }

    /// Full key fingerprint (lowercase hex, no spaces).
    let fingerprint: String

    /// Key version (4 for the v4 Legacy family, 6 for the v6 families).
    let keyVersion: UInt8

    /// Encryption profile.
    let profile: PGPKeyProfile

    /// Successor OpenPGP configuration identity, persisted independently from
    /// the historical profile vocabulary.
    let openPGPConfigurationIdentity: PGPKeyConfiguration.Identity

    /// Private-key custody model for this local identity.
    let privateKeyCustodyKind: PGPPrivateKeyCustodyKind

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

    var openPGPConfiguration: PGPKeyConfiguration {
        openPGPConfigurationIdentity.configuration
    }

    /// Fingerprints of software-custody identities — the keys with SE-wrapped
    /// private-key bundles subject to auth-mode re-wrap and re-wrap recovery.
    /// Device-bound Secure Enclave custody keys have no bundle and must never
    /// enter those enumerations: a bundleless fingerprint classifies as
    /// unrecoverable and poisons the whole mode-switch recovery.
    static func softwareCustodyFingerprints(in identities: [PGPKeyIdentity]) -> [String] {
        identities
            .filter { $0.privateKeyCustodyKind == .softwareSecretCertificate }
            // Normalize defensively: the downstream re-wrap keying is
            // case-sensitive and relies on the lowercase-hex fingerprint
            // invariant; lowercasing here hardens it against any future drift.
            .map { $0.fingerprint.lowercased() }
    }

    init(
        fingerprint: String,
        keyVersion: UInt8,
        profile: PGPKeyProfile,
        userId: String?,
        hasEncryptionSubkey: Bool,
        isRevoked: Bool,
        isExpired: Bool,
        isDefault: Bool,
        isBackedUp: Bool,
        publicKeyData: Data,
        revocationCert: Data,
        primaryAlgo: String,
        subkeyAlgo: String?,
        expiryDate: Date?,
        openPGPConfigurationIdentity: PGPKeyConfiguration.Identity,
        privateKeyCustodyKind: PGPPrivateKeyCustodyKind
    ) {
        self.fingerprint = fingerprint
        self.keyVersion = keyVersion
        self.profile = profile
        self.openPGPConfigurationIdentity = openPGPConfigurationIdentity
        self.privateKeyCustodyKind = privateKeyCustodyKind
        self.userId = userId
        self.hasEncryptionSubkey = hasEncryptionSubkey
        self.isRevoked = isRevoked
        self.isExpired = isExpired
        self.isDefault = isDefault
        self.isBackedUp = isBackedUp
        self.publicKeyData = publicKeyData
        self.revocationCert = revocationCert
        self.primaryAlgo = primaryAlgo
        self.subkeyAlgo = subkeyAlgo
        self.expiryDate = expiryDate
    }
}
