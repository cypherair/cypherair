import Foundation

/// Represents a user's own PGP key identity stored on this device.
/// The actual secret key bytes are SE-wrapped in Keychain — this model
/// holds only metadata and the public key data.
///
/// Conforms to `Codable` for serialization into the protected key-metadata
/// domain, with legacy Keychain decoding retained for migration.
struct PGPKeyIdentity: Identifiable, Hashable, Codable {
    private enum CodingKeys: String, CodingKey {
        case fingerprint
        case keyVersion
        case profile
        case openPGPConfigurationIdentity
        case privateKeyCustodyKind
        case userId
        case hasEncryptionSubkey
        case isRevoked
        case isExpired
        case isDefault
        case isBackedUp
        case publicKeyData
        case revocationCert
        case primaryAlgo
        case subkeyAlgo
        case expiryDate
    }

    /// Unique identifier — the full fingerprint in lowercase hex.
    var id: String { fingerprint }

    /// Full key fingerprint (lowercase hex, no spaces).
    let fingerprint: String

    /// Key version (4 for Profile A, 6 for Profile B).
    let keyVersion: UInt8

    /// Encryption profile.
    let profile: PGPKeyProfile

    /// Successor OpenPGP configuration identity, persisted independently from
    /// historical Profile A/B vocabulary.
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

    var openPGPConfiguration: PGPKeyConfiguration {
        openPGPConfigurationIdentity.configuration
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
        openPGPConfigurationIdentity: PGPKeyConfiguration.Identity? = nil,
        privateKeyCustodyKind: PGPPrivateKeyCustodyKind? = nil
    ) {
        self.fingerprint = fingerprint
        self.keyVersion = keyVersion
        self.profile = profile
        self.openPGPConfigurationIdentity = openPGPConfigurationIdentity ?? profile.openPGPConfiguration.identity
        self.privateKeyCustodyKind = privateKeyCustodyKind ?? profile.defaultCustodyKind
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

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let profile = try container.decode(PGPKeyProfile.self, forKey: .profile)

        fingerprint = try container.decode(String.self, forKey: .fingerprint)
        keyVersion = try container.decode(UInt8.self, forKey: .keyVersion)
        self.profile = profile
        openPGPConfigurationIdentity = try container.decodeIfPresent(
            PGPKeyConfiguration.Identity.self,
            forKey: .openPGPConfigurationIdentity
        ) ?? profile.openPGPConfiguration.identity
        privateKeyCustodyKind = try container.decodeIfPresent(
            PGPPrivateKeyCustodyKind.self,
            forKey: .privateKeyCustodyKind
        ) ?? profile.defaultCustodyKind
        userId = try container.decodeIfPresent(String.self, forKey: .userId)
        hasEncryptionSubkey = try container.decode(Bool.self, forKey: .hasEncryptionSubkey)
        isRevoked = try container.decode(Bool.self, forKey: .isRevoked)
        isExpired = try container.decode(Bool.self, forKey: .isExpired)
        isDefault = try container.decode(Bool.self, forKey: .isDefault)
        isBackedUp = try container.decode(Bool.self, forKey: .isBackedUp)
        publicKeyData = try container.decode(Data.self, forKey: .publicKeyData)
        revocationCert = try container.decode(Data.self, forKey: .revocationCert)
        primaryAlgo = try container.decode(String.self, forKey: .primaryAlgo)
        subkeyAlgo = try container.decodeIfPresent(String.self, forKey: .subkeyAlgo)
        expiryDate = try container.decodeIfPresent(Date.self, forKey: .expiryDate)
    }
}
