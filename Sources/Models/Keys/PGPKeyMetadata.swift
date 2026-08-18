import Foundation

/// App-owned metadata parsed from an OpenPGP certificate.
struct PGPKeyMetadata: Equatable, Hashable, Sendable {
    /// Key fingerprint as lowercase hex string.
    let fingerprint: String

    /// Key version as parsed from the certificate.
    let keyVersion: UInt8

    /// Policy-selected primary User ID string for display and identity matching.
    let userId: String?

    /// Whether the key has a valid encryption subkey.
    let hasEncryptionSubkey: Bool

    /// Whether the key is revoked.
    let isRevoked: Bool

    /// Whether the key has expired.
    let isExpired: Bool

    /// The engine's classified suite, or nil when the certificate is
    /// unplaceable — its algorithm, curve, and version match no suite.
    let suite: PGPKeySuite?

    /// Primary key algorithm name.
    let primaryAlgo: String

    /// Encryption subkey algorithm name, if present.
    let subkeyAlgo: String?

    /// Expiration timestamp as seconds since Unix epoch. Nil means no expiry.
    let expiryTimestamp: UInt64?

    var expiryDate: Date? {
        expiryTimestamp.map {
            Date(timeIntervalSince1970: TimeInterval($0))
        }
    }
}
