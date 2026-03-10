import Foundation

/// Result of wrapping a private key with the Secure Enclave.
/// Contains the three Keychain items that must be stored together.
struct WrappedKeyBundle {
    /// SE key dataRepresentation (for Keychain storage).
    let seKeyData: Data
    /// Random HKDF salt.
    let salt: Data
    /// AES-GCM sealed box containing the encrypted private key.
    let sealedBox: Data
}

/// Handle to a Secure Enclave wrapping key.
/// In production, this wraps a CryptoKit SecureEnclave.P256.KeyAgreement.PrivateKey.
/// In tests, this wraps a software P-256 key.
protocol SEKeyHandle {
    /// The key's data representation for Keychain storage.
    var dataRepresentation: Data { get }
}

/// Protocol for Secure Enclave operations.
/// Production: CryptoKit SecureEnclave APIs.
/// Test: Software P-256 + AES-GCM (same algorithm, no hardware binding).
///
/// SECURITY-CRITICAL: Changes to this protocol require human review.
/// See SECURITY.md Section 7.
protocol SecureEnclaveManageable {
    /// Generate a new P-256 wrapping key in the Secure Enclave.
    /// The access control flags determine auth requirements (Standard vs High Security).
    ///
    /// - Parameter accessControl: SecAccessControl with appropriate flags for the auth mode.
    /// - Returns: A handle to the SE key.
    func generateWrappingKey(accessControl: Any) throws -> any SEKeyHandle

    /// Wrap a private key using the SE wrapping scheme:
    /// self-ECDH → HKDF(SHA-256, salt, info="CypherAir-SE-Wrap-v1:"+fingerprint) → AES-GCM seal.
    ///
    /// - Parameters:
    ///   - privateKey: The raw private key bytes to wrap.
    ///   - handle: The SE wrapping key handle.
    ///   - fingerprint: The key's hex fingerprint (lowercase, no spaces) for HKDF info string.
    /// - Returns: A WrappedKeyBundle containing the three Keychain items.
    func wrap(privateKey: Data, using handle: any SEKeyHandle, fingerprint: String) throws -> WrappedKeyBundle

    /// Unwrap a private key. Triggers device authentication (Face ID / Touch ID).
    ///
    /// - Parameters:
    ///   - bundle: The WrappedKeyBundle retrieved from Keychain.
    ///   - handle: The SE wrapping key handle (reconstructed from dataRepresentation).
    ///   - fingerprint: The key's hex fingerprint for HKDF info string.
    /// - Returns: The raw private key bytes. MUST be zeroized after use.
    func unwrap(bundle: WrappedKeyBundle, using handle: any SEKeyHandle, fingerprint: String) throws -> Data

    /// Delete an SE wrapping key from the Secure Enclave.
    func deleteKey(_ handle: any SEKeyHandle) throws

    /// Reconstruct an SE key handle from its data representation.
    /// This triggers device authentication on real hardware.
    func reconstructKey(from data: Data) throws -> any SEKeyHandle

    /// Check if Secure Enclave is available on this device.
    static var isAvailable: Bool { get }
}

/// HKDF info string constant.
/// CRITICAL: This exact string must be used in both wrapping and unwrapping.
/// Any mismatch will produce a different derived key and make wrapped keys
/// permanently inaccessible.
///
/// Format: "CypherAir-SE-Wrap-v1:" + lowercase hex fingerprint (no spaces).
/// The "v1" segment enables future migration if the wrapping scheme changes.
enum SEConstants {
    static let hkdfInfoPrefix = "CypherAir-SE-Wrap-v1:"

    /// Construct the full HKDF info string for a given key fingerprint.
    static func hkdfInfo(fingerprint: String) -> Data {
        let infoString = hkdfInfoPrefix + fingerprint.lowercased()
        return Data(infoString.utf8)
    }
}
