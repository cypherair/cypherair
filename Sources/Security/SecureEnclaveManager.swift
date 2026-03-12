import Foundation
import CryptoKit
import Security

/// Errors from Secure Enclave operations.
enum SecureEnclaveError: Error {
    /// The SE key handle is not a valid HardwareSEKey.
    case invalidKeyHandle
    /// Failed to create SecAccessControl with the given flags.
    case accessControlCreationFailed
    /// AES-GCM sealed box is missing the combined representation.
    case sealedBoxCombineFailed
    /// Secure Enclave is not available on this device.
    case notAvailable
    /// Failed to generate secure random bytes.
    case randomGenerationFailed
}

/// Handle to a real Secure Enclave P-256 key.
/// Wraps `SecureEnclave.P256.KeyAgreement.PrivateKey` from CryptoKit.
final class HardwareSEKey: SEKeyHandle {
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey

    var dataRepresentation: Data {
        key.dataRepresentation
    }

    init(key: SecureEnclave.P256.KeyAgreement.PrivateKey) {
        self.key = key
    }
}

/// Production Secure Enclave manager using CryptoKit.
///
/// Wrapping scheme (identical for Ed25519, X25519, Ed448, X448 keys):
/// 1. Generate SE P-256 KeyAgreement key with access control flags.
/// 2. Self-ECDH: SE privkey x SE pubkey (computed inside SE hardware).
/// 3. HKDF(SHA-256, randomSalt, info="CypherAir-SE-Wrap-v1:"+fingerprint) -> AES-256 key.
/// 4. AES.GCM.seal(privateKeyBytes) -> sealed box.
///
/// SECURITY-CRITICAL: Changes to this file require human review.
/// See SECURITY.md Section 3 and Section 7.
struct HardwareSecureEnclave: SecureEnclaveManageable {

    static var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    func generateWrappingKey(accessControl: SecAccessControl?) throws -> any SEKeyHandle {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }

        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        if let accessControl {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl)
        } else {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        }

        return HardwareSEKey(key: key)
    }

    func wrap(privateKey: Data, using handle: any SEKeyHandle, fingerprint: String) throws -> WrappedKeyBundle {
        guard let hwKey = handle as? HardwareSEKey else {
            throw SecureEnclaveError.invalidKeyHandle
        }

        // Self-ECDH: compute shared secret between SE key and its own public key.
        // On real hardware, this computation happens inside the Secure Enclave.
        let sharedSecret = try hwKey.key.sharedSecretFromKeyAgreement(
            with: hwKey.key.publicKey
        )

        // Generate random salt (32 bytes) using SecRandomCopyBytes.
        var salt = Data(count: 32)
        let saltStatus = salt.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        guard saltStatus == errSecSuccess else {
            throw SecureEnclaveError.randomGenerationFailed
        }

        // HKDF derive AES-256 key with domain-separated info string.
        let infoData = SEConstants.hkdfInfo(fingerprint: fingerprint)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: infoData,
            outputByteCount: 32
        )

        // AES-GCM seal the private key bytes.
        let sealedBox = try AES.GCM.seal(privateKey, using: symmetricKey)
        guard let combined = sealedBox.combined else {
            throw SecureEnclaveError.sealedBoxCombineFailed
        }

        return WrappedKeyBundle(
            seKeyData: handle.dataRepresentation,
            salt: salt,
            sealedBox: combined
        )
    }

    func unwrap(bundle: WrappedKeyBundle, using handle: any SEKeyHandle, fingerprint: String) throws -> Data {
        guard let hwKey = handle as? HardwareSEKey else {
            throw SecureEnclaveError.invalidKeyHandle
        }

        // Self-ECDH (same as wrapping, computed inside SE hardware).
        let sharedSecret = try hwKey.key.sharedSecretFromKeyAgreement(
            with: hwKey.key.publicKey
        )

        // Re-derive symmetric key with stored salt and same info string.
        let infoData = SEConstants.hkdfInfo(fingerprint: fingerprint)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: bundle.salt,
            sharedInfo: infoData,
            outputByteCount: 32
        )

        // AES-GCM open the sealed box.
        let sealedBox = try AES.GCM.SealedBox(combined: bundle.sealedBox)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)
        return plaintext
    }

    func deleteKey(_ handle: any SEKeyHandle) throws {
        // SE keys are deleted by removing them from Keychain.
        // The actual SE key is tied to its dataRepresentation stored in Keychain.
        // Once the Keychain item is removed, the SE key becomes inaccessible.
        // The caller (AuthenticationManager) is responsible for Keychain deletion.
    }

    func reconstructKey(from data: Data) throws -> any SEKeyHandle {
        // Reconstructing from dataRepresentation triggers device authentication
        // (Face ID / Touch ID) when the key has biometric access control flags.
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: data
        )
        return HardwareSEKey(key: key)
    }
}
