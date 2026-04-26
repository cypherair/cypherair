import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// Errors from Secure Enclave operations.
enum SecureEnclaveError: Error, Equatable {
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
    /// The fingerprint is empty or contains non-hex characters.
    case invalidFingerprint
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
    private let traceStore: AuthLifecycleTraceStore?

    init(traceStore: AuthLifecycleTraceStore? = nil) {
        self.traceStore = traceStore
    }

    static var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    func generateWrappingKey(accessControl: SecAccessControl?, authenticationContext: LAContext?) throws -> any SEKeyHandle {
        traceStore?.record(
            category: .operation,
            name: "secureEnclave.generateWrappingKey.start",
            metadata: [
                "accessControl": accessControl == nil ? "false" : "true",
                "hasAuthenticationContext": authenticationContext == nil ? "false" : "true"
            ]
        )
        guard SecureEnclave.isAvailable else {
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.generateWrappingKey.finish",
                metadata: ["result": "notAvailable"]
            )
            throw SecureEnclaveError.notAvailable
        }

        do {
            let key: SecureEnclave.P256.KeyAgreement.PrivateKey
            if let accessControl {
                // Passing a pre-authenticated LAContext associates it with the new SE key,
                // so that subsequent operations (e.g., sharedSecretFromKeyAgreement in wrap())
                // reuse the existing authentication session instead of triggering Face ID again.
                key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
            } else {
                key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
            }
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.generateWrappingKey.finish",
                metadata: ["result": "success"]
            )
            return HardwareSEKey(key: key)
        } catch {
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.generateWrappingKey.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
    }

    func wrap(privateKey: Data, using handle: any SEKeyHandle, fingerprint: String) throws -> WrappedKeyBundle {
        traceStore?.record(
            category: .operation,
            name: "secureEnclave.wrap.start"
        )
        guard let hwKey = handle as? HardwareSEKey else {
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.wrap.finish",
                metadata: ["result": "invalidKeyHandle"]
            )
            throw SecureEnclaveError.invalidKeyHandle
        }

        do {
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
            // Note: SymmetricKey is an opaque CryptoKit type that manages its own secure
            // memory lifecycle internally. There is no public zeroize() API — the key
            // material is cleared by the framework when the value goes out of scope.
            // This satisfies SECURITY.md §3.2 step 6 ("zeroize symmetric key") via
            // framework guarantees rather than explicit application-level zeroing.
            let infoData = try SEConstants.hkdfInfo(fingerprint: fingerprint)
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

            traceStore?.record(
                category: .operation,
                name: "secureEnclave.wrap.finish",
                metadata: ["result": "success"]
            )
            return WrappedKeyBundle(
                seKeyData: handle.dataRepresentation,
                salt: salt,
                sealedBox: combined
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.wrap.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
    }

    func unwrap(bundle: WrappedKeyBundle, using handle: any SEKeyHandle, fingerprint: String) throws -> Data {
        traceStore?.record(
            category: .operation,
            name: "secureEnclave.unwrap.start"
        )
        guard let hwKey = handle as? HardwareSEKey else {
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.unwrap.finish",
                metadata: ["result": "invalidKeyHandle"]
            )
            throw SecureEnclaveError.invalidKeyHandle
        }

        do {
            // Self-ECDH (same as wrapping, computed inside SE hardware).
            let sharedSecret = try hwKey.key.sharedSecretFromKeyAgreement(
                with: hwKey.key.publicKey
            )

            // Re-derive symmetric key with stored salt and same info string.
            // See wrap() for note on SymmetricKey's opaque secure memory lifecycle.
            let infoData = try SEConstants.hkdfInfo(fingerprint: fingerprint)
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: bundle.salt,
                sharedInfo: infoData,
                outputByteCount: 32
            )

            // AES-GCM open the sealed box.
            let sealedBox = try AES.GCM.SealedBox(combined: bundle.sealedBox)
            let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.unwrap.finish",
                metadata: ["result": "success"]
            )
            return plaintext
        } catch {
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.unwrap.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
    }

    func deleteKey(_ handle: any SEKeyHandle) throws {
        traceStore?.record(
            category: .operation,
            name: "secureEnclave.deleteKey",
            metadata: ["result": "noop"]
        )
        // SE keys are deleted by removing them from Keychain.
        // The actual SE key is tied to its dataRepresentation stored in Keychain.
        // Once the Keychain item is removed, the SE key becomes inaccessible.
        // The caller (AuthenticationManager) is responsible for Keychain deletion.
    }

    func reconstructKey(from data: Data, authenticationContext: LAContext?) throws -> any SEKeyHandle {
        traceStore?.record(
            category: .operation,
            name: "secureEnclave.reconstructKey.start",
            metadata: ["hasAuthenticationContext": authenticationContext == nil ? "false" : "true"]
        )
        // Reconstructing from dataRepresentation triggers device authentication
        // (Face ID / Touch ID) when the key has biometric access control flags.
        // Passing a pre-authenticated LAContext reuses the existing session,
        // avoiding a repeated Face ID prompt.
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: data,
                authenticationContext: authenticationContext
            )
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.reconstructKey.finish",
                metadata: ["result": "success"]
            )
            return HardwareSEKey(key: key)
        } catch {
            traceStore?.record(
                category: .operation,
                name: "secureEnclave.reconstructKey.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
    }
}
