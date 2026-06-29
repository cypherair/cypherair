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
    /// Secure Enclave is not available on this device.
    case notAvailable
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
/// Wrapping scheme (identical for Ed25519, X25519, Ed448, X448 keys), via
/// `PrivateKeyEnvelope`:
/// 1. Generate a persistent SE P-256 KeyAgreement key with access control flags.
/// 2. Ephemeral-static ECDH: a fresh software ephemeral P-256 private key agrees with
///    the persistent SE public key on seal; on open the persistent SE private key
///    agrees with the ephemeral public key inside SE hardware.
/// 3. HKDF(SHA-256, randomSalt, domain-bound sharedInfo) -> AES-256 key.
/// 4. AES.GCM.seal(privateKeyBytes, authenticating: public-parameter AAD) -> envelope.
///
/// SECURITY-CRITICAL: Changes to this file require human review.
/// See SECURITY.md Section 3 and Section 10.
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
            // Ephemeral-static ECDH + HKDF + AES-GCM seal, with public-parameter AAD.
            // The persistent SE public key is the static party; the codec generates the
            // software ephemeral private key. The derived SymmetricKey is an opaque
            // CryptoKit type that clears its own secure memory when it goes out of scope.
            let envelope = try PrivateKeyEnvelopeCodec.seal(
                privateKey: privateKey,
                fingerprint: fingerprint,
                seKeyData: handle.dataRepresentation,
                seKeyPublicKeyX963: hwKey.key.publicKey.x963Representation
            )
            let encoded = try PrivateKeyEnvelopeCodec.encode(envelope)

            traceStore?.record(
                category: .operation,
                name: "secureEnclave.wrap.finish",
                metadata: ["result": "success"]
            )
            return WrappedKeyBundle(envelope: encoded)
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
            // Decode + validate the envelope, then run the open-side ECDH inside the SE:
            // persistent SE private key x the envelope's software ephemeral public key.
            let envelope = try PrivateKeyEnvelopeCodec.decode(
                bundle.envelope,
                expectedFingerprint: fingerprint
            )
            // Fail closed before any key agreement if the bound SE public key does not
            // match this handle. The AAD already binds SHA-256(seKeyPublicKeyX963), so a
            // mismatched key fails AES-GCM regardless; this surfaces a clear error first.
            guard envelope.seKeyPublicKeyX963 == hwKey.key.publicKey.x963Representation else {
                throw PrivateKeyEnvelopeError.deviceBindingMismatch
            }
            let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(
                x963Representation: envelope.ephemeralPublicKeyX963
            )
            let sharedSecret = try hwKey.key.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
            let plaintext = try PrivateKeyEnvelopeCodec.open(
                envelope: envelope,
                sharedSecret: sharedSecret,
                expectedFingerprint: fingerprint
            )
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
