import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Security

/// The three flag sets an enclave key may be created with. This is the only
/// place access controls are built, so the invariant that every key carries the
/// application-password option, with the single ML-KEM exception, is a property
/// of this enum rather than of every call site.
public enum EnclaveAccessPolicy: String, Sendable, CaseIterable {
    /// The wrapping key and the identity wrapping key: user presence plus the
    /// application password.
    case presenceAndPassword
    /// Device-bound custody keys other than ML-KEM: any biometric plus the
    /// application password.
    case biometricAndPassword
    /// ML-KEM custody keys only: the enclave cannot decapsulate under the
    /// application-password option, so these carry the biometric alone.
    case biometricOnly

    public var requiresCredential: Bool { self != .biometricOnly }

    var flags: SecAccessControlCreateFlags {
        switch self {
        case .presenceAndPassword: [.privateKeyUsage, .userPresence, .applicationPassword]
        case .biometricAndPassword: [.privateKeyUsage, .biometryAny, .applicationPassword]
        case .biometricOnly: [.privateKeyUsage, .biometryAny]
        }
    }

    public func makeAccessControl() throws(VaultError) -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            flags,
            &error
        ) else {
            _ = error?.takeRetainedValue()
            throw .internalFailure("access control creation failed")
        }
        return control
    }
}

/// A P-256 key-agreement key that lives in the enclave. Sealing needs only its
/// public key and blob; opening runs the agreement inside the enclave.
public protocol EnclaveKeyAgreementKey {
    var dataRepresentation: Data { get }
    var publicKeyX963: Data { get }
    func sharedSecret(withEphemeralPublicKeyX963 x963: Data) throws -> SharedSecret
}

/// The enclave as the vault sees it. The production implementation is CryptoKit,
/// the sandbox and the tests use `SoftwareEnclave`.
public protocol Enclave: Sendable {
    var isAvailable: Bool { get }

    /// Creates a key under `policy`, which must require a credential;
    /// `credential` becomes its application password.
    func makeKeyAgreementKey(
        policy: EnclaveAccessPolicy,
        credential: borrowing SensitiveBuffer,
        context: LAContext
    ) throws -> any EnclaveKeyAgreementKey

    /// Reconstructs a key from its blob for use with `context`, presenting
    /// `credential` as the application password.
    func keyAgreementKey(
        from blob: Data,
        credential: borrowing SensitiveBuffer,
        context: LAContext
    ) throws -> any EnclaveKeyAgreementKey

    /// Creates a custody key whose policy requires a credential.
    func makeCustodyKey(type: CustodyKeyType, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveCustodyKey
    /// Creates a custody key whose policy carries no credential: ML-KEM only.
    func makeCredentialFreeCustodyKey(type: CustodyKeyType, context: LAContext) throws -> any EnclaveCustodyKey
    func custodyKey(type: CustodyKeyType, from blob: Data, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveCustodyKey
    func credentialFreeCustodyKey(type: CustodyKeyType, from blob: Data, context: LAContext) throws -> any EnclaveCustodyKey
}

extension LAContext {
    /// Presents `credential` to the enclave as this context's application
    /// password. The context keeps its own copy; the temporary is erased here.
    func present(credential: borrowing SensitiveBuffer) throws(VaultError) {
        var copy = credential.withUnsafeBytes { Data($0) }
        defer { copy.withUnsafeMutableBytes { sensitiveErase($0) } }
        guard setCredential(copy, type: .applicationPassword) else {
            throw .internalFailure("credential could not be set")
        }
    }
}
