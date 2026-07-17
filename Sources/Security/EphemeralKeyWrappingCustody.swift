import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Errors from the ephemeral key-wrapping custody.
enum EphemeralKeyWrappingCustodyError: Error, Equatable {
    /// No Secure Enclave exists in this environment. Ephemeral custody fails
    /// closed — there is deliberately no software fallback branch.
    case secureEnclaveUnavailable
}

/// Real-Secure Enclave key-wrapping custody for ephemeral sandboxes: the guided
/// tutorial dependency graph and the DEBUG UI-test container.
///
/// Every operation delegates to the production `HardwareSecureEnclave`, so the
/// sandbox exercises the real `PrivateKeyEnvelope` seal/open path — hardware
/// P-256 ECDH, HKDF, AES-GCM with public-parameter AAD, fingerprint binding,
/// and the fail-closed device-binding mismatch check — with one deliberate
/// difference: **no access control is ever applied to the wrapping key**
/// (`accessControl` and `authenticationContext` arguments are dropped).
/// Authentication prompts on custody operations are a production behavior the
/// ephemeral sandbox does not reproduce; a nil-ACL Secure Enclave key operates
/// promptlessly, and its `dataRepresentation` lives only inside the envelope
/// rows of the sandbox's in-memory keychain — zero persistent Keychain rows,
/// zero residue once the sandbox is discarded.
///
/// Where no Secure Enclave exists, every entry point throws
/// `EphemeralKeyWrappingCustodyError.secureEnclaveUnavailable` (fail closed).
struct EphemeralKeyWrappingCustody: SecureEnclaveManageable {
    private let hardware = HardwareSecureEnclave()

    static var isAvailable: Bool {
        HardwareSecureEnclave.isAvailable
    }

    func generateWrappingKey(accessControl: SecAccessControl?, authenticationContext: LAContext?) throws -> any SEKeyHandle {
        guard Self.isAvailable else {
            throw EphemeralKeyWrappingCustodyError.secureEnclaveUnavailable
        }
        // Deliberately promptless: the caller's access control and context are
        // not forwarded (see the type doc comment).
        return try hardware.generateWrappingKey(accessControl: nil, authenticationContext: nil)
    }

    func wrap(privateKey: Data, using handle: any SEKeyHandle, fingerprint: String) throws -> WrappedKeyBundle {
        guard Self.isAvailable else {
            throw EphemeralKeyWrappingCustodyError.secureEnclaveUnavailable
        }
        return try hardware.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint)
    }

    func unwrap(bundle: WrappedKeyBundle, using handle: any SEKeyHandle, fingerprint: String) throws -> Data {
        guard Self.isAvailable else {
            throw EphemeralKeyWrappingCustodyError.secureEnclaveUnavailable
        }
        return try hardware.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
    }

    func deleteKey(_ handle: any SEKeyHandle) throws {
        try hardware.deleteKey(handle)
    }

    func reconstructKey(from data: Data, authenticationContext: LAContext?) throws -> any SEKeyHandle {
        guard Self.isAvailable else {
            throw EphemeralKeyWrappingCustodyError.secureEnclaveUnavailable
        }
        // Nil-ACL keys reconstruct and operate without authentication; the
        // caller's context is deliberately not forwarded.
        return try hardware.reconstructKey(from: data, authenticationContext: nil)
    }
}
