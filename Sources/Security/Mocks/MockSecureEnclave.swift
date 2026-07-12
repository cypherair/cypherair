import Foundation
import LocalAuthentication
import Security
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Software mock of the Secure Enclave for simulator/unit testing.
/// Uses the same P-256 + HKDF + AES-GCM algorithm as the real SE,
/// but without hardware binding.
///
/// **Known limitation:** `MockSEKey.dataRepresentation` returns
/// `P256.KeyAgreement.PrivateKey.rawRepresentation` (32-byte scalar),
/// whereas production `HardwareSEKey.dataRepresentation` returns
/// `SecureEnclave.P256.KeyAgreement.PrivateKey.dataRepresentation`
/// (SE-specific serialization, ~100+ bytes). The mock's wrapping/unwrapping
/// path is internally consistent but cannot expose bugs related to the
/// SE-specific serialization format. This is an inherent limitation of
/// running without SE hardware.
///
/// This mock allows testing the wrapping/unwrapping logic without
/// requiring a physical device with Secure Enclave hardware.
///
/// - Warning: Not thread-safe. Only use from test methods on a single actor.
final class MockSecureEnclave: SecureEnclaveManageable, @unchecked Sendable {
    /// Track operations for test verification.
    private(set) var generateCallCount = 0
    private(set) var wrapCallCount = 0
    private(set) var unwrapCallCount = 0
    private(set) var reconstructCallCount = 0

    /// The `authenticationContext` passed to the most recent `reconstructKey` /
    /// `generateWrappingKey` call, for asserting whether a call site threads
    /// (or withholds) a context. The mock never evaluates it.
    private(set) var lastReconstructAuthenticationContext: LAContext?
    private(set) var lastGenerateAuthenticationContext: LAContext?

    /// If set, the next operation will throw this error.
    var nextError: Error?

    /// Simulated authentication mode. When set, reconstructKey() will enforce
    /// auth mode constraints (e.g., High Security + no biometrics → failure).
    /// Default: nil (no auth simulation, backward-compatible with existing tests).
    var simulatedAuthMode: AuthenticationMode?

    /// Whether biometrics are available in the simulated environment.
    /// Only checked when simulatedAuthMode is set.
    var biometricsAvailable: Bool = true

    /// Simulated key storage (in production, this is in the SE hardware).
    private var keys: [Data: MockSEKey] = [:]

    static var isAvailable: Bool { true }

    func generateWrappingKey(accessControl: SecAccessControl?, authenticationContext: LAContext?) throws -> any SEKeyHandle {
        if let error = nextError {
            nextError = nil
            throw error
        }
        generateCallCount += 1
        lastGenerateAuthenticationContext = authenticationContext

        #if canImport(CryptoKit)
        // Use software P-256 key (same algorithm, no hardware binding)
        let privateKey = P256.KeyAgreement.PrivateKey()
        let mockKey = MockSEKey(privateKey: privateKey)
        keys[mockKey.dataRepresentation] = mockKey
        return mockKey
        #else
        fatalError("CryptoKit is required for MockSecureEnclave. This fallback should never execute on iOS.")
        #endif
    }

    func wrap(privateKey: Data, using handle: any SEKeyHandle, fingerprint: String) throws -> WrappedKeyBundle {
        if let error = nextError {
            nextError = nil
            throw error
        }
        wrapCallCount += 1

        #if canImport(CryptoKit)
        guard let mockKey = handle as? MockSEKey else {
            throw MockSEError.invalidKeyHandle
        }

        // Same envelope path as production: ephemeral-static ECDH against the mock key's
        // public key, HKDF + AES-GCM seal with public-parameter AAD. Exercises the full
        // PrivateKeyEnvelope contract/binding/tamper logic on the macOS unit lane.
        let envelope = try PrivateKeyEnvelopeCodec.seal(
            privateKey: privateKey,
            fingerprint: fingerprint,
            seKeyData: handle.dataRepresentation,
            seKeyPublicKeyX963: mockKey.privateKey.publicKey.x963Representation
        )
        return WrappedKeyBundle(envelope: try PrivateKeyEnvelopeCodec.encode(envelope))
        #else
        fatalError("CryptoKit is required for MockSecureEnclave. This fallback should never execute on iOS.")
        #endif
    }

    func unwrap(bundle: WrappedKeyBundle, using handle: any SEKeyHandle, fingerprint: String) throws -> Data {
        if let error = nextError {
            nextError = nil
            throw error
        }
        unwrapCallCount += 1

        #if canImport(CryptoKit)
        guard let mockKey = handle as? MockSEKey else {
            throw MockSEError.invalidKeyHandle
        }

        // Mirror production unwrap: decode + validate, fail closed on a bound public-key
        // mismatch, then open-side ECDH (mock private key x envelope ephemeral public key).
        let envelope = try PrivateKeyEnvelopeCodec.decode(
            bundle.envelope,
            expectedFingerprint: fingerprint
        )
        guard envelope.seKeyPublicKeyX963 == mockKey.privateKey.publicKey.x963Representation else {
            throw PrivateKeyEnvelopeError.deviceBindingMismatch
        }
        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: envelope.ephemeralPublicKeyX963
        )
        let sharedSecret = try mockKey.privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        return try PrivateKeyEnvelopeCodec.open(
            envelope: envelope,
            sharedSecret: sharedSecret,
            expectedFingerprint: fingerprint
        )
        #else
        fatalError("CryptoKit is required for MockSecureEnclave. This fallback should never execute on iOS.")
        #endif
    }

    func deleteKey(_ handle: any SEKeyHandle) throws {
        if let error = nextError {
            nextError = nil
            throw error
        }
        keys.removeValue(forKey: handle.dataRepresentation)
    }

    func reconstructKey(from data: Data, authenticationContext: LAContext?) throws -> any SEKeyHandle {
        if let error = nextError {
            nextError = nil
            throw error
        }
        reconstructCallCount += 1
        lastReconstructAuthenticationContext = authenticationContext
        // Simulate auth mode enforcement.
        if let mode = simulatedAuthMode, mode == .highSecurity, !biometricsAvailable {
            throw MockSEError.authenticationFailed
        }
        // Mock ignores authenticationContext — software P-256 doesn't need it.
        #if canImport(CryptoKit)
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: data)
        return MockSEKey(privateKey: privateKey)
        #else
        fatalError("CryptoKit is required for MockSecureEnclave. This fallback should never execute on iOS.")
        #endif
    }

}

#if canImport(CryptoKit)
/// Mock SE key handle backed by a software P-256 key.
final class MockSEKey: SEKeyHandle {
    let privateKey: P256.KeyAgreement.PrivateKey

    var dataRepresentation: Data {
        privateKey.rawRepresentation
    }

    init(privateKey: P256.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
    }
}
#endif

enum MockSEError: Error {
    case invalidKeyHandle
    case authenticationFailed
}
