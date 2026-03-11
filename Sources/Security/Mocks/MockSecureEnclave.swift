import Foundation
import Security
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Software mock of the Secure Enclave for simulator/unit testing.
/// Uses the same P-256 + HKDF + AES-GCM algorithm as the real SE,
/// but without hardware binding.
///
/// This mock allows testing the wrapping/unwrapping logic without
/// requiring a physical device with Secure Enclave hardware.
final class MockSecureEnclave: SecureEnclaveManageable {
    /// Track operations for test verification.
    private(set) var generateCallCount = 0
    private(set) var wrapCallCount = 0
    private(set) var unwrapCallCount = 0
    private(set) var deleteCallCount = 0

    /// If set, the next operation will throw this error.
    var nextError: Error?

    /// Simulated key storage (in production, this is in the SE hardware).
    private var keys: [Data: MockSEKey] = [:]

    static var isAvailable: Bool { true }

    func generateWrappingKey(accessControl: SecAccessControl?) throws -> any SEKeyHandle {
        if let error = nextError {
            nextError = nil
            throw error
        }
        generateCallCount += 1

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

        // Self-ECDH: compute shared secret between key and its own public key
        let sharedSecret = try mockKey.privateKey.sharedSecretFromKeyAgreement(
            with: mockKey.privateKey.publicKey
        )

        // Generate random salt
        var salt = Data(count: 32)
        salt.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }

        // HKDF derive AES-256 key
        let infoData = SEConstants.hkdfInfo(fingerprint: fingerprint)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: infoData,
            outputByteCount: 32
        )

        // AES-GCM seal
        let sealedBox = try AES.GCM.seal(privateKey, using: symmetricKey)

        return WrappedKeyBundle(
            seKeyData: handle.dataRepresentation,
            salt: salt,
            sealedBox: sealedBox.combined!
        )
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

        // Self-ECDH (same as wrapping)
        let sharedSecret = try mockKey.privateKey.sharedSecretFromKeyAgreement(
            with: mockKey.privateKey.publicKey
        )

        // HKDF with stored salt and same info string
        let infoData = SEConstants.hkdfInfo(fingerprint: fingerprint)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: bundle.salt,
            sharedInfo: infoData,
            outputByteCount: 32
        )

        // AES-GCM open
        let sealedBox = try AES.GCM.SealedBox(combined: bundle.sealedBox)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)
        return plaintext
        #else
        fatalError("CryptoKit is required for MockSecureEnclave. This fallback should never execute on iOS.")
        #endif
    }

    func deleteKey(_ handle: any SEKeyHandle) throws {
        if let error = nextError {
            nextError = nil
            throw error
        }
        deleteCallCount += 1
        keys.removeValue(forKey: handle.dataRepresentation)
    }

    func reconstructKey(from data: Data) throws -> any SEKeyHandle {
        #if canImport(CryptoKit)
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: data)
        return MockSEKey(privateKey: privateKey)
        #else
        fatalError("CryptoKit is required for MockSecureEnclave. This fallback should never execute on iOS.")
        #endif
    }

    /// Reset all state for clean test setup.
    func reset() {
        generateCallCount = 0
        wrapCallCount = 0
        unwrapCallCount = 0
        deleteCallCount = 0
        nextError = nil
        keys.removeAll()
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
    case keyNotFound
    case authenticationFailed
}
