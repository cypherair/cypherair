import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// C6: Secure Enclave and Keychain integration tests on real hardware.
final class DeviceSecureEnclaveTests: DeviceSecurityTestCase {
    // MARK: - C6.1: SE Key Generation

    func test_seGenerateKey_noAccessControl_succeeds() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        XCTAssertFalse(handle.dataRepresentation.isEmpty, "SE key dataRepresentation must not be empty")
    }

    func test_seGenerateKey_standardAccessControl_succeeds() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        var error: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny, .or, .devicePasscode],
            &error
        )
        XCTAssertNotNil(accessControl, "Failed to create Standard access control")

        let handle = try secureEnclave.generateWrappingKey(accessControl: accessControl, authenticationContext: nil)
        XCTAssertFalse(handle.dataRepresentation.isEmpty)
    }

    func test_seGenerateKey_highSecurityAccessControl_succeeds() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        var error: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            &error
        )
        XCTAssertNotNil(accessControl, "Failed to create High Security access control")

        let handle = try secureEnclave.generateWrappingKey(accessControl: accessControl, authenticationContext: nil)
        XCTAssertFalse(handle.dataRepresentation.isEmpty)
    }

    // MARK: - C6.2: SE Wrap / Unwrap Round-Trip

    func test_seWrapUnwrap_ed25519Size_roundTrip_returnsIdentical() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        // Ed25519 private key is 32 bytes
        let fakePrivateKey = Data(repeating: 0xAB, count: 32)

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        XCTAssertFalse(bundle.envelope.isEmpty)
        let decoded = try PrivateKeyEnvelopeCodec.decode(bundle.envelope, expectedFingerprint: fingerprint)
        XCTAssertEqual(decoded.seKeyData, handle.dataRepresentation, "Envelope must carry the SE key handle")
        XCTAssertEqual(decoded.hkdfSalt.count, 32, "HKDF salt must be 32 bytes")
        XCTAssertEqual(decoded.ephemeralPublicKeyX963.count, 65, "Ephemeral key must be a P-256 X9.63 point")
        XCTAssertEqual(decoded.seKeyPublicKeyX963.count, 65, "SE public key must be a P-256 X9.63 point")

        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
        XCTAssertEqual(unwrapped, fakePrivateKey, "Unwrapped key must match original")
    }

    func test_seWrapUnwrap_ed448Size_roundTrip_returnsIdentical() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        // Ed448 private key is 57 bytes
        let fakePrivateKey = Data(repeating: 0xCD, count: 57)

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
        XCTAssertEqual(unwrapped, fakePrivateKey, "Ed448-size key must survive wrap/unwrap")
    }

    func test_seUnwrap_wrongFingerprint_fails() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprintA = uniqueFingerprint()
        let fingerprintB = uniqueFingerprint()
        let fakePrivateKey = Data(repeating: 0xEF, count: 32)

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: handle, fingerprint: fingerprintA)

        // Unwrap with a different fingerprint → HKDF derives a different key → AES-GCM open fails.
        XCTAssertThrowsError(
            try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprintB),
            "Unwrap with wrong fingerprint must fail (HKDF domain separation)"
        )
    }

    func test_seReconstructKey_fromDataRepresentation_succeeds() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let fakePrivateKey = Data(repeating: 0x11, count: 32)

        // Generate and wrap.
        let originalHandle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: originalHandle, fingerprint: fingerprint)

        // Reconstruct SE key from dataRepresentation (simulates app restart).
        let reconstructedHandle = try secureEnclave.reconstructKey(from: originalHandle.dataRepresentation, authenticationContext: nil)

        // Unwrap using reconstructed handle.
        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: reconstructedHandle, fingerprint: fingerprint)
        XCTAssertEqual(unwrapped, fakePrivateKey, "Reconstructed SE key must unwrap correctly")
    }

    func test_seMultipleKeys_independentFingerprints_nonInterfering() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fp1 = uniqueFingerprint()
        let fp2 = uniqueFingerprint()
        let key1 = Data(repeating: 0xAA, count: 32)
        let key2 = Data(repeating: 0xBB, count: 57)

        let handle1 = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let handle2 = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)

        let bundle1 = try secureEnclave.wrap(privateKey: key1, using: handle1, fingerprint: fp1)
        let bundle2 = try secureEnclave.wrap(privateKey: key2, using: handle2, fingerprint: fp2)

        let unwrapped1 = try secureEnclave.unwrap(bundle: bundle1, using: handle1, fingerprint: fp1)
        let unwrapped2 = try secureEnclave.unwrap(bundle: bundle2, using: handle2, fingerprint: fp2)

        XCTAssertEqual(unwrapped1, key1)
        XCTAssertEqual(unwrapped2, key2)
        XCTAssertNotEqual(unwrapped1, unwrapped2, "Different keys must remain distinct")
    }

    func test_seWrapUnwrap_randomKeyData_roundTrip() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        // Use real random bytes instead of repeating pattern.
        var randomKey = Data(count: 32)
        let status = randomKey.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        XCTAssertEqual(status, errSecSuccess, "SecRandomCopyBytes must succeed")

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(privateKey: randomKey, using: handle, fingerprint: fingerprint)
        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)

        XCTAssertEqual(unwrapped, randomKey, "Random key data must survive wrap/unwrap")
    }

    // MARK: - C6.3: Keychain Integration

    func test_keychain_saveLoad_roundTrip() throws {
        let service = "com.cypherair.test.\(UUID().uuidString)"
        let account = KeychainConstants.defaultAccount
        trackKeychain(service: service, account: account)

        let testData = Data("keychain-test-data".utf8)
        try keychain.save(testData, service: service, account: account, accessControl: nil)

        let loaded = try keychain.load(service: service, account: account)
        XCTAssertEqual(loaded, testData, "Loaded data must match saved data")
    }

    func test_keychain_saveDuplicate_throwsDuplicateItem() throws {
        let service = "com.cypherair.test.\(UUID().uuidString)"
        let account = KeychainConstants.defaultAccount
        trackKeychain(service: service, account: account)

        let testData = Data("first".utf8)
        try keychain.save(testData, service: service, account: account, accessControl: nil)

        XCTAssertThrowsError(
            try keychain.save(Data("second".utf8), service: service, account: account, accessControl: nil)
        ) { error in
            guard let keychainError = error as? KeychainError else {
                return XCTFail("Expected KeychainError, got \(type(of: error))")
            }
            if case .duplicateItem = keychainError {
                // Expected
            } else {
                XCTFail("Expected .duplicateItem, got \(keychainError)")
            }
        }
    }

    func test_keychain_loadNonexistent_throwsItemNotFound() {
        let service = "com.cypherair.test.nonexistent.\(UUID().uuidString)"
        let account = KeychainConstants.defaultAccount

        XCTAssertThrowsError(try keychain.load(service: service, account: account)) { error in
            guard let keychainError = error as? KeychainError else {
                return XCTFail("Expected KeychainError, got \(type(of: error))")
            }
            if case .itemNotFound = keychainError {
                // Expected
            } else {
                XCTFail("Expected .itemNotFound, got \(keychainError)")
            }
        }
    }

    func test_keychain_deleteAndLoad_throwsItemNotFound() throws {
        let service = "com.cypherair.test.\(UUID().uuidString)"
        let account = KeychainConstants.defaultAccount
        trackKeychain(service: service, account: account)

        try keychain.save(Data("to-delete".utf8), service: service, account: account, accessControl: nil)
        try keychain.delete(service: service, account: account)

        XCTAssertThrowsError(try keychain.load(service: service, account: account)) { error in
            guard let keychainError = error as? KeychainError,
                  case .itemNotFound = keychainError else {
                return XCTFail("Expected .itemNotFound after delete")
            }
        }
    }

    func test_keychain_exists_trueAfterSave_falseAfterDelete() throws {
        let service = "com.cypherair.test.\(UUID().uuidString)"
        let account = KeychainConstants.defaultAccount
        trackKeychain(service: service, account: account)

        XCTAssertFalse(keychain.exists(service: service, account: account), "Must not exist before save")

        try keychain.save(Data("exists-test".utf8), service: service, account: account, accessControl: nil)
        XCTAssertTrue(keychain.exists(service: service, account: account), "Must exist after save")

        try keychain.delete(service: service, account: account)
        XCTAssertFalse(keychain.exists(service: service, account: account), "Must not exist after delete")
    }

    func test_seWrap_storeInKeychain_loadAndUnwrap_fullRoundTrip() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0x42, count: 32)

        // 1. Generate SE key and wrap.
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        // 2. Store the single envelope row in the real Keychain.
        try keychain.save(bundle.envelope, service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint), account: account, accessControl: nil)

        // 3. Load from Keychain.
        let loadedEnvelope = try keychain.load(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint), account: account)

        // 4. Extract the SE key handle from the envelope, reconstruct, and unwrap.
        let seKeyData = try PrivateKeyEnvelopeCodec.seKeyData(from: loadedEnvelope, expectedFingerprint: fingerprint)
        let reconstructed = try secureEnclave.reconstructKey(from: seKeyData, authenticationContext: nil)
        let loadedBundle = WrappedKeyBundle(envelope: loadedEnvelope)
        let unwrapped = try secureEnclave.unwrap(bundle: loadedBundle, using: reconstructed, fingerprint: fingerprint)

        XCTAssertEqual(unwrapped, fakePrivateKey, "Full Keychain round-trip must preserve key data")
    }

    // MARK: - C6.4: SE Unwrap → FFI Decrypt (End-to-End)

    /// C6.4: Full pipeline — generate key via FFI, SE wrap certData, store in Keychain,
    /// load + SE unwrap, then decrypt via FFI. Profile A (v4, SEIPDv1).
    func test_seUnwrapThenDecrypt_profileA_succeeds() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let plaintext = Data("C6.4 Profile A: SE → FFI decrypt test".utf8)

        // 1. Generate Profile A key via FFI.
        let generated = try engine.generateKey(
            name: "C6.4 Test A", email: nil, expirySeconds: nil, profile: .universal
        )

        // 2. Encrypt a message using the public key (signed).
        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [generated.publicKeyData],
            signingKey: generated.certData,
            encryptToSelf: nil
        )

        // 3. SE wrap the certData (full cert with private key).
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: generated.certData,
            using: handle,
            fingerprint: fingerprint
        )

        // 4. Store the single envelope row in the Keychain.
        try keychain.save(bundle.envelope,
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account, accessControl: nil)

        // 5. Load from Keychain and SE unwrap (simulates app restart + decrypt flow).
        let loadedEnvelope = try keychain.load(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account)

        let seKeyData = try PrivateKeyEnvelopeCodec.seKeyData(from: loadedEnvelope, expectedFingerprint: fingerprint)
        let reconstructed = try secureEnclave.reconstructKey(from: seKeyData, authenticationContext: nil)
        let loadedBundle = WrappedKeyBundle(envelope: loadedEnvelope)
        let recoveredCertData = try secureEnclave.unwrap(
            bundle: loadedBundle, using: reconstructed, fingerprint: fingerprint)

        // 6. Decrypt using the recovered certData via FFI.
        let result = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [recoveredCertData],
            verificationKeys: [generated.publicKeyData]
        )

        // 7. Verify plaintext and signature.
        XCTAssertEqual(result.plaintext, plaintext,
            "Decrypted plaintext must match original after SE round-trip")
        XCTAssertEqual(result.summaryState, .verified,
            "Signature must verify after SE round-trip")
    }

    /// C6.4: Same end-to-end pipeline for Profile B (v6, Ed448+X448, SEIPDv2 AEAD OCB).
    func test_seUnwrapThenDecrypt_profileB_succeeds() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let plaintext = Data("C6.4 Profile B: SE → FFI decrypt test (AEAD OCB)".utf8)

        // 1. Generate Profile B key via FFI.
        let generated = try engine.generateKey(
            name: "C6.4 Test B", email: nil, expirySeconds: nil, profile: .advanced
        )

        // 2. Encrypt a message (SEIPDv2 AEAD for v6 recipient).
        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [generated.publicKeyData],
            signingKey: generated.certData,
            encryptToSelf: nil
        )

        // 3. SE wrap the certData.
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: generated.certData,
            using: handle,
            fingerprint: fingerprint
        )

        // 4. Store the single envelope row in the Keychain.
        try keychain.save(bundle.envelope,
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account, accessControl: nil)

        // 5. Load from Keychain and SE unwrap.
        let loadedEnvelope = try keychain.load(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account)

        let seKeyData = try PrivateKeyEnvelopeCodec.seKeyData(from: loadedEnvelope, expectedFingerprint: fingerprint)
        let reconstructed = try secureEnclave.reconstructKey(from: seKeyData, authenticationContext: nil)
        let loadedBundle = WrappedKeyBundle(envelope: loadedEnvelope)
        let recoveredCertData = try secureEnclave.unwrap(
            bundle: loadedBundle, using: reconstructed, fingerprint: fingerprint)

        // 6. Decrypt using the recovered certData via FFI.
        let result = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [recoveredCertData],
            verificationKeys: [generated.publicKeyData]
        )

        // 7. Verify plaintext and signature.
        XCTAssertEqual(result.plaintext, plaintext,
            "Profile B decrypted plaintext must match original after SE round-trip")
        XCTAssertEqual(result.summaryState, .verified,
            "Profile B signature must verify after SE round-trip")
    }

    // MARK: - C6.5: SE Key Deletion → Unwrap Fails

    /// C6.5: After deleting the envelope row for an identity,
    /// attempting to load it should fail with .itemNotFound.
    func test_seKeyDeletion_thenLoadFails_withItemNotFound() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0xDE, count: 32)

        // 1. Generate SE key, wrap, store the envelope row in the Keychain.
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        try keychain.save(bundle.envelope,
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account, accessControl: nil)

        // Verify the row exists before deletion.
        XCTAssertTrue(keychain.exists(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account))

        // 2. Delete the envelope row (simulates key deletion).
        try keychain.delete(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account)

        // 3. Attempting to load it should fail with .itemNotFound.
        XCTAssertThrowsError(
            try keychain.load(
                service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
                account: account)
        ) { error in
            guard let keychainError = error as? KeychainError,
                  case .itemNotFound = keychainError else {
                return XCTFail("Expected .itemNotFound after deletion, got \(error)")
            }
        }

        // 4. Verify the row is gone.
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account), "Envelope row must not exist after deletion")
    }

    /// C6.5: Tampered envelope row — flipping a stored byte must make unwrap fail closed.
    /// The single-row envelope replaces the former partial-deletion scenario, which is
    /// structurally impossible now that the bundle is one atomic row.
    func test_seWrap_tamperedEnvelope_unwrapFailsClosed() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0xEF, count: 57)

        // 1. Generate SE key, wrap, store the envelope row.
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        try keychain.save(bundle.envelope,
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account, accessControl: nil)

        // 2. Flip the final byte of the stored envelope (AES-GCM tag region) and re-store.
        var tampered = try keychain.load(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account)
        tampered[tampered.index(before: tampered.endIndex)] ^= 0xFF
        try keychain.update(tampered,
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account)

        // 3. Reconstruct + unwrap must fail closed — either the contract/decoder rejects the
        //    mutated bytes or AES-GCM authentication fails.
        let loadedEnvelope = try keychain.load(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account)
        XCTAssertThrowsError(
            try {
                let seKeyData = try PrivateKeyEnvelopeCodec.seKeyData(from: loadedEnvelope, expectedFingerprint: fingerprint)
                let reconstructed = try secureEnclave.reconstructKey(from: seKeyData, authenticationContext: nil)
                _ = try secureEnclave.unwrap(
                    bundle: WrappedKeyBundle(envelope: loadedEnvelope),
                    using: reconstructed,
                    fingerprint: fingerprint)
            }(),
            "A tampered envelope must never yield plaintext"
        )
    }

    // MARK: - Keychain Full Lifecycle Loop

    /// Run 10 iterations of the full Keychain lifecycle: generate SE key → wrap → store →
    /// load → unwrap → verify → delete → verify deletion. Alternates between 32-byte
    /// (Ed25519) and 57-byte (Ed448) key sizes. Catches state leaks between iterations.
    func test_keychainFullLifecycleLoop_10x_noStateLeaks() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let account = KeychainConstants.defaultAccount

        for i in 0..<10 {
            let fingerprint = uniqueFingerprint()
            let keySize = (i % 2 == 0) ? 32 : 57
            let fakeKey = Data(repeating: UInt8(i + 1), count: keySize)

            // Generate SE key and wrap
            let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
            let bundle = try secureEnclave.wrap(privateKey: fakeKey, using: handle, fingerprint: fingerprint)

            // Store the single envelope row
            try keychain.save(bundle.envelope, service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint), account: account, accessControl: nil)

            // Load, reconstruct, unwrap, verify
            let loadedEnvelope = try keychain.load(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint), account: account)

            let seKeyData = try PrivateKeyEnvelopeCodec.seKeyData(from: loadedEnvelope, expectedFingerprint: fingerprint)
            let reconstructed = try secureEnclave.reconstructKey(from: seKeyData, authenticationContext: nil)
            let loadedBundle = WrappedKeyBundle(envelope: loadedEnvelope)
            let unwrapped = try secureEnclave.unwrap(bundle: loadedBundle, using: reconstructed, fingerprint: fingerprint)

            XCTAssertEqual(unwrapped, fakeKey, "Iteration \(i): unwrapped key must match original")

            // Delete the envelope row
            try keychain.delete(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint), account: account)

            // Verify deletion
            XCTAssertFalse(keychain.exists(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint), account: account),
                           "Iteration \(i): envelope row must be deleted")
        }
    }
}
