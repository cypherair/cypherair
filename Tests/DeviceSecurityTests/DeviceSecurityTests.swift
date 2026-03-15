import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// C6/C7/C8: Device-only Security Layer Tests
///
/// These tests exercise real Secure Enclave hardware, real Keychain,
/// and real biometric authentication. They MUST run on a physical device
/// (iPhone 17 Pro Max or any device with Secure Enclave).
///
/// Run with: CypherAir-DeviceTests test plan on a connected device.
final class DeviceSecurityTests: XCTestCase {

    // MARK: - Properties

    private var keychain: SystemKeychain!
    private var secureEnclave: HardwareSecureEnclave!
    /// Fingerprints created during the test, cleaned up in tearDown.
    private var createdFingerprints: [String] = []
    /// Raw Keychain service keys created during the test, cleaned up in tearDown.
    private var createdKeychainServices: [(service: String, account: String)] = []

    // MARK: - Setup / Teardown

    override func setUp() {
        super.setUp()
        keychain = SystemKeychain()
        secureEnclave = HardwareSecureEnclave()
    }

    override func tearDown() {
        // Clean up all Keychain items created during the test.
        let account = KeychainConstants.defaultAccount
        for fingerprint in createdFingerprints {
            // Permanent items
            try? keychain.delete(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account)
            try? keychain.delete(service: KeychainConstants.saltService(fingerprint: fingerprint), account: account)
            try? keychain.delete(service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account)
            // Pending items (mode switch)
            try? keychain.delete(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account)
            try? keychain.delete(service: KeychainConstants.pendingSaltService(fingerprint: fingerprint), account: account)
            try? keychain.delete(service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint), account: account)
        }
        for entry in createdKeychainServices {
            try? keychain.delete(service: entry.service, account: entry.account)
        }
        // Clean up UserDefaults flags
        UserDefaults.standard.removeObject(forKey: AuthPreferences.rewrapInProgressKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.authModeKey)

        createdFingerprints = []
        createdKeychainServices = []
        keychain = nil
        secureEnclave = nil
        super.tearDown()
    }

    /// Generate a unique test fingerprint to avoid Keychain collisions between tests.
    private func uniqueFingerprint() -> String {
        let fp = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        createdFingerprints.append(fp)
        return fp
    }

    /// Track a Keychain service for cleanup.
    private func trackKeychain(service: String, account: String = KeychainConstants.defaultAccount) {
        createdKeychainServices.append((service: service, account: account))
    }

    // MARK: - C6.1: SE Key Generation

    func test_seGenerateKey_noAccessControl_succeeds() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
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

        let handle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
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

        let handle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        XCTAssertFalse(handle.dataRepresentation.isEmpty)
    }

    // MARK: - C6.2: SE Wrap / Unwrap Round-Trip

    func test_seWrapUnwrap_ed25519Size_roundTrip_returnsIdentical() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        // Ed25519 private key is 32 bytes
        let fakePrivateKey = Data(repeating: 0xAB, count: 32)

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        XCTAssertFalse(bundle.seKeyData.isEmpty)
        XCTAssertFalse(bundle.salt.isEmpty)
        XCTAssertFalse(bundle.sealedBox.isEmpty)
        XCTAssertEqual(bundle.salt.count, 32, "Salt must be 32 bytes")

        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
        XCTAssertEqual(unwrapped, fakePrivateKey, "Unwrapped key must match original")
    }

    func test_seWrapUnwrap_ed448Size_roundTrip_returnsIdentical() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        // Ed448 private key is 57 bytes
        let fakePrivateKey = Data(repeating: 0xCD, count: 57)

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
        XCTAssertEqual(unwrapped, fakePrivateKey, "Ed448-size key must survive wrap/unwrap")
    }

    func test_seUnwrap_wrongFingerprint_fails() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprintA = uniqueFingerprint()
        let fingerprintB = uniqueFingerprint()
        let fakePrivateKey = Data(repeating: 0xEF, count: 32)

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
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
        let originalHandle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: originalHandle, fingerprint: fingerprint)

        // Reconstruct SE key from dataRepresentation (simulates app restart).
        let reconstructedHandle = try secureEnclave.reconstructKey(from: originalHandle.dataRepresentation)

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

        let handle1 = try secureEnclave.generateWrappingKey(accessControl: nil)
        let handle2 = try secureEnclave.generateWrappingKey(accessControl: nil)

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

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
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
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        // 2. Store all 3 items in real Keychain.
        try keychain.save(bundle.seKeyData, service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(bundle.salt, service: KeychainConstants.saltService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(bundle.sealedBox, service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        // 3. Load from Keychain.
        let loadedSEKey = try keychain.load(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account)
        let loadedSalt = try keychain.load(service: KeychainConstants.saltService(fingerprint: fingerprint), account: account)
        let loadedSealed = try keychain.load(service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account)

        // 4. Reconstruct SE key and unwrap.
        let reconstructed = try secureEnclave.reconstructKey(from: loadedSEKey)
        let loadedBundle = WrappedKeyBundle(seKeyData: loadedSEKey, salt: loadedSalt, sealedBox: loadedSealed)
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
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: generated.certData,
            using: handle,
            fingerprint: fingerprint
        )

        // 4. Store in Keychain (3 items).
        try keychain.save(bundle.seKeyData,
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account, accessControl: nil)
        try keychain.save(bundle.salt,
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account, accessControl: nil)
        try keychain.save(bundle.sealedBox,
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account, accessControl: nil)

        // 5. Load from Keychain and SE unwrap (simulates app restart + decrypt flow).
        let loadedSEKey = try keychain.load(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account)
        let loadedSalt = try keychain.load(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account)
        let loadedSealed = try keychain.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account)

        let reconstructed = try secureEnclave.reconstructKey(from: loadedSEKey)
        let loadedBundle = WrappedKeyBundle(
            seKeyData: loadedSEKey, salt: loadedSalt, sealedBox: loadedSealed)
        let recoveredCertData = try secureEnclave.unwrap(
            bundle: loadedBundle, using: reconstructed, fingerprint: fingerprint)

        // 6. Decrypt using the recovered certData via FFI.
        let result = try engine.decrypt(
            ciphertext: ciphertext,
            secretKeys: [recoveredCertData],
            verificationKeys: [generated.publicKeyData]
        )

        // 7. Verify plaintext and signature.
        XCTAssertEqual(result.plaintext, plaintext,
            "Decrypted plaintext must match original after SE round-trip")
        XCTAssertEqual(result.signatureStatus, .valid,
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
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: generated.certData,
            using: handle,
            fingerprint: fingerprint
        )

        // 4. Store in Keychain.
        try keychain.save(bundle.seKeyData,
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account, accessControl: nil)
        try keychain.save(bundle.salt,
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account, accessControl: nil)
        try keychain.save(bundle.sealedBox,
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account, accessControl: nil)

        // 5. Load from Keychain and SE unwrap.
        let loadedSEKey = try keychain.load(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account)
        let loadedSalt = try keychain.load(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account)
        let loadedSealed = try keychain.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account)

        let reconstructed = try secureEnclave.reconstructKey(from: loadedSEKey)
        let loadedBundle = WrappedKeyBundle(
            seKeyData: loadedSEKey, salt: loadedSalt, sealedBox: loadedSealed)
        let recoveredCertData = try secureEnclave.unwrap(
            bundle: loadedBundle, using: reconstructed, fingerprint: fingerprint)

        // 6. Decrypt using the recovered certData via FFI.
        let result = try engine.decrypt(
            ciphertext: ciphertext,
            secretKeys: [recoveredCertData],
            verificationKeys: [generated.publicKeyData]
        )

        // 7. Verify plaintext and signature.
        XCTAssertEqual(result.plaintext, plaintext,
            "Profile B decrypted plaintext must match original after SE round-trip")
        XCTAssertEqual(result.signatureStatus, .valid,
            "Profile B signature must verify after SE round-trip")
    }

    // MARK: - C6.5: SE Key Deletion → Unwrap Fails

    /// C6.5: After deleting all 3 Keychain items for an identity,
    /// attempting to load the SE key data should fail with .itemNotFound.
    func test_seKeyDeletion_thenLoadFails_withItemNotFound() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0xDE, count: 32)

        // 1. Generate SE key, wrap, store in Keychain.
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        try keychain.save(bundle.seKeyData,
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account, accessControl: nil)
        try keychain.save(bundle.salt,
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account, accessControl: nil)
        try keychain.save(bundle.sealedBox,
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account, accessControl: nil)

        // Verify items exist before deletion.
        XCTAssertTrue(keychain.exists(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account))

        // 2. Delete all 3 Keychain items (simulates key deletion).
        try keychain.delete(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account)
        try keychain.delete(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account)
        try keychain.delete(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account)

        // 3. Attempting to load SE key data should fail with .itemNotFound.
        XCTAssertThrowsError(
            try keychain.load(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: account)
        ) { error in
            guard let keychainError = error as? KeychainError,
                  case .itemNotFound = keychainError else {
                return XCTFail("Expected .itemNotFound after deletion, got \(error)")
            }
        }

        // 4. Verify all 3 items are gone.
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account), "SE key must not exist after deletion")
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account), "Salt must not exist after deletion")
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account), "Sealed box must not exist after deletion")
    }

    /// C6.5: Partial deletion — sealed box removed but SE key and salt remain.
    /// Loading the sealed box should fail, blocking the unwrap path.
    func test_seKeyPartialDeletion_sealedBoxMissing_throwsClearError() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0xEF, count: 57)

        // 1. Generate SE key, wrap, store in Keychain.
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        try keychain.save(bundle.seKeyData,
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account, accessControl: nil)
        try keychain.save(bundle.salt,
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account, accessControl: nil)
        try keychain.save(bundle.sealedBox,
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account, accessControl: nil)

        // 2. Delete ONLY the sealed box (simulates partial data corruption).
        try keychain.delete(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account)

        // 3. SE key and salt still exist.
        XCTAssertTrue(keychain.exists(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account), "SE key should still exist")
        XCTAssertTrue(keychain.exists(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account), "Salt should still exist")

        // 4. Loading sealed box fails — blocks the unwrap path.
        XCTAssertThrowsError(
            try keychain.load(
                service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
                account: account)
        ) { error in
            guard let keychainError = error as? KeychainError,
                  case .itemNotFound = keychainError else {
                return XCTFail("Expected .itemNotFound for missing sealed box, got \(error)")
            }
        }
    }

    // MARK: - C7.1: Authentication Manager — Access Control

    func test_createAccessControl_standard_succeeds() throws {
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let ac = try authManager.createAccessControl(for: .standard)
        // SecAccessControl is an opaque type; if we get here without throwing, it succeeded.
        XCTAssertNotNil(ac)
    }

    func test_createAccessControl_highSecurity_succeeds() throws {
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let ac = try authManager.createAccessControl(for: .highSecurity)
        XCTAssertNotNil(ac)
    }

    func test_canEvaluate_standard_returnsTrue() {
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        // On a real device with passcode set, standard mode should always be evaluable.
        XCTAssertTrue(authManager.canEvaluate(mode: .standard), "Standard mode must be evaluable on device")
    }

    func test_isBiometricsAvailable_onFaceIDDevice_returnsTrue() {
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        // iPhone 17 Pro Max has Face ID — this should return true.
        XCTAssertTrue(authManager.isBiometricsAvailable, "Biometrics must be available on iPhone 17 Pro Max")
    }

    // MARK: - C7.2: Authentication Manager — Mode Preference Persistence

    func test_currentMode_defaultIsStandard() {
        let testDefaults = UserDefaults(suiteName: "com.cypherair.test")!
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: testDefaults
        )
        XCTAssertEqual(authManager.currentMode, .standard, "Default mode must be standard")
        testDefaults.removePersistentDomain(forName: "com.cypherair.test")
    }

    func test_gracePeriod_defaultIs180() {
        let testDefaults = UserDefaults(suiteName: "com.cypherair.test")!
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: testDefaults
        )
        XCTAssertEqual(authManager.gracePeriod, 180, "Default grace period must be 180 seconds")
        testDefaults.removePersistentDomain(forName: "com.cypherair.test")
    }

    // MARK: - C7.3: Crash Recovery

    func test_crashRecovery_oldAndPendingExist_cleansPendingKeepsOld() throws {
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        // Simulate: old items exist (the original keys).
        let oldData = Data("original-se-key".utf8)
        try keychain.save(oldData, service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(Data("old-salt".utf8), service: KeychainConstants.saltService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(Data("old-sealed".utf8), service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        // Simulate: pending items also exist (partially completed re-wrap).
        try keychain.save(Data("pending-se-key".utf8), service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(Data("pending-salt".utf8), service: KeychainConstants.pendingSaltService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(Data("pending-sealed".utf8), service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        // Set the crash recovery flag.
        UserDefaults.standard.set(true, forKey: AuthPreferences.rewrapInProgressKey)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        // Verify: flag cleared.
        XCTAssertFalse(
            UserDefaults.standard.bool(forKey: AuthPreferences.rewrapInProgressKey),
            "rewrapInProgress flag must be cleared"
        )

        // Verify: old items still intact.
        let loadedOld = try keychain.load(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account)
        XCTAssertEqual(loadedOld, oldData, "Original SE key must be intact after crash recovery")

        // Verify: pending items removed.
        XCTAssertFalse(
            keychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account),
            "Pending items must be cleaned up"
        )
    }

    func test_crashRecovery_onlyPendingExist_promotesToPermanent() throws {
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        // Simulate: old items deleted, only pending items remain.
        let pendingSEKey = Data("promoted-se-key".utf8)
        let pendingSalt = Data("promoted-salt".utf8)
        let pendingSealed = Data("promoted-sealed".utf8)
        try keychain.save(pendingSEKey, service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(pendingSalt, service: KeychainConstants.pendingSaltService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(pendingSealed, service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        UserDefaults.standard.set(true, forKey: AuthPreferences.rewrapInProgressKey)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        // Verify: flag cleared.
        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.rewrapInProgressKey))

        // Verify: items promoted to permanent names.
        let loadedSEKey = try keychain.load(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account)
        XCTAssertEqual(loadedSEKey, pendingSEKey, "Pending SE key must be promoted to permanent")

        let loadedSalt = try keychain.load(service: KeychainConstants.saltService(fingerprint: fingerprint), account: account)
        XCTAssertEqual(loadedSalt, pendingSalt)

        let loadedSealed = try keychain.load(service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account)
        XCTAssertEqual(loadedSealed, pendingSealed)

        // Verify: pending items removed.
        XCTAssertFalse(keychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account))
    }

    func test_crashRecovery_noFlag_doesNothing() throws {
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        // No flag set, but pending items exist (should be left alone).
        try keychain.save(Data("stale".utf8), service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        UserDefaults.standard.removeObject(forKey: AuthPreferences.rewrapInProgressKey)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        // Pending items should still be there (recovery did not run).
        XCTAssertTrue(keychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account))
    }

    // MARK: - C7.4: Mode Switch with Mock SE (Logic Test)

    func test_switchMode_noIdentities_throwsNoIdentities() async throws {
        let mockAuth = MockAuthenticator()
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )

        do {
            try await authManager.switchMode(to: .highSecurity, fingerprints: [], hasBackup: true, authenticator: mockAuth)
            XCTFail("Should have thrown noIdentities error")
        } catch let error as AuthenticationError {
            if case .noIdentities = error {
                // Expected
            } else {
                XCTFail("Expected .noIdentities, got \(error)")
            }
        }
    }

    func test_switchMode_sameMode_isNoop() async throws {
        let testDefaults = UserDefaults(suiteName: "com.cypherair.test")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.test") }

        testDefaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: testDefaults
        )

        // Switching to the same mode should return immediately without error.
        let mockAuth = MockAuthenticator()
        try await authManager.switchMode(to: .standard, fingerprints: ["abc123"], hasBackup: true, authenticator: mockAuth)
    }

    // MARK: - C7.5: Full Mode Switch on Device (SE + Keychain)

    func test_switchMode_standardToHighSecurity_fullStack() async throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0x77, count: 32)

        let testDefaults = UserDefaults(suiteName: "com.cypherair.test")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.test") }
        testDefaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)

        // 1. Initial wrap under Standard mode (no access control for test simplicity).
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        // Store in Keychain as permanent items.
        try keychain.save(bundle.seKeyData, service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(bundle.salt, service: KeychainConstants.saltService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(bundle.sealedBox, service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        // 2. Switch mode.
        // Brief pause to let any prior SE authentication session settle,
        // preventing "Canceled by another authentication" from overlapping requests.
        try await Task.sleep(for: .seconds(2))

        let mockAuth = MockAuthenticator()
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: testDefaults
        )
        try await authManager.switchMode(to: .highSecurity, fingerprints: [fingerprint], hasBackup: true, authenticator: mockAuth)

        // 3. Verify: mode persisted.
        XCTAssertEqual(
            testDefaults.string(forKey: AuthPreferences.authModeKey),
            AuthenticationMode.highSecurity.rawValue
        )

        // 4. Verify: rewrap flag cleared.
        XCTAssertFalse(testDefaults.bool(forKey: AuthPreferences.rewrapInProgressKey))

        // 5. Verify: can still unwrap the key with new items.
        let newSEKeyData = try keychain.load(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account)
        let newSalt = try keychain.load(service: KeychainConstants.saltService(fingerprint: fingerprint), account: account)
        let newSealed = try keychain.load(service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account)

        let newHandle = try secureEnclave.reconstructKey(from: newSEKeyData)
        let newBundle = WrappedKeyBundle(seKeyData: newSEKeyData, salt: newSalt, sealedBox: newSealed)
        let unwrapped = try secureEnclave.unwrap(bundle: newBundle, using: newHandle, fingerprint: fingerprint)

        XCTAssertEqual(unwrapped, fakePrivateKey, "Key must be accessible after mode switch")

        // 6. Verify: no pending items left.
        XCTAssertFalse(keychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account))
    }

    // MARK: - C7.6: Mode Switch Rollback on Failure (Mock-based)

    /// Verifies that when a Keychain save fails mid-way through mode switch,
    /// the original keys remain intact and all temporary items are cleaned up.
    /// Uses MockKeychain + MockSecureEnclave so this can also run in the simulator.
    func test_switchMode_keychainSaveFailsMidway_rollsBackAndKeepsOriginalKeys() async throws {
        let mockKeychain = MockKeychain()
        let mockSE = MockSecureEnclave()
        let mockAuth = MockAuthenticator()

        let testDefaults = UserDefaults(suiteName: "com.cypherair.test.rollback")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.test.rollback") }
        testDefaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)

        let fp1 = uniqueFingerprint()
        let fp2 = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        let fakeKey1 = Data(repeating: 0xAA, count: 32)
        let fakeKey2 = Data(repeating: 0xBB, count: 57)

        // Wrap and store keys for both fingerprints.
        let handle1 = try mockSE.generateWrappingKey(accessControl: nil)
        let bundle1 = try mockSE.wrap(privateKey: fakeKey1, using: handle1, fingerprint: fp1)
        try mockKeychain.save(bundle1.seKeyData, service: KeychainConstants.seKeyService(fingerprint: fp1), account: account, accessControl: nil)
        try mockKeychain.save(bundle1.salt, service: KeychainConstants.saltService(fingerprint: fp1), account: account, accessControl: nil)
        try mockKeychain.save(bundle1.sealedBox, service: KeychainConstants.sealedKeyService(fingerprint: fp1), account: account, accessControl: nil)

        let handle2 = try mockSE.generateWrappingKey(accessControl: nil)
        let bundle2 = try mockSE.wrap(privateKey: fakeKey2, using: handle2, fingerprint: fp2)
        try mockKeychain.save(bundle2.seKeyData, service: KeychainConstants.seKeyService(fingerprint: fp2), account: account, accessControl: nil)
        try mockKeychain.save(bundle2.salt, service: KeychainConstants.saltService(fingerprint: fp2), account: account, accessControl: nil)
        try mockKeychain.save(bundle2.sealedBox, service: KeychainConstants.sealedKeyService(fingerprint: fp2), account: account, accessControl: nil)

        // 6 saves so far. Next saves are pending items during switchMode.
        // Fail on the 10th save (the 4th pending item save, i.e., first save of fp2's pending items).
        // This means fp1's 3 pending items succeed, but fp2's first pending save fails.
        mockKeychain.failOnSaveNumber = 10

        let authManager = AuthenticationManager(
            secureEnclave: mockSE,
            keychain: mockKeychain,
            defaults: testDefaults
        )

        // Attempt mode switch — should fail and roll back.
        do {
            try await authManager.switchMode(
                to: .highSecurity,
                fingerprints: [fp1, fp2],
                hasBackup: true,
                authenticator: mockAuth
            )
            XCTFail("switchMode should have thrown due to Keychain save failure")
        } catch let error as AuthenticationError {
            if case .modeSwitchFailed = error {
                // Expected
            } else {
                XCTFail("Expected .modeSwitchFailed, got \(error)")
            }
        }

        // Verify: original keys for BOTH fingerprints are still intact.
        let loaded1 = try mockKeychain.load(service: KeychainConstants.seKeyService(fingerprint: fp1), account: account)
        XCTAssertEqual(loaded1, bundle1.seKeyData, "Original SE key for fp1 must be intact after rollback")

        let loaded2 = try mockKeychain.load(service: KeychainConstants.seKeyService(fingerprint: fp2), account: account)
        XCTAssertEqual(loaded2, bundle2.seKeyData, "Original SE key for fp2 must be intact after rollback")

        // Verify: NO pending items remain for either fingerprint.
        XCTAssertFalse(mockKeychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fp1), account: account),
                       "Pending items for fp1 must be cleaned up after rollback")
        XCTAssertFalse(mockKeychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fp2), account: account),
                       "Pending items for fp2 must be cleaned up after rollback")

        // Verify: rewrap flag is cleared.
        XCTAssertFalse(testDefaults.bool(forKey: AuthPreferences.rewrapInProgressKey),
                       "rewrapInProgress flag must be cleared after rollback")

        // Verify: mode did NOT change.
        XCTAssertEqual(testDefaults.string(forKey: AuthPreferences.authModeKey),
                       AuthenticationMode.standard.rawValue,
                       "Mode must remain standard after failed switch")
    }

    /// Verifies that switchMode fails when the authenticator rejects the user.
    func test_switchMode_authenticationFails_throwsError() async throws {
        let mockKeychain = MockKeychain()
        let mockSE = MockSecureEnclave()
        let mockAuth = MockAuthenticator()
        mockAuth.shouldSucceed = false

        let testDefaults = UserDefaults(suiteName: "com.cypherair.test.authfail")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.test.authfail") }
        testDefaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)

        let fp = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        // Set up a key so we have a valid fingerprint.
        let handle = try mockSE.generateWrappingKey(accessControl: nil)
        let bundle = try mockSE.wrap(privateKey: Data(repeating: 0xCC, count: 32), using: handle, fingerprint: fp)
        try mockKeychain.save(bundle.seKeyData, service: KeychainConstants.seKeyService(fingerprint: fp), account: account, accessControl: nil)
        try mockKeychain.save(bundle.salt, service: KeychainConstants.saltService(fingerprint: fp), account: account, accessControl: nil)
        try mockKeychain.save(bundle.sealedBox, service: KeychainConstants.sealedKeyService(fingerprint: fp), account: account, accessControl: nil)

        let authManager = AuthenticationManager(
            secureEnclave: mockSE,
            keychain: mockKeychain,
            defaults: testDefaults
        )

        // Authentication should fail, so switchMode should throw before touching any keys.
        do {
            try await authManager.switchMode(
                to: .highSecurity,
                fingerprints: [fp],
                hasBackup: true,
                authenticator: mockAuth
            )
            XCTFail("switchMode should have thrown due to authentication failure")
        } catch {
            // Expected — authentication failed before any Keychain modification.
        }

        // Verify: original keys untouched, no pending items, no rewrap flag.
        XCTAssertTrue(mockKeychain.exists(service: KeychainConstants.seKeyService(fingerprint: fp), account: account),
                      "Original key must be untouched when auth fails")
        XCTAssertFalse(mockKeychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fp), account: account),
                       "No pending items should exist when auth fails")
        XCTAssertFalse(testDefaults.bool(forKey: AuthPreferences.rewrapInProgressKey),
                       "rewrapInProgress flag must not be set when auth fails")
    }

    // MARK: - C8.1: MIE Smoke Tests (SE Wrap/Unwrap)

    func test_mie_singleWrapUnwrapCycle_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        var keyData = Data(count: 32)
        let status = keyData.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        XCTAssertEqual(status, errSecSuccess)

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(privateKey: keyData, using: handle, fingerprint: fingerprint)
        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)

        XCTAssertEqual(unwrapped, keyData, "MIE smoke: wrap/unwrap must succeed without tag mismatch")
    }

    func test_mie_50xRapidWrapUnwrap_noIntermittentCrashes() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        for i in 0..<50 {
            let fingerprint = uniqueFingerprint()
            // Alternate between Ed25519 (32 bytes) and Ed448 (57 bytes) sizes.
            let size = (i % 2 == 0) ? 32 : 57
            var keyData = Data(count: size)
            let status = keyData.withUnsafeMutableBytes { ptr in
                SecRandomCopyBytes(kSecRandomDefault, size, ptr.baseAddress!)
            }
            XCTAssertEqual(status, errSecSuccess, "Iteration \(i): SecRandom failed")

            let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
            let bundle = try secureEnclave.wrap(privateKey: keyData, using: handle, fingerprint: fingerprint)
            let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)

            XCTAssertEqual(unwrapped, keyData, "Iteration \(i): wrap/unwrap mismatch")
        }
    }

    // MARK: - C8.2: Full PGP Workflow Under MIE (Both Profiles)

    /// C8.2: Complete Profile A (v4, Ed25519+X25519, SEIPDv1) workflow on device.
    /// Exercises OpenSSL: AES-256, X25519 key agreement, Ed25519 signing, SHA-512 hashing.
    /// Pass: all operations complete without EXC_GUARD / GUARD_EXC_MTE_SYNC_FAULT.
    func test_mie_fullPGPWorkflow_profileA_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let plaintext = Data("C8.2 Profile A MIE: full workflow — 你好世界 🔐".utf8)

        // 1. Key generation (Ed25519+X25519, v4).
        let key = try engine.generateKey(
            name: "C8.2 MIE Test A", email: "mie-a@test.local",
            expirySeconds: nil, profile: .universal
        )
        XCTAssertFalse(key.certData.isEmpty, "Profile A key generation must succeed")
        XCTAssertFalse(key.fingerprint.isEmpty, "Profile A fingerprint must not be empty")

        // 2. Encrypt with signing (AES-256 via SEIPDv1, X25519 key agreement).
        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [key.publicKeyData],
            signingKey: key.certData,
            encryptToSelf: nil
        )
        XCTAssertFalse(ciphertext.isEmpty, "Profile A ciphertext must not be empty")

        // 3. Decrypt (AES-256 decryption, Ed25519 signature verification).
        let decrypted = try engine.decrypt(
            ciphertext: ciphertext,
            secretKeys: [key.certData],
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(decrypted.plaintext, plaintext,
            "Profile A decrypted plaintext must match original")
        XCTAssertEqual(decrypted.signatureStatus, .valid,
            "Profile A signature must verify")

        // 4. Cleartext sign (Ed25519 + SHA-512).
        let signed = try engine.signCleartext(
            text: plaintext, signerCert: key.certData
        )
        XCTAssertFalse(signed.isEmpty, "Cleartext signature must not be empty")

        // 5. Verify cleartext signature.
        let verifyResult = try engine.verifyCleartext(
            signedMessage: signed,
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(verifyResult.status, .valid,
            "Profile A cleartext signature must verify")

        // 6. Detached sign.
        let detachedSig = try engine.signDetached(
            data: plaintext, signerCert: key.certData
        )
        XCTAssertFalse(detachedSig.isEmpty, "Detached signature must not be empty")

        // 7. Verify detached signature.
        let detachedVerify = try engine.verifyDetached(
            data: plaintext,
            signature: detachedSig,
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(detachedVerify.status, .valid,
            "Profile A detached signature must verify")
    }

    /// C8.2: Complete Profile B (v6, Ed448+X448, SEIPDv2 AEAD OCB) workflow on device.
    /// Exercises OpenSSL: AES-256-OCB AEAD, X448 key agreement, Ed448 signing, SHA-512.
    /// Pass: all operations complete without tag mismatch crashes.
    func test_mie_fullPGPWorkflow_profileB_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let plaintext = Data("C8.2 Profile B MIE: full workflow — AEAD OCB 🛡️".utf8)

        // 1. Key generation (Ed448+X448, v6).
        let key = try engine.generateKey(
            name: "C8.2 MIE Test B", email: "mie-b@test.local",
            expirySeconds: nil, profile: .advanced
        )
        XCTAssertFalse(key.certData.isEmpty, "Profile B key generation must succeed")

        // 2. Encrypt with signing (AES-256-OCB AEAD via SEIPDv2, X448).
        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [key.publicKeyData],
            signingKey: key.certData,
            encryptToSelf: nil
        )
        XCTAssertFalse(ciphertext.isEmpty, "Profile B ciphertext must not be empty")

        // 3. Decrypt (AEAD OCB decryption, Ed448 signature verification).
        let decrypted = try engine.decrypt(
            ciphertext: ciphertext,
            secretKeys: [key.certData],
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(decrypted.plaintext, plaintext,
            "Profile B decrypted plaintext must match original")
        XCTAssertEqual(decrypted.signatureStatus, .valid,
            "Profile B signature must verify")

        // 4. Cleartext sign (Ed448 + SHA-512).
        let signed = try engine.signCleartext(
            text: plaintext, signerCert: key.certData
        )
        XCTAssertFalse(signed.isEmpty, "Profile B cleartext signature must not be empty")

        // 5. Verify cleartext signature.
        let verifyResult = try engine.verifyCleartext(
            signedMessage: signed,
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(verifyResult.status, .valid,
            "Profile B cleartext signature must verify")

        // 6. Detached sign.
        let detachedSig = try engine.signDetached(
            data: plaintext, signerCert: key.certData
        )
        XCTAssertFalse(detachedSig.isEmpty, "Profile B detached signature must not be empty")

        // 7. Verify detached signature.
        let detachedVerify = try engine.verifyDetached(
            data: plaintext,
            signature: detachedSig,
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(detachedVerify.status, .valid,
            "Profile B detached signature must verify")
    }

    /// C8.2: Cross-profile encryption format auto-selection under MIE.
    /// Tests: B→A (SEIPDv1), A→B (SEIPDv2), mixed A+B recipients (SEIPDv1).
    func test_mie_crossProfileEncrypt_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let plaintext = Data("C8.2 Cross-profile MIE test".utf8)

        let keyA = try engine.generateKey(
            name: "Cross A", email: nil, expirySeconds: nil, profile: .universal
        )
        let keyB = try engine.generateKey(
            name: "Cross B", email: nil, expirySeconds: nil, profile: .advanced
        )

        // B sender → A recipient: should auto-select SEIPDv1.
        let ciphertextBA = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData],
            signingKey: keyB.certData,
            encryptToSelf: nil
        )
        let resultBA = try engine.decrypt(
            ciphertext: ciphertextBA,
            secretKeys: [keyA.certData],
            verificationKeys: [keyB.publicKeyData]
        )
        XCTAssertEqual(resultBA.plaintext, plaintext, "B→A decrypt must succeed")
        XCTAssertEqual(resultBA.signatureStatus, .valid, "B→A signature must verify")

        // A sender → B recipient: should auto-select SEIPDv2.
        let ciphertextAB = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyB.publicKeyData],
            signingKey: keyA.certData,
            encryptToSelf: nil
        )
        let resultAB = try engine.decrypt(
            ciphertext: ciphertextAB,
            secretKeys: [keyB.certData],
            verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(resultAB.plaintext, plaintext, "A→B decrypt must succeed")
        XCTAssertEqual(resultAB.signatureStatus, .valid, "A→B signature must verify")

        // Mixed recipients (A + B): should produce SEIPDv1.
        let ciphertextMixed = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData, keyB.publicKeyData],
            signingKey: keyA.certData,
            encryptToSelf: nil
        )
        // Both recipients must be able to decrypt.
        let resultMixedA = try engine.decrypt(
            ciphertext: ciphertextMixed,
            secretKeys: [keyA.certData],
            verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(resultMixedA.plaintext, plaintext, "Mixed→A decrypt must succeed")

        let resultMixedB = try engine.decrypt(
            ciphertext: ciphertextMixed,
            secretKeys: [keyB.certData],
            verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(resultMixedB.plaintext, plaintext, "Mixed→B decrypt must succeed")
    }

    /// C8.2: Key export/import round-trip under MIE.
    /// Profile A: Iterated+Salted S2K. Profile B: Argon2id S2K (512 MB).
    func test_mie_keyExportImport_bothProfiles_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let passphrase = "mie-export-test-passphrase"
        let plaintext = Data("C8.2 export/import round-trip test".utf8)

        // Profile A: export with Iterated+Salted S2K, then import.
        let keyA = try engine.generateKey(
            name: "Export A", email: nil, expirySeconds: nil, profile: .universal
        )
        let ciphertextA = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let exportedA = try engine.exportSecretKey(
            certData: keyA.certData, passphrase: passphrase, profile: .universal
        )
        XCTAssertFalse(exportedA.isEmpty, "Profile A export must produce data")

        let importedA = try engine.importSecretKey(
            armoredData: exportedA, passphrase: passphrase
        )
        XCTAssertFalse(importedA.isEmpty, "Profile A import must succeed")

        // Decrypt with the imported key to verify round-trip.
        let decryptedA = try engine.decrypt(
            ciphertext: ciphertextA,
            secretKeys: [importedA],
            verificationKeys: []
        )
        XCTAssertEqual(decryptedA.plaintext, plaintext,
            "Profile A: imported key must decrypt correctly")

        // Profile B: export with Argon2id S2K, then import.
        let keyB = try engine.generateKey(
            name: "Export B", email: nil, expirySeconds: nil, profile: .advanced
        )
        let ciphertextB = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyB.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let exportedB = try engine.exportSecretKey(
            certData: keyB.certData, passphrase: passphrase, profile: .advanced
        )
        XCTAssertFalse(exportedB.isEmpty, "Profile B export must produce data")

        let importedB = try engine.importSecretKey(
            armoredData: exportedB, passphrase: passphrase
        )
        XCTAssertFalse(importedB.isEmpty, "Profile B import must succeed")

        let decryptedB = try engine.decrypt(
            ciphertext: ciphertextB,
            secretKeys: [importedB],
            verificationKeys: []
        )
        XCTAssertEqual(decryptedB.plaintext, plaintext,
            "Profile B: imported key must decrypt correctly")
    }

    // MARK: - C8.3: OpenSSL Crypto Operations Under MIE

    /// C8.3: Explicitly exercise every OpenSSL code path used by Sequoia.
    /// Covers: AES-256, SHA-512, Ed25519, X25519, Ed448, X448, AES-256-OCB AEAD, Argon2id.
    /// Pass: all crypto operations succeed with no memory tagging violations.
    func test_mie_opensslCryptoPaths_allAlgorithms_noTagViolations() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let plaintext = Data("C8.3 OpenSSL paths MIE validation".utf8)

        // --- Generate keys for both profiles ---
        let keyA = try engine.generateKey(
            name: "OpenSSL A", email: nil, expirySeconds: nil, profile: .universal
        )
        let keyB = try engine.generateKey(
            name: "OpenSSL B", email: nil, expirySeconds: nil, profile: .advanced
        )

        // 1. AES-256 via SEIPDv1 (Profile A encrypt + decrypt).
        //    OpenSSL path: AES-256-CFB encryption + MDC (SHA-1 hash).
        let ciphertextA = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let resultA = try engine.decrypt(
            ciphertext: ciphertextA,
            secretKeys: [keyA.certData],
            verificationKeys: []
        )
        XCTAssertEqual(resultA.plaintext, plaintext, "AES-256 SEIPDv1 round-trip failed")

        // 2. SHA-512 via signing (both profiles).
        //    OpenSSL path: SHA-512 hash for signature computation.
        let signedA = try engine.signCleartext(text: plaintext, signerCert: keyA.certData)
        let verifyA = try engine.verifyCleartext(
            signedMessage: signedA, verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(verifyA.status, .valid, "SHA-512 + Ed25519 sign/verify failed")

        let signedB = try engine.signCleartext(text: plaintext, signerCert: keyB.certData)
        let verifyB = try engine.verifyCleartext(
            signedMessage: signedB, verificationKeys: [keyB.publicKeyData]
        )
        XCTAssertEqual(verifyB.status, .valid, "SHA-512 + Ed448 sign/verify failed")

        // 3. Ed25519 via Profile A sign + verify (covered above in step 2).

        // 4. X25519 via Profile A encrypt (covered above in step 1).
        //    OpenSSL path: X25519 ECDH key agreement for session key.

        // 5. Ed448 via Profile B sign + verify (covered above in step 2).

        // 6. X448 via Profile B encrypt.
        //    OpenSSL path: X448 ECDH key agreement for session key.
        let ciphertextB = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyB.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let resultB = try engine.decrypt(
            ciphertext: ciphertextB,
            secretKeys: [keyB.certData],
            verificationKeys: []
        )
        XCTAssertEqual(resultB.plaintext, plaintext, "AES-256-OCB AEAD + X448 round-trip failed")

        // 7. AES-256-OCB AEAD via SEIPDv2 (Profile B, covered above in step 6).

        // 8. Argon2id via Profile B key export.
        //    OpenSSL path: Argon2id KDF (512 MB memory, 4 lanes).
        let exported = try engine.exportSecretKey(
            certData: keyB.certData, passphrase: "openssltest", profile: .advanced
        )
        XCTAssertFalse(exported.isEmpty, "Argon2id S2K export must succeed")

        let imported = try engine.importSecretKey(
            armoredData: exported, passphrase: "openssltest"
        )
        XCTAssertFalse(imported.isEmpty, "Argon2id S2K import must succeed")

        // 9. Detached signatures (exercises Ed25519/Ed448 + SHA-512 in detached mode).
        let detSigA = try engine.signDetached(data: plaintext, signerCert: keyA.certData)
        let detVerifyA = try engine.verifyDetached(
            data: plaintext, signature: detSigA, verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(detVerifyA.status, .valid, "Ed25519 detached sign/verify failed")

        let detSigB = try engine.signDetached(data: plaintext, signerCert: keyB.certData)
        let detVerifyB = try engine.verifyDetached(
            data: plaintext, signature: detSigB, verificationKeys: [keyB.publicKeyData]
        )
        XCTAssertEqual(detVerifyB.status, .valid, "Ed448 detached sign/verify failed")
    }

    /// C8.3: Armor/dearmor exercises OpenSSL Base64 and binary parsing paths.
    func test_mie_armorDearmor_bothProfiles_noTagViolations() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()

        let keyA = try engine.generateKey(
            name: "Armor A", email: nil, expirySeconds: nil, profile: .universal
        )
        let keyB = try engine.generateKey(
            name: "Armor B", email: nil, expirySeconds: nil, profile: .advanced
        )

        // Armor public keys and round-trip.
        let armoredA = try engine.armorPublicKey(certData: keyA.publicKeyData)
        XCTAssertFalse(armoredA.isEmpty, "Profile A armored public key must not be empty")
        let dearmoredA = try engine.dearmor(armored: armoredA)
        XCTAssertEqual(dearmoredA, keyA.publicKeyData,
            "Profile A armor/dearmor must round-trip")

        let armoredB = try engine.armorPublicKey(certData: keyB.publicKeyData)
        XCTAssertFalse(armoredB.isEmpty, "Profile B armored public key must not be empty")
        let dearmoredB = try engine.dearmor(armored: armoredB)
        XCTAssertEqual(dearmoredB, keyB.publicKeyData,
            "Profile B armor/dearmor must round-trip")

        // Armor ciphertext and round-trip decrypt.
        let plaintext = Data("Armor round-trip test".utf8)
        let binaryCiphertext = try engine.encryptBinary(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let armoredMsg = try engine.armor(data: binaryCiphertext, kind: .message)
        XCTAssertFalse(armoredMsg.isEmpty, "Armored message must not be empty")
        let dearmoredMsg = try engine.dearmor(armored: armoredMsg)
        XCTAssertEqual(dearmoredMsg, binaryCiphertext,
            "Message armor/dearmor must preserve binary content")
    }

    // MARK: - C8.4: 100× Encrypt/Decrypt Cycles Under MIE

    /// C8.4: 100 encrypt/decrypt cycles for Profile A (SEIPDv1) under MIE.
    /// Detects intermittent tag mismatches that single-cycle tests might miss.
    /// Monitor: `log stream --predicate 'eventMessage contains "MTE"'`
    /// Pass: zero tag violations across 100 cycles.
    func test_mie_100xEncryptDecryptCycles_profileA_noIntermittentCrashes() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "100x A", email: nil, expirySeconds: nil, profile: .universal
        )

        for i in 0..<100 {
            let plaintext = Data("C8.4 Profile A iteration \(i) — \(UUID().uuidString)".utf8)

            let ciphertext = try engine.encrypt(
                plaintext: plaintext,
                recipients: [key.publicKeyData],
                signingKey: key.certData,
                encryptToSelf: nil
            )

            let result = try engine.decrypt(
                ciphertext: ciphertext,
                secretKeys: [key.certData],
                verificationKeys: [key.publicKeyData]
            )

            XCTAssertEqual(result.plaintext, plaintext,
                "Profile A iteration \(i): plaintext mismatch")
            XCTAssertEqual(result.signatureStatus, .valid,
                "Profile A iteration \(i): signature invalid")
        }
    }

    /// C8.4: 100 encrypt/decrypt cycles for Profile B (SEIPDv2 AEAD OCB) under MIE.
    /// Exercises OpenSSL AES-256-OCB + X448 + Ed448 100 times.
    /// Pass: zero tag violations across 100 cycles.
    func test_mie_100xEncryptDecryptCycles_profileB_noIntermittentCrashes() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "100x B", email: nil, expirySeconds: nil, profile: .advanced
        )

        for i in 0..<100 {
            let plaintext = Data("C8.4 Profile B iteration \(i) — \(UUID().uuidString)".utf8)

            let ciphertext = try engine.encrypt(
                plaintext: plaintext,
                recipients: [key.publicKeyData],
                signingKey: key.certData,
                encryptToSelf: nil
            )

            let result = try engine.decrypt(
                ciphertext: ciphertext,
                secretKeys: [key.certData],
                verificationKeys: [key.publicKeyData]
            )

            XCTAssertEqual(result.plaintext, plaintext,
                "Profile B iteration \(i): plaintext mismatch")
            XCTAssertEqual(result.signatureStatus, .valid,
                "Profile B iteration \(i): signature invalid")
        }
    }

    /// C8.4: 100 sign/verify cycles for both profiles under MIE.
    /// Exercises Ed25519 + Ed448 + SHA-512 hashing 200 times total.
    /// Pass: zero tag violations across all cycles.
    func test_mie_100xSignVerifyCycles_bothProfiles_noIntermittentCrashes() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let keyA = try engine.generateKey(
            name: "100x Sign A", email: nil, expirySeconds: nil, profile: .universal
        )
        let keyB = try engine.generateKey(
            name: "100x Sign B", email: nil, expirySeconds: nil, profile: .advanced
        )

        for i in 0..<100 {
            let text = Data("C8.4 sign/verify iteration \(i) — \(UUID().uuidString)".utf8)

            // Profile A: Ed25519 cleartext sign + verify.
            let signedA = try engine.signCleartext(text: text, signerCert: keyA.certData)
            let verifyA = try engine.verifyCleartext(
                signedMessage: signedA, verificationKeys: [keyA.publicKeyData]
            )
            XCTAssertEqual(verifyA.status, .valid,
                "Profile A sign/verify iteration \(i) failed")

            // Profile B: Ed448 cleartext sign + verify.
            let signedB = try engine.signCleartext(text: text, signerCert: keyB.certData)
            let verifyB = try engine.verifyCleartext(
                signedMessage: signedB, verificationKeys: [keyB.publicKeyData]
            )
            XCTAssertEqual(verifyB.status, .valid,
                "Profile B sign/verify iteration \(i) failed")
        }
    }

    // MARK: - C4.5: Argon2id Memory Guard (Device)

    /// C4.5: Verify SystemMemoryInfo returns a sane value on real hardware.
    func test_systemMemoryInfo_returnsNonZero() {
        let memoryInfo = SystemMemoryInfo()
        let available = memoryInfo.availableMemoryBytes()

        // On an 8 GB+ device, available memory should be at least 500 MB.
        XCTAssertGreaterThan(available, 500 * 1024 * 1024,
            "os_proc_available_memory must return > 500 MB on 8 GB+ device")

        // And less than total physical memory (sanity check).
        let totalPhysical = ProcessInfo.processInfo.physicalMemory
        XCTAssertLessThanOrEqual(available, totalPhysical,
            "Available memory must not exceed physical memory")
    }

    /// C4.5: Real 512 MB Argon2id import with guard on device.
    /// Validates the full pipeline: parseS2kParams → guard → importSecretKey.
    func test_argon2idGuard_realDevice_512MB_import_succeeds() throws {
        let engine = PgpEngine()

        // Generate and export a Profile B key.
        let key = try engine.generateKey(
            name: "Device Argon2id", email: nil, expirySeconds: nil, profile: .advanced
        )
        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "device-test-pass",
            profile: .advanced
        )

        // Parse S2K params and run the guard with real memory info.
        let s2kInfo = try engine.parseS2kParams(armoredData: exported)
        let memoryGuard = Argon2idMemoryGuard() // Uses SystemMemoryInfo (real)

        // On an 8 GB+ device, 512 MB should be well within limits.
        XCTAssertNoThrow(try memoryGuard.validate(s2kInfo: s2kInfo))

        // If the guard passes, proceed with actual import.
        let imported = try engine.importSecretKey(
            armoredData: exported,
            passphrase: "device-test-pass"
        )
        XCTAssertFalse(imported.isEmpty, "Imported key data must not be empty")
    }

    // MARK: - C10: Performance Benchmarks

    /// C10.1: Text encryption latency (1 KB) — Profile A (Ed25519+X25519, SEIPDv1).
    /// Threshold: < 50ms. Soft-fail: record and document.
    func test_perf_textEncrypt1KB_profileA_latencyUnder50ms() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.1 A", email: nil, expirySeconds: nil, profile: .universal
        )
        let plaintext = Data(repeating: 0x41, count: 1024) // 1 KB

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.encrypt(
                plaintext: plaintext,
                recipients: [key.publicKeyData],
                signingKey: key.certData,
                encryptToSelf: nil
            )
        }
    }

    /// C10.1: Text encryption latency (1 KB) — Profile B (Ed448+X448, SEIPDv2 AEAD OCB).
    /// Threshold: < 50ms. Soft-fail: record and document.
    func test_perf_textEncrypt1KB_profileB_latencyUnder50ms() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.1 B", email: nil, expirySeconds: nil, profile: .advanced
        )
        let plaintext = Data(repeating: 0x41, count: 1024) // 1 KB

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.encrypt(
                plaintext: plaintext,
                recipients: [key.publicKeyData],
                signingKey: key.certData,
                encryptToSelf: nil
            )
        }
    }

    /// C10.2: 100 MB file encryption — Profile A (X25519, SEIPDv1).
    /// Threshold: < 10s. Soft-fail: record and document.
    /// Uses encryptBinary() (.gpg format) — matches real file encryption workflow.
    func test_perf_fileEncrypt100MB_profileA_latencyUnder10s() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.2", email: nil, expirySeconds: nil, profile: .universal
        )
        let fileData = Data(count: 100 * 1024 * 1024) // 100 MB zero-filled

        let options = XCTMeasureOptions()
        options.iterationCount = 3

        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()], options: options) {
            _ = try! engine.encryptBinary(
                plaintext: fileData,
                recipients: [key.publicKeyData],
                signingKey: nil,
                encryptToSelf: nil
            )
        }
    }

    /// C10.3: 100 MB file encryption — Profile B (X448, SEIPDv2 AEAD OCB).
    /// Threshold: < 15s. Soft-fail: record and document.
    /// Uses encryptBinary() (.gpg format) — matches real file encryption workflow.
    func test_perf_fileEncrypt100MB_profileB_latencyUnder15s() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.3", email: nil, expirySeconds: nil, profile: .advanced
        )
        let fileData = Data(count: 100 * 1024 * 1024) // 100 MB zero-filled

        let options = XCTMeasureOptions()
        options.iterationCount = 3

        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()], options: options) {
            _ = try! engine.encryptBinary(
                plaintext: fileData,
                recipients: [key.publicKeyData],
                signingKey: nil,
                encryptToSelf: nil
            )
        }
    }

    /// C10.4: Key generation latency — Profile A (Ed25519+X25519).
    /// No hard threshold. Record value.
    func test_perf_keyGeneration_profileA_recordLatency() throws {
        let engine = PgpEngine()

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.generateKey(
                name: "Perf C10.4", email: nil, expirySeconds: nil, profile: .universal
            )
        }
    }

    /// C10.5: Key generation latency — Profile B (Ed448+X448).
    /// No hard threshold. Record value.
    /// Note: Ed448 key generation is expected to be significantly slower than Ed25519.
    func test_perf_keyGeneration_profileB_recordLatency() throws {
        let engine = PgpEngine()

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.generateKey(
                name: "Perf C10.5", email: nil, expirySeconds: nil, profile: .advanced
            )
        }
    }

    /// C10.6: SE key reconstruction from dataRepresentation.
    /// Threshold: < 10ms. ARCHITECTURE.md documents 2–5ms.
    func test_perf_seKeyReconstruction_latencyUnder10ms() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        // Generate SE key and extract its dataRepresentation for reconstruction.
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let keyData = handle.dataRepresentation

        let options = XCTMeasureOptions()
        options.iterationCount = 20

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! secureEnclave.reconstructKey(from: keyData)
        }
    }

    /// C10.7: SE wrap/unwrap end-to-end (excluding biometric prompt).
    /// Threshold: < 100ms. Soft-fail: record and document.
    /// Measures: SE P-256 key gen + self-ECDH + HKDF + AES-GCM seal + unwrap cycle.
    func test_perf_seWrapUnwrap_endToEnd_latencyUnder100ms() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fakePrivateKey = Data(repeating: 0xAB, count: 57) // Ed448 size (worst case)
        let fingerprint = uniqueFingerprint()

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            let handle = try! secureEnclave.generateWrappingKey(accessControl: nil)
            let bundle = try! secureEnclave.wrap(
                privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint
            )
            let unwrapped = try! secureEnclave.unwrap(
                bundle: bundle, using: handle, fingerprint: fingerprint
            )
            assert(unwrapped == fakePrivateKey)
        }
    }

    /// C10.8: Argon2id calibration time (512 MB / p=4).
    /// Target: ~3s. Soft-fail: record actual value.
    /// Measures exportSecretKey with Profile B, which triggers Argon2id S2K.
    func test_perf_argon2id_512MB_calibrationTime_target3s() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.8", email: nil, expirySeconds: nil, profile: .advanced
        )

        let options = XCTMeasureOptions()
        options.iterationCount = 3

        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()], options: options) {
            _ = try! engine.exportSecretKey(
                certData: key.certData,
                passphrase: "benchmark-passphrase",
                profile: .advanced
            )
        }
    }

    // MARK: - High Security → Standard Reverse Mode Switch (Device)

    /// Verify full-stack mode switch from High Security back to Standard.
    /// This is the reverse direction of test_switchMode_standardToHighSecurity_fullStack.
    /// Uses real SE + real Keychain on device.
    func test_switchMode_highSecurityToStandard_fullStack() async throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0x88, count: 57) // Ed448 size

        let testDefaults = UserDefaults(suiteName: "com.cypherair.test.hs2std")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.test.hs2std") }
        testDefaults.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.authModeKey)

        // 1. Initial wrap under High Security mode.
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint)

        try keychain.save(bundle.seKeyData, service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(bundle.salt, service: KeychainConstants.saltService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(bundle.sealedBox, service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        // 2. Switch mode: High Security → Standard.
        // Brief pause to let any prior SE authentication session settle,
        // preventing "Canceled by another authentication" from overlapping requests.
        try await Task.sleep(for: .seconds(2))

        let mockAuth = MockAuthenticator()
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: testDefaults
        )
        try await authManager.switchMode(to: .standard, fingerprints: [fingerprint], hasBackup: true, authenticator: mockAuth)

        // 3. Verify: mode persisted as standard.
        XCTAssertEqual(
            testDefaults.string(forKey: AuthPreferences.authModeKey),
            AuthenticationMode.standard.rawValue
        )

        // 4. Verify: rewrap flag cleared.
        XCTAssertFalse(testDefaults.bool(forKey: AuthPreferences.rewrapInProgressKey))

        // 5. Verify: can still unwrap the key.
        let newSEKeyData = try keychain.load(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account)
        let newSalt = try keychain.load(service: KeychainConstants.saltService(fingerprint: fingerprint), account: account)
        let newSealed = try keychain.load(service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account)

        let newHandle = try secureEnclave.reconstructKey(from: newSEKeyData)
        let newBundle = WrappedKeyBundle(seKeyData: newSEKeyData, salt: newSalt, sealedBox: newSealed)
        let unwrapped = try secureEnclave.unwrap(bundle: newBundle, using: newHandle, fingerprint: fingerprint)

        XCTAssertEqual(unwrapped, fakePrivateKey, "Key must be accessible after HS→Standard switch")

        // 6. Verify: no pending items left.
        XCTAssertFalse(keychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account))
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
            let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
            let bundle = try secureEnclave.wrap(privateKey: fakeKey, using: handle, fingerprint: fingerprint)

            // Store 3 items
            try keychain.save(bundle.seKeyData, service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
            try keychain.save(bundle.salt, service: KeychainConstants.saltService(fingerprint: fingerprint), account: account, accessControl: nil)
            try keychain.save(bundle.sealedBox, service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

            // Load, reconstruct, unwrap, verify
            let loadedSE = try keychain.load(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account)
            let loadedSalt = try keychain.load(service: KeychainConstants.saltService(fingerprint: fingerprint), account: account)
            let loadedSealed = try keychain.load(service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account)

            let reconstructed = try secureEnclave.reconstructKey(from: loadedSE)
            let loadedBundle = WrappedKeyBundle(seKeyData: loadedSE, salt: loadedSalt, sealedBox: loadedSealed)
            let unwrapped = try secureEnclave.unwrap(bundle: loadedBundle, using: reconstructed, fingerprint: fingerprint)

            XCTAssertEqual(unwrapped, fakeKey, "Iteration \(i): unwrapped key must match original")

            // Delete all 3 items
            try keychain.delete(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account)
            try keychain.delete(service: KeychainConstants.saltService(fingerprint: fingerprint), account: account)
            try keychain.delete(service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account)

            // Verify deletion
            XCTAssertFalse(keychain.exists(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account),
                           "Iteration \(i): SE key must be deleted")
        }
    }

    // MARK: - 12-Key Mode Switch Stress Tests (Mock-Based)

    /// Stress test: switch mode with 12 identities. All should be re-wrapped successfully.
    func test_switchMode_12Keys_allRewrappedSuccessfully() async throws {
        let mockKeychain = MockKeychain()
        let mockSE = MockSecureEnclave()
        let mockAuth = MockAuthenticator()

        let testDefaults = UserDefaults(suiteName: "com.cypherair.test.12keys")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.test.12keys") }
        testDefaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)

        let account = KeychainConstants.defaultAccount
        var fingerprints: [String] = []
        var originalKeys: [String: Data] = [:]

        // Create 12 identities with alternating key sizes
        for i in 0..<12 {
            let fp = uniqueFingerprint()
            fingerprints.append(fp)
            let keySize = (i % 2 == 0) ? 32 : 57
            let fakeKey = Data(repeating: UInt8(i + 0x10), count: keySize)
            originalKeys[fp] = fakeKey

            let handle = try mockSE.generateWrappingKey(accessControl: nil)
            let bundle = try mockSE.wrap(privateKey: fakeKey, using: handle, fingerprint: fp)
            try mockKeychain.save(bundle.seKeyData, service: KeychainConstants.seKeyService(fingerprint: fp), account: account, accessControl: nil)
            try mockKeychain.save(bundle.salt, service: KeychainConstants.saltService(fingerprint: fp), account: account, accessControl: nil)
            try mockKeychain.save(bundle.sealedBox, service: KeychainConstants.sealedKeyService(fingerprint: fp), account: account, accessControl: nil)
        }

        // Switch mode Standard → High Security
        let authManager = AuthenticationManager(
            secureEnclave: mockSE,
            keychain: mockKeychain,
            defaults: testDefaults
        )
        try await authManager.switchMode(to: .highSecurity, fingerprints: fingerprints, hasBackup: true, authenticator: mockAuth)

        // Verify: mode persisted
        XCTAssertEqual(testDefaults.string(forKey: AuthPreferences.authModeKey),
                       AuthenticationMode.highSecurity.rawValue)
        XCTAssertFalse(testDefaults.bool(forKey: AuthPreferences.rewrapInProgressKey))

        // Verify: all 12 keys are accessible after re-wrap
        for fp in fingerprints {
            let seData = try mockKeychain.load(service: KeychainConstants.seKeyService(fingerprint: fp), account: account)
            let salt = try mockKeychain.load(service: KeychainConstants.saltService(fingerprint: fp), account: account)
            let sealed = try mockKeychain.load(service: KeychainConstants.sealedKeyService(fingerprint: fp), account: account)

            let handle = try mockSE.reconstructKey(from: seData)
            let bundle = WrappedKeyBundle(seKeyData: seData, salt: salt, sealedBox: sealed)
            let unwrapped = try mockSE.unwrap(bundle: bundle, using: handle, fingerprint: fp)
            XCTAssertEqual(unwrapped, originalKeys[fp], "Key for \(fp) must match after 12-key mode switch")

            // No pending items
            XCTAssertFalse(mockKeychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fp), account: account))
        }
    }

    /// Stress test: 12 identities, fail on key #8's first pending save. All original keys should remain intact.
    func test_switchMode_12Keys_failOnKey8_rollsBackAll() async throws {
        let mockKeychain = MockKeychain()
        let mockSE = MockSecureEnclave()
        let mockAuth = MockAuthenticator()

        let testDefaults = UserDefaults(suiteName: "com.cypherair.test.12fail")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.test.12fail") }
        testDefaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)

        let account = KeychainConstants.defaultAccount
        var fingerprints: [String] = []
        var originalBundles: [String: WrappedKeyBundle] = [:]

        // Create 12 identities
        for i in 0..<12 {
            let fp = uniqueFingerprint()
            fingerprints.append(fp)
            let keySize = (i % 2 == 0) ? 32 : 57
            let fakeKey = Data(repeating: UInt8(i + 0x20), count: keySize)

            let handle = try mockSE.generateWrappingKey(accessControl: nil)
            let bundle = try mockSE.wrap(privateKey: fakeKey, using: handle, fingerprint: fp)
            try mockKeychain.save(bundle.seKeyData, service: KeychainConstants.seKeyService(fingerprint: fp), account: account, accessControl: nil)
            try mockKeychain.save(bundle.salt, service: KeychainConstants.saltService(fingerprint: fp), account: account, accessControl: nil)
            try mockKeychain.save(bundle.sealedBox, service: KeychainConstants.sealedKeyService(fingerprint: fp), account: account, accessControl: nil)
            originalBundles[fp] = bundle
        }

        // 36 saves so far (12 keys × 3 items). Pending saves start at 37.
        // Key #8 (0-indexed: key 7) starts pending saves at save 37 + (7 × 3) = 58.
        // Fail on save 58 = first pending item of key #8.
        mockKeychain.failOnSaveNumber = 58

        let authManager = AuthenticationManager(
            secureEnclave: mockSE,
            keychain: mockKeychain,
            defaults: testDefaults
        )

        // Attempt mode switch — should fail and roll back
        do {
            try await authManager.switchMode(
                to: .highSecurity,
                fingerprints: fingerprints,
                hasBackup: true,
                authenticator: mockAuth
            )
            XCTFail("switchMode should have thrown due to Keychain save failure at key #8")
        } catch let error as AuthenticationError {
            if case .modeSwitchFailed = error {
                // Expected
            } else {
                XCTFail("Expected .modeSwitchFailed, got \(error)")
            }
        }

        // Verify: all 12 original keys are intact
        for fp in fingerprints {
            let loaded = try mockKeychain.load(service: KeychainConstants.seKeyService(fingerprint: fp), account: account)
            XCTAssertEqual(loaded, originalBundles[fp]!.seKeyData,
                           "Original SE key for \(fp) must be intact after rollback")
        }

        // Verify: no pending items for any fingerprint
        for fp in fingerprints {
            XCTAssertFalse(mockKeychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fp), account: account),
                           "Pending items for \(fp) must be cleaned up after rollback")
        }

        // Verify: rewrap flag cleared, mode unchanged
        XCTAssertFalse(testDefaults.bool(forKey: AuthPreferences.rewrapInProgressKey))
        XCTAssertEqual(testDefaults.string(forKey: AuthPreferences.authModeKey),
                       AuthenticationMode.standard.rawValue)
    }
}
