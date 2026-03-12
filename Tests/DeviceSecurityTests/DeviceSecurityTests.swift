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

    // MARK: - C8: MIE Smoke Tests

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
}
