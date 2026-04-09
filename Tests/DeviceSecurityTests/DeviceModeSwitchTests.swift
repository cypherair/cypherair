import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// C7.4-C7.6 and related mode-switch stress tests.
final class DeviceModeSwitchTests: DeviceSecurityTestCase {
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

    // MARK: - C7.5: Mode Switch Migration Flow on Device (SE + Keychain)

    /// Verifies the migration flow completes on real device infrastructure.
    /// This test intentionally uses a mock authenticator and a non-ACL initial key so it
    /// remains non-interactive; it does NOT prove the final High Security boundary.
    func test_switchMode_standardToHighSecurity_migrationFlowCompletesWithMockAuthenticator() async throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0x77, count: 32)

        let testDefaults = UserDefaults(suiteName: "com.cypherair.test")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.test") }
        testDefaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)

        // 1. Initial wrap under Standard mode (no access control for test simplicity).
        // This keeps the test non-interactive and focused on migration mechanics only.
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

    // MARK: - C7.5A: Mode Switch Access Control Validation (Manual Device)

    func test_switchMode_standardToHighSecurity_reappliesRealAccessControl_manual() async throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0x77, count: 32)

        let testDefaults = UserDefaults(suiteName: "com.cypherair.device.manual.stdtohs")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.device.manual.stdtohs") }
        testDefaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)

        let initialBundle = try createWrappedBundle(
            privateKey: fakePrivateKey,
            fingerprint: fingerprint,
            mode: .standard
        )
        try storePermanentBundle(initialBundle, fingerprint: fingerprint)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: testDefaults
        )

        // Brief pause to let any prior SE authentication session settle,
        // preventing "Canceled by another authentication" from overlapping requests.
        try await waitForAuthenticationSessionToSettle()

        try await authManager.switchMode(
            to: .highSecurity,
            fingerprints: [fingerprint],
            hasBackup: true,
            authenticator: authManager
        )

        XCTAssertEqual(
            testDefaults.string(forKey: AuthPreferences.authModeKey),
            AuthenticationMode.highSecurity.rawValue
        )
        XCTAssertFalse(testDefaults.bool(forKey: AuthPreferences.rewrapInProgressKey))

        try await waitForAuthenticationSessionToSettle()

        let authenticated = try await authManager.evaluate(
            mode: .highSecurity,
            reason: "Authenticate to validate High Security access after mode switch."
        )
        XCTAssertTrue(authenticated)

        let newSEKeyData = try keychain.load(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account
        )
        let newSalt = try keychain.load(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account
        )
        let newSealed = try keychain.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account
        )
        let newHandle = try secureEnclave.reconstructKey(
            from: newSEKeyData,
            authenticationContext: authManager.lastEvaluatedContext
        )
        let newBundle = WrappedKeyBundle(
            seKeyData: newSEKeyData,
            salt: newSalt,
            sealedBox: newSealed
        )
        let unwrapped = try secureEnclave.unwrap(
            bundle: newBundle,
            using: newHandle,
            fingerprint: fingerprint
        )

        XCTAssertEqual(unwrapped, fakePrivateKey, "Key must be accessible after manual Standard→High Security switch")
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

    // MARK: - High Security → Standard Reverse Mode Switch (Device)

    /// Verifies the reverse migration flow completes on real device infrastructure.
    /// Like the forward migration test, this remains non-interactive and does not
    /// prove the final Standard-mode passcode fallback boundary.
    func test_switchMode_highSecurityToStandard_migrationFlowCompletesWithMockAuthenticator() async throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0x88, count: 57) // Ed448 size

        let testDefaults = UserDefaults(suiteName: "com.cypherair.test.hs2std")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.test.hs2std") }
        testDefaults.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.authModeKey)

        // 1. Initial wrap under High Security mode.
        // No initial ACL so this test stays focused on migration mechanics.
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

    func test_switchMode_highSecurityToStandard_reappliesRealAccessControl_manual() async throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount
        let fakePrivateKey = Data(repeating: 0x88, count: 57)

        let testDefaults = UserDefaults(suiteName: "com.cypherair.device.manual.hs2std")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.device.manual.hs2std") }
        testDefaults.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.authModeKey)

        let initialBundle = try createWrappedBundle(
            privateKey: fakePrivateKey,
            fingerprint: fingerprint,
            mode: .highSecurity
        )
        try storePermanentBundle(initialBundle, fingerprint: fingerprint)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: testDefaults
        )

        // Brief pause to let any prior SE authentication session settle,
        // preventing "Canceled by another authentication" from overlapping requests.
        try await waitForAuthenticationSessionToSettle()

        try await authManager.switchMode(
            to: .standard,
            fingerprints: [fingerprint],
            hasBackup: true,
            authenticator: authManager
        )

        XCTAssertEqual(
            testDefaults.string(forKey: AuthPreferences.authModeKey),
            AuthenticationMode.standard.rawValue
        )
        XCTAssertFalse(testDefaults.bool(forKey: AuthPreferences.rewrapInProgressKey))

        try await waitForAuthenticationSessionToSettle()

        let authenticated = try await authManager.evaluate(
            mode: .standard,
            reason: "Authenticate to validate Standard access after mode switch."
        )
        XCTAssertTrue(authenticated)

        let newSEKeyData = try keychain.load(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account
        )
        let newSalt = try keychain.load(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account
        )
        let newSealed = try keychain.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account
        )
        let newHandle = try secureEnclave.reconstructKey(
            from: newSEKeyData,
            authenticationContext: authManager.lastEvaluatedContext
        )
        let newBundle = WrappedKeyBundle(
            seKeyData: newSEKeyData,
            salt: newSalt,
            sealedBox: newSealed
        )
        let unwrapped = try secureEnclave.unwrap(
            bundle: newBundle,
            using: newHandle,
            fingerprint: fingerprint
        )

        XCTAssertEqual(unwrapped, fakePrivateKey, "Key must be accessible after manual High Security→Standard switch")
        XCTAssertFalse(keychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account))
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
