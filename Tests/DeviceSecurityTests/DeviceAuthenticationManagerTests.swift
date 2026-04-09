import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// C7.1-C7.3: Authentication manager tests on real hardware.
final class DeviceAuthenticationManagerTests: DeviceSecurityTestCase {
    private func authenticateAndUnwrapStoredBundle(
        mode: AuthenticationMode,
        fingerprint: String,
        privateKey: Data,
        defaults: UserDefaults,
        reason: String
    ) async throws {
        try await waitForAuthenticationSessionToSettle()

        let bundle = try createWrappedBundle(
            privateKey: privateKey,
            fingerprint: fingerprint,
            mode: mode
        )
        try storePermanentBundle(bundle, fingerprint: fingerprint)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults
        )

        try await waitForAuthenticationSessionToSettle()

        let authenticated = try await authManager.evaluate(mode: mode, reason: reason)
        XCTAssertTrue(authenticated, "Authentication must succeed before SE reconstruction")

        let loadedSEKey = try keychain.load(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
        let loadedSalt = try keychain.load(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
        let loadedSealed = try keychain.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
        let handle = try secureEnclave.reconstructKey(
            from: loadedSEKey,
            authenticationContext: authManager.lastEvaluatedContext
        )
        let storedBundle = WrappedKeyBundle(
            seKeyData: loadedSEKey,
            salt: loadedSalt,
            sealedBox: loadedSealed
        )
        let unwrapped = try secureEnclave.unwrap(
            bundle: storedBundle,
            using: handle,
            fingerprint: fingerprint
        )

        XCTAssertEqual(unwrapped, privateKey, "Stored key must unwrap after production authentication")
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

    func test_canEvaluate_highSecurity_matchesBiometricsAvailability() {
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )

        XCTAssertEqual(
            authManager.canEvaluate(mode: .highSecurity),
            authManager.isBiometricsAvailable,
            "High Security evaluability should match biometric availability"
        )
    }

    func test_isBiometricsAvailable_onFaceIDDevice_returnsTrue() {
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        // iPhone 17 Pro Max has Face ID — this should return true.
        XCTAssertTrue(authManager.isBiometricsAvailable, "Biometrics must be available on iPhone 17 Pro Max")
    }

    // MARK: - C7.1A: Production Authentication Path (Manual Device)

    func test_authenticateAndUnwrap_standard_productionPath_manual() async throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let testDefaults = UserDefaults(suiteName: "com.cypherair.device.manual.standard")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.device.manual.standard") }

        try await authenticateAndUnwrapStoredBundle(
            mode: .standard,
            fingerprint: fingerprint,
            privateKey: Data(repeating: 0x91, count: 32),
            defaults: testDefaults,
            reason: "Authenticate to validate Standard mode Secure Enclave access."
        )
    }

    func test_authenticateAndUnwrap_highSecurity_productionPath_manual() async throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        let testDefaults = UserDefaults(suiteName: "com.cypherair.device.manual.highsecurity")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.device.manual.highsecurity") }

        try await authenticateAndUnwrapStoredBundle(
            mode: .highSecurity,
            fingerprint: fingerprint,
            privateKey: Data(repeating: 0xA7, count: 57),
            defaults: testDefaults,
            reason: "Authenticate to validate High Security Secure Enclave access."
        )
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

        // Set the crash recovery flag and simulate switching from standard → highSecurity.
        UserDefaults.standard.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        UserDefaults.standard.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)
        UserDefaults.standard.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        // Verify: flag cleared.
        XCTAssertEqual(summary?.outcomes, [.cleanedPendingSafe])
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

        // Verify: auth mode remains standard (old keys have standard ACLs).
        XCTAssertEqual(
            authManager.currentMode,
            .standard,
            "Case 1 recovery must NOT change auth mode — old keys retain original ACLs"
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

        // Simulate switching from standard → highSecurity.
        UserDefaults.standard.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        UserDefaults.standard.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)
        UserDefaults.standard.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        // Verify: flag cleared.
        XCTAssertEqual(summary?.outcomes, [.promotedPendingSafe])
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

        // Verify: auth mode updated to highSecurity (promoted keys have new ACLs).
        XCTAssertEqual(
            authManager.currentMode,
            .highSecurity,
            "Case 2 recovery must update auth mode to target — promoted keys have new ACLs"
        )
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
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        // Pending items should still be there (recovery did not run).
        XCTAssertNil(summary)
        XCTAssertTrue(keychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account))
    }

    func test_crashRecovery_partialPermanentAndCompletePending_replacesPermanent() throws {
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        let oldData = Data("original-se-key".utf8)
        try keychain.save(oldData, service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        let pendingSEKey = Data("promoted-se-key".utf8)
        let pendingSalt = Data("promoted-salt".utf8)
        let pendingSealed = Data("promoted-sealed".utf8)
        try keychain.save(pendingSEKey, service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(pendingSalt, service: KeychainConstants.pendingSaltService(fingerprint: fingerprint), account: account, accessControl: nil)
        try keychain.save(pendingSealed, service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        UserDefaults.standard.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        UserDefaults.standard.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)
        UserDefaults.standard.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.promotedPendingSafe])
        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.rewrapInProgressKey))
        XCTAssertEqual(
            try keychain.load(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account),
            pendingSEKey
        )
        XCTAssertEqual(
            try keychain.load(service: KeychainConstants.saltService(fingerprint: fingerprint), account: account),
            pendingSalt
        )
        XCTAssertEqual(
            try keychain.load(service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account),
            pendingSealed
        )
        XCTAssertEqual(authManager.currentMode, .highSecurity)
    }

    func test_crashRecovery_unrecoverable_clearsFlagAndLeavesAuthModeUnchanged() {
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        try? keychain.save(Data("partial-old".utf8), service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
        try? keychain.save(Data("partial-pending".utf8), service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        UserDefaults.standard.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        UserDefaults.standard.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)
        UserDefaults.standard.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.unrecoverable])
        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.rewrapInProgressKey))
        XCTAssertEqual(authManager.currentMode, .standard)
    }

    func test_crashRecovery_retryableFailure_keepsFlagAndDoesNotUpdateAuthMode() {
        let testDefaults = UserDefaults(suiteName: "com.cypherair.retryable")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.retryable") }

        let mockKeychain = MockKeychain()
        let mockSecureEnclave = MockSecureEnclave()
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        try? mockKeychain.save(Data("pending-se-key".utf8), service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account, accessControl: nil)
        try? mockKeychain.save(Data("pending-salt".utf8), service: KeychainConstants.pendingSaltService(fingerprint: fingerprint), account: account, accessControl: nil)
        try? mockKeychain.save(Data("pending-sealed".utf8), service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint), account: account, accessControl: nil)

        mockKeychain.failOnSaveNumber = mockKeychain.saveCallCount + 1

        testDefaults.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        testDefaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.authModeKey)
        testDefaults.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)

        let authManager = AuthenticationManager(
            secureEnclave: mockSecureEnclave,
            keychain: mockKeychain,
            defaults: testDefaults
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.retryableFailure])
        XCTAssertTrue(testDefaults.bool(forKey: AuthPreferences.rewrapInProgressKey))
        XCTAssertEqual(authManager.currentMode, .standard)
        XCTAssertTrue(mockKeychain.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account))
    }
}
