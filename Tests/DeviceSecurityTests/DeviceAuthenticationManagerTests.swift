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

        let authManager = makeAuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults
        )

        try await waitForAuthenticationSessionToSettle()

        let authenticated = try await authManager.evaluate(mode: mode, reason: reason)
        XCTAssertTrue(authenticated, "Authentication must succeed before SE reconstruction")

        let loadedEnvelope = try keychain.load(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
        let loadedSEKey = try PrivateKeyEnvelopeCodec.seKeyData(from: loadedEnvelope, expectedFingerprint: fingerprint)
        let handle = try secureEnclave.reconstructKey(
            from: loadedSEKey,
            authenticationContext: authManager.lastEvaluatedContext
        )
        let storedBundle = WrappedKeyBundle(envelope: loadedEnvelope)
        let unwrapped = try secureEnclave.unwrap(
            bundle: storedBundle,
            using: handle,
            fingerprint: fingerprint
        )

        XCTAssertEqual(unwrapped, privateKey, "Stored key must unwrap after production authentication")
    }

    // MARK: - C7.1: Authentication Manager — Access Control

    func test_createAccessControl_standard_succeeds() throws {
        let authManager = makeAuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let ac = try authManager.createAccessControl(for: .standard)
        // SecAccessControl is an opaque type; if we get here without throwing, it succeeded.
        XCTAssertNotNil(ac)
    }

    func test_createAccessControl_highSecurity_succeeds() throws {
        let authManager = makeAuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let ac = try authManager.createAccessControl(for: .highSecurity)
        XCTAssertNotNil(ac)
    }

    func test_canEvaluate_standard_returnsTrue() {
        let authManager = makeAuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        // On a real device with passcode set, standard mode should always be evaluable.
        XCTAssertTrue(authManager.canEvaluate(mode: .standard), "Standard mode must be evaluable on device")
    }

    func test_canEvaluate_highSecurity_matchesBiometricsAvailability() {
        let authManager = makeAuthenticationManager(
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
        let authManager = makeAuthenticationManager(
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

    // MARK: - C7.2: Authentication Manager — Private-Key Control State

    func test_currentMode_withoutPrivateKeyControlStore_isNil() {
        let testDefaults = UserDefaults(suiteName: "com.cypherair.test")!
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: testDefaults
        )
        XCTAssertNil(authManager.currentMode, "Locked private-key control must not expose a default mode")
        testDefaults.removePersistentDomain(forName: "com.cypherair.test")
    }

    // MARK: - C7.3: Crash Recovery

    func test_crashRecovery_oldAndPendingExist_cleansPendingKeepsOld() throws {
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        // Simulate: the old permanent envelope exists (the original key).
        let oldData = Data("original-envelope".utf8)
        try keychain.save(oldData, service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint), account: account, accessControl: nil)

        // Simulate: a pending envelope also exists (interrupted re-wrap).
        try keychain.save(Data("pending-envelope".utf8), service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint), account: account, accessControl: nil)

        // Set the protected recovery journal and simulate switching from standard -> highSecurity.
        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)

        let authManager = makeAuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        // Verify: protected journal cleared.
        XCTAssertEqual(summary?.outcomes, [.cleanedPendingSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)

        // Verify: old envelope still intact.
        let loadedOld = try keychain.load(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint), account: account)
        XCTAssertEqual(loadedOld, oldData, "Original envelope must be intact after crash recovery")

        // Verify: pending envelope removed.
        XCTAssertFalse(
            keychain.exists(service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint), account: account),
            "Pending envelope must be cleaned up"
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

        // Simulate: old envelope deleted, only the pending envelope remains.
        let pendingEnvelope = Data("promoted-envelope".utf8)
        try keychain.save(pendingEnvelope, service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint), account: account, accessControl: nil)

        // Simulate switching from standard -> highSecurity.
        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)

        let authManager = makeAuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        // Verify: protected journal cleared.
        XCTAssertEqual(summary?.outcomes, [.promotedPendingSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)

        // Verify: envelope promoted to the permanent row.
        let loadedEnvelope = try keychain.load(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint), account: account)
        XCTAssertEqual(loadedEnvelope, pendingEnvelope, "Pending envelope must be promoted to permanent")

        // Verify: pending envelope removed.
        XCTAssertFalse(keychain.exists(service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint), account: account))

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

        // No journal entry set, but a pending envelope exists (should be left alone).
        try keychain.save(Data("stale".utf8), service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint), account: account, accessControl: nil)

        let authManager = makeAuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        // Pending envelope should still be there (recovery did not run).
        XCTAssertNil(summary)
        XCTAssertTrue(keychain.exists(service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint), account: account))
    }

    // The former `test_crashRecovery_partialPermanentAndCompletePending_replacesPermanent`
    // was removed: a partially-present permanent bundle is structurally impossible with the
    // single-row envelope, so that scenario collapses to
    // `test_crashRecovery_onlyPendingExist_promotesToPermanent` above.

    func test_crashRecovery_unrecoverable_clearsFlagAndLeavesAuthModeUnchanged() {
        let fingerprint = uniqueFingerprint()

        // Neither a permanent nor a pending envelope is present → unrecoverable.
        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try? privateKeyControlStore.beginRewrap(targetMode: .highSecurity)

        let authManager = makeAuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.unrecoverable])
        XCTAssertNil((try? privateKeyControlStore.recoveryJournal())?.rewrapTargetMode)
        XCTAssertEqual(authManager.currentMode, .standard)
    }

    func test_crashRecovery_retryableFailure_keepsFlagAndDoesNotUpdateAuthMode() {
        let testDefaults = UserDefaults(suiteName: "com.cypherair.retryable")!
        defer { testDefaults.removePersistentDomain(forName: "com.cypherair.retryable") }

        let mockKeychain = MockKeychain()
        let mockSecureEnclave = MockSecureEnclave()
        let fingerprint = uniqueFingerprint()
        let account = KeychainConstants.defaultAccount

        try? mockKeychain.save(Data("pending-envelope".utf8), service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint), account: account, accessControl: nil)

        mockKeychain.failOnSaveNumber = mockKeychain.saveCallCount + 1

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try? privateKeyControlStore.beginRewrap(targetMode: .highSecurity)

        let authManager = makeAuthenticationManager(
            secureEnclave: mockSecureEnclave,
            keychain: mockKeychain,
            defaults: testDefaults,
            privateKeyControlStore: privateKeyControlStore
        )
        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.retryableFailure])
        XCTAssertEqual((try? privateKeyControlStore.recoveryJournal())?.rewrapTargetMode, .highSecurity)
        XCTAssertEqual(authManager.currentMode, .standard)
        XCTAssertTrue(mockKeychain.exists(service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint), account: account))
    }
}
