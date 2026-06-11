#if os(macOS)
import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Uniform enrollment rule — mode-switch rewrap: the WHOLE
/// `AuthenticationManager.switchMode` action (pre-authentication + both re-wrap
/// phases) runs inside one operation-prompt session, so the pre-auth sheet's
/// own resign is deferred and decided at the session's end.
@MainActor
final class ModeSwitchOperationPromptCompositionTests: XCTestCase {
    /// Suspends inside the mode-switch pre-auth so the test can deliver a
    /// resign while the "system sheet" is up, recording whether the coordinator
    /// saw the prompt as part of an operation session.
    private final class GatedModeSwitchAuthenticator: AuthenticationEvaluable, @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Never>?
        private var observedInSession: Bool?
        let suspendedExpectation = XCTestExpectation(description: "mode-switch pre-auth suspended")
        private let coordinator: AuthenticationPromptCoordinator

        init(coordinator: AuthenticationPromptCoordinator) {
            self.coordinator = coordinator
        }

        var wasInOperationPromptSession: Bool? {
            lock.withLock { observedInSession }
        }

        var isBiometricsAvailable: Bool { true }
        var lastEvaluatedContext: LAContext? { nil }
        func canEvaluate(mode: AuthenticationMode) -> Bool { true }

        func evaluate(mode: AuthenticationMode, reason: String) async throws -> Bool {
            let inSession = coordinator.isOperationPromptInProgress
            lock.withLock { observedInSession = inSession }
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                lock.withLock { continuation = cont }
                suspendedExpectation.fulfill()
            }
            return true
        }

        func resume() {
            let cont = lock.withLock {
                let value = continuation
                continuation = nil
                return value
            }
            cont?.resume()
        }
    }

    private func makeManager(
        coordinator: AuthenticationPromptCoordinator
    ) throws -> (manager: AuthenticationManager, fingerprint: String, defaultsSuiteName: String) {
        let suiteName = "com.cypherair.tests.modeswitch.composition.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let manager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults,
            authenticationPromptCoordinator: coordinator
        )
        manager.configurePrivateKeyControlStore(InMemoryPrivateKeyControlStore(mode: .standard))
        let fingerprint = String(repeating: "a", count: 40)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: Data(repeating: 0x42, count: 32),
            using: handle,
            fingerprint: fingerprint
        )
        try KeyBundleStore(keychain: keychain).saveBundle(bundle, fingerprint: fingerprint)
        return (manager, fingerprint, suiteName)
    }

    func test_switchMode_runsInsideOperationPromptSession_resignDeferred_thenLockedWhenStillAway() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount
        let made = try makeManager(coordinator: harness.coordinator)
        defer { UserDefaults(suiteName: made.defaultsSuiteName)?.removePersistentDomain(forName: made.defaultsSuiteName) }
        let stub = GatedModeSwitchAuthenticator(coordinator: harness.coordinator)

        let action = Task {
            try await made.manager.switchMode(
                to: .highSecurity,
                fingerprints: [made.fingerprint],
                hasBackup: true,
                authenticator: stub
            )
        }
        await fulfillment(of: [stub.suspendedExpectation], timeout: 10)
        await harness.settle() // the session-began hop must land before the resign

        XCTAssertEqual(
            stub.wasInOperationPromptSession,
            true,
            "The mode-switch pre-auth must run inside an operation-prompt session (the uniform rule)."
        )

        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .unlocked,
            "A resign during the in-session pre-auth is deferred, never a mid-action lock."
        )
        XCTAssertEqual(harness.relockCount, relocksBefore)

        stub.resume()
        try await action.value
        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .locked,
            "Still away at the prompts' end -> the deferred away is processed fail-closed."
        )
        XCTAssertGreaterThan(harness.relockCount, relocksBefore)
    }

    func test_switchMode_resignDiscarded_whenForegroundReturnsBeforePromptsEnd() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount
        let made = try makeManager(coordinator: harness.coordinator)
        defer { UserDefaults(suiteName: made.defaultsSuiteName)?.removePersistentDomain(forName: made.defaultsSuiteName) }
        let stub = GatedModeSwitchAuthenticator(coordinator: harness.coordinator)

        let action = Task {
            try await made.manager.switchMode(
                to: .highSecurity,
                fingerprints: [made.fingerprint],
                hasBackup: true,
                authenticator: stub
            )
        }
        await fulfillment(of: [stub.suspendedExpectation], timeout: 10)
        await harness.settle()

        harness.deliverResign()
        harness.deliverReturn() // it was the prompt's own resign: the user never left
        stub.resume()
        try await action.value
        await harness.settle()

        XCTAssertEqual(harness.lockState, .unlocked)
        XCTAssertEqual(harness.relockCount, relocksBefore)
    }

    func test_switchMode_earlyExit_keepsSessionBalanced() async throws {
        // noIdentities throws out of the wrapped body: the rethrow path must
        // close the session so a later resign is processed normally.
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let made = try makeManager(coordinator: harness.coordinator)
        defer { UserDefaults(suiteName: made.defaultsSuiteName)?.removePersistentDomain(forName: made.defaultsSuiteName) }

        do {
            try await made.manager.switchMode(
                to: .highSecurity,
                fingerprints: [],
                hasBackup: true,
                authenticator: MockAuthenticator()
            )
            XCTFail("Expected noIdentities")
        } catch AuthenticationError.noIdentities {
        }

        await harness.settle()
        XCTAssertFalse(harness.coordinator.isOperationPromptInProgress)
        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .locked,
            "After the balanced early exit, a genuine resign locks normally — no leaked session."
        )
    }
}
#endif
