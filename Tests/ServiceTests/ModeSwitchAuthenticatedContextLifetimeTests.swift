import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Protection-mode switch: one authentication, reused for every key, and dead
/// when the switch ends.
///
/// The reuse is the reason the switch authenticates up front — re-wrapping N keys
/// must not mean N prompts. The lifetime is the other half of that bargain: the
/// authenticated context is a live Secure Enclave capability, so it must not
/// outlive the switch that minted it (it used to survive until app termination,
/// app relock included — issue #776).
final class ModeSwitchAuthenticatedContextLifetimeTests: XCTestCase {
    /// Counts invalidations so a test can pin "exactly one, after the switch ends".
    private final class TrackingLAContext: LAContext {
        private(set) var invalidateCount = 0
        override func invalidate() {
            invalidateCount += 1
            super.invalidate()
        }
    }

    private final class StubModeSwitchAuthenticator: AuthenticationEvaluable, @unchecked Sendable {
        private(set) var evaluateCalls = 0
        let context = TrackingLAContext()
        /// Hands back a live context alongside `isAuthenticated: false` — a shape
        /// the production evaluator never produces, but one the memberwise
        /// initializer allows any conformer to build.
        var reportsAuthenticated = true

        var isBiometricsAvailable: Bool { true }
        func canEvaluate(mode: AuthenticationMode) -> Bool { true }

        func evaluate(
            mode: AuthenticationMode,
            reason: String
        ) async throws -> PrivateKeyAuthenticationResult {
            evaluateCalls += 1
            return PrivateKeyAuthenticationResult(
                isAuthenticated: reportsAuthenticated,
                context: context
            )
        }
    }

    private struct Fixture {
        let manager: AuthenticationManager
        let secureEnclave: MockSecureEnclave
        let fingerprints: [String]
        let defaultsSuiteName: String
    }

    private func makeFixture(keyCount: Int) throws -> Fixture {
        let suiteName = "com.cypherair.tests.modeswitch.contextlifetime.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let manager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults,
            authenticationPromptCoordinator: AuthenticationPromptCoordinator()
        )
        manager.configurePrivateKeyControlStore(InMemoryPrivateKeyControlStore(mode: .standard))

        let bundleStore = KeyBundleStore(keychain: keychain)
        let fingerprints = (0..<keyCount).map { String(repeating: String($0), count: 40) }
        for (index, fingerprint) in fingerprints.enumerated() {
            let handle = try secureEnclave.generateWrappingKey(
                accessControl: nil,
                authenticationContext: nil
            )
            let bundle = try secureEnclave.wrap(
                privateKey: Data(repeating: UInt8(0x40 + index), count: 32),
                using: handle,
                fingerprint: fingerprint
            )
            try bundleStore.saveBundle(bundle, fingerprint: fingerprint)
        }

        return Fixture(
            manager: manager,
            secureEnclave: secureEnclave,
            fingerprints: fingerprints,
            defaultsSuiteName: suiteName
        )
    }

    func test_switchMode_authenticatesOnce_reusesThatContextForEveryKey_thenInvalidatesIt() async throws {
        let fixture = try makeFixture(keyCount: 2)
        defer { UserDefaults().removePersistentDomain(forName: fixture.defaultsSuiteName) }
        let stub = StubModeSwitchAuthenticator()
        let generatesBeforeSwitch = fixture.secureEnclave.generateCallCount

        try await fixture.manager.switchMode(
            to: .highSecurity,
            fingerprints: fixture.fingerprints,
            hasBackup: true,
            authenticator: stub
        )

        XCTAssertEqual(fixture.manager.currentMode, .highSecurity)
        XCTAssertEqual(stub.evaluateCalls, 1, "The whole switch runs on a single authentication.")
        XCTAssertEqual(
            fixture.secureEnclave.reconstructCallCount,
            fixture.fingerprints.count,
            "Every key is re-wrapped."
        )
        XCTAssertEqual(
            fixture.secureEnclave.generateCallCount - generatesBeforeSwitch,
            fixture.fingerprints.count,
            "Every key gets a new wrapping key under the target mode."
        )
        XCTAssertTrue(
            fixture.secureEnclave.lastReconstructAuthenticationContext === stub.context,
            "The unwrap side must consume the switch's authenticated context, not prompt again."
        )
        XCTAssertTrue(
            fixture.secureEnclave.lastGenerateAuthenticationContext === stub.context,
            "The re-wrap side must consume the same context, keeping the switch in one authentication."
        )
        XCTAssertEqual(
            stub.context.invalidateCount,
            1,
            "The switch's authentication dies with the switch — it must not stay usable afterwards."
        )
    }

    func test_switchMode_failedRewrap_stillInvalidatesTheAuthenticatedContext() async throws {
        let fixture = try makeFixture(keyCount: 1)
        defer { UserDefaults().removePersistentDomain(forName: fixture.defaultsSuiteName) }
        let stub = StubModeSwitchAuthenticator()
        fixture.secureEnclave.nextError = MockSEError.invalidKeyHandle

        do {
            try await fixture.manager.switchMode(
                to: .highSecurity,
                fingerprints: fixture.fingerprints,
                hasBackup: true,
                authenticator: stub
            )
            XCTFail("Expected the failed re-wrap to abort the switch")
        } catch AuthenticationError.modeSwitchFailed {
        }

        XCTAssertEqual(fixture.manager.currentMode, .standard, "A failed switch keeps the old mode.")
        XCTAssertEqual(
            stub.context.invalidateCount,
            1,
            "A switch that fails part-way must not leave its authentication alive either."
        )
    }

    func test_switchMode_notAuthenticatedResult_abortsAndInvalidatesTheContextItWasHanded() async throws {
        let fixture = try makeFixture(keyCount: 1)
        defer { UserDefaults().removePersistentDomain(forName: fixture.defaultsSuiteName) }
        let stub = StubModeSwitchAuthenticator()
        stub.reportsAuthenticated = false

        do {
            try await fixture.manager.switchMode(
                to: .highSecurity,
                fingerprints: fixture.fingerprints,
                hasBackup: true,
                authenticator: stub
            )
            XCTFail("Expected a not-authenticated result to abort the switch")
        } catch AuthenticationError.failed {
        }

        XCTAssertEqual(fixture.manager.currentMode, .standard)
        XCTAssertEqual(
            fixture.secureEnclave.reconstructCallCount,
            0,
            "Nothing is re-wrapped without an authenticated result."
        )
        XCTAssertEqual(
            stub.context.invalidateCount,
            1,
            "The guard revokes whatever context it was handed rather than trusting the producer to have passed nil."
        )
    }
}
