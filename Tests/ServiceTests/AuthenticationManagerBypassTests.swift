import LocalAuthentication
import XCTest
@testable import CypherAir

/// The UITest authentication bypass must stay OFF unless a build explicitly
/// opts in through the constructor. A flipped default would silently disable
/// authentication on every code path — and because a bypassed evaluation still
/// reports success, no other test would catch it. These exercise the real
/// constructor default (the opt-in argument is omitted) so a flip is caught.
final class AuthenticationManagerBypassTests: XCTestCase {
    /// Mirrors the private `UITestPreferences.bypassAuthenticationKey`. The
    /// control test below fails if this drifts, so it cannot pass vacuously.
    private static let bypassPreferenceKey = "com.cypherair.preference.uiTestBypassAuthentication"

    private final class PolicyEvaluatorSpy: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        var invocationCount: Int {
            lock.lock()
            defer { lock.unlock() }
            return count
        }
        func record() {
            lock.lock()
            defer { lock.unlock() }
            count += 1
        }
    }

    private func makeDefaults(bypassPreferenceEnabled: Bool) -> (UserDefaults, String) {
        let suiteName = "com.cypherair.tests.authbypass.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.set(bypassPreferenceEnabled, forKey: Self.bypassPreferenceKey)
        return (defaults, suiteName)
    }

    func test_bypassEngagesOnlyWhenConstructorOptInEnabled() async throws {
        // Control: opt-in enabled AND the preference set ⇒ both evaluate paths
        // short-circuit before the policy evaluator runs. This also proves the
        // preference key is wired: if it were not, real authentication would run
        // here and the invocation count would not be zero.
        let (defaults, suiteName) = makeDefaults(bypassPreferenceEnabled: true)
        defer { UserDefaults().removePersistentDomain(forName: suiteName) }
        let spy = PolicyEvaluatorSpy()
        let manager = AuthenticationManager(
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            defaults: defaults,
            allowsUITestAuthenticationBypass: true,
            authenticationPromptCoordinator: AuthenticationPromptCoordinator(),
            localAuthenticationPolicyEvaluator: { _, _, _, reply in
                spy.record()
                reply(true, nil)
            }
        )

        _ = try await manager.evaluate(mode: .standard, reason: "control")
        _ = try await manager.evaluateAppSession(policy: .userPresence, reason: "control")

        XCTAssertEqual(
            spy.invocationCount,
            0,
            "With the constructor opt-in enabled and the preference set, both evaluate paths bypass real authentication."
        )
    }

    func test_bothEvaluatePathsIgnoreBypassPreferenceByDefault() async throws {
        // Guard: the constructor default (opt-in argument omitted) must ignore the
        // preference, so both evaluate paths still perform real authentication even
        // with the bypass preference set.
        let (defaults, suiteName) = makeDefaults(bypassPreferenceEnabled: true)
        defer { UserDefaults().removePersistentDomain(forName: suiteName) }
        let spy = PolicyEvaluatorSpy()
        let manager = AuthenticationManager(
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            defaults: defaults,
            authenticationPromptCoordinator: AuthenticationPromptCoordinator(),
            localAuthenticationPolicyEvaluator: { _, _, _, reply in
                spy.record()
                reply(true, nil)
            }
        )

        _ = try await manager.evaluate(mode: .standard, reason: "guard")
        _ = try await manager.evaluateAppSession(policy: .userPresence, reason: "guard")

        XCTAssertEqual(
            spy.invocationCount,
            2,
            "The bypass preference must be ignored unless the constructor opt-in is set; both evaluate paths must authenticate for real."
        )
    }
}
