#if os(macOS)
import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Guards the macOS embedded app-session evaluation seam (issue #724 stage 2):
/// the supplied context IS the evaluated and returned context, the biometric
/// policy is the one evaluated, errors flow through the SAME app-session
/// normalization as the system-sheet path, and — the standing doctrine — an
/// app-session context never becomes `lastEvaluatedContext` (the private-key
/// mode-switch reuse seam). All via the injected policy evaluator; no real
/// LocalAuthentication.
final class AuthenticationManagerEmbeddedAppSessionTests: XCTestCase {
    private final class PolicyEvaluatorRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var policies: [LAPolicy] = []
        private var contexts: [LAContext] = []

        var recordedPolicies: [LAPolicy] {
            lock.lock()
            defer { lock.unlock() }
            return policies
        }

        var recordedContexts: [LAContext] {
            lock.lock()
            defer { lock.unlock() }
            return contexts
        }

        func record(context: LAContext, policy: LAPolicy) {
            lock.lock()
            defer { lock.unlock() }
            contexts.append(context)
            policies.append(policy)
        }
    }

    private func makeManager(
        recorder: PolicyEvaluatorRecorder,
        reply: @escaping @Sendable (@escaping (Bool, Error?) -> Void) -> Void
    ) -> AuthenticationManager {
        AuthenticationManager(
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            authenticationPromptCoordinator: AuthenticationPromptCoordinator(),
            localAuthenticationPolicyEvaluator: { context, policy, _, replyHandler in
                recorder.record(context: context, policy: policy)
                reply(replyHandler)
            }
        )
    }

    func test_success_evaluatesBiometricPolicyOnSuppliedContext_andReturnsIt() async throws {
        let recorder = PolicyEvaluatorRecorder()
        let manager = makeManager(recorder: recorder) { reply in
            reply(true, nil)
        }
        let embeddedContext = LAContext()

        let result = try await manager.evaluateAppSessionWithEmbeddedBiometrics(
            context: embeddedContext,
            reason: "test"
        )

        XCTAssertTrue(result.isAuthenticated)
        XCTAssertTrue(
            result.context === embeddedContext,
            "One context: the context the embedded view displays IS the handoff context."
        )
        XCTAssertTrue(recorder.recordedContexts.first === embeddedContext)
        XCTAssertEqual(recorder.recordedPolicies, [.deviceOwnerAuthenticationWithBiometrics])
        XCTAssertNil(
            manager.lastEvaluatedContext,
            "An app-session context must never enter the private-key mode-switch reuse seam."
        )
    }

    func test_biometryLockout_normalizesIdenticallyToSystemSheetPath() async {
        let recorder = PolicyEvaluatorRecorder()
        let manager = makeManager(recorder: recorder) { reply in
            reply(false, LAError(.biometryLockout))
        }

        do {
            _ = try await manager.evaluateAppSessionWithEmbeddedBiometrics(
                context: LAContext(),
                reason: "test"
            )
            XCTFail("Expected the lockout to throw.")
        } catch let error as AuthenticationError {
            guard case .appAccessBiometricsLockedOut = error else {
                return XCTFail("Unexpected normalization: \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }
}
#endif
