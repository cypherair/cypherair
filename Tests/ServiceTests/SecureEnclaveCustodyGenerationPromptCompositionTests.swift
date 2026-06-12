#if os(macOS)
import Foundation
import XCTest
@testable import CypherAir

/// Uniform enrollment rule — Secure Enclave custody generation (P7D): the
/// whole device-bound generation runs inside one operation-prompt session, so
/// the biometryAny digest-signing prompts' own sheet resign is deferred and
/// decided at the session's end (mirrors KeyProvisioningOperationPromptCompositionTests).
@MainActor
final class SecureEnclaveCustodyGenerationPromptCompositionTests: KeyManagementServiceTestCase {
    /// Suspends inside the post-identity-commit checkpoint so the test can
    /// deliver a resign mid-action, recording whether the coordinator saw the
    /// action as an operation session.
    private final class CheckpointGate: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Never>?
        private var observedInSession: Bool?
        private var isArmed = true
        let suspendedExpectation = XCTestExpectation(description: "generation checkpoint suspended")
        private let coordinator: AuthenticationPromptCoordinator

        init(coordinator: AuthenticationPromptCoordinator) {
            self.coordinator = coordinator
        }

        var wasInOperationPromptSession: Bool? {
            lock.withLock { observedInSession }
        }

        @Sendable func checkpoint() async {
            let shouldSuspend = lock.withLock {
                guard isArmed else { return false }
                isArmed = false
                observedInSession = coordinator.isOperationPromptInProgress
                return true
            }
            guard shouldSuspend else { return }
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                lock.withLock { continuation = cont }
                suspendedExpectation.fulfill()
            }
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

    func test_secureEnclaveGeneration_runsInsideOperationPromptSession_resignDeferred_thenLockedWhenStillAway() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount
        let gate = CheckpointGate(coordinator: harness.coordinator)
        let target = makeHiddenSecureEnclaveGenerationService(
            authenticationPromptCoordinator: harness.coordinator,
            afterIdentityCommitCheckpoint: gate.checkpoint
        )

        let action = Task { [service = target.service] in
            try await service.generateSecureEnclaveCustodyKey(
                name: "SE Custody Composition",
                email: nil,
                expirySeconds: nil,
                configurationIdentity: .compatibleP256V4
            )
        }
        await fulfillment(of: [gate.suspendedExpectation], timeout: 30)
        await harness.settle() // the session-began hop must land before the resign

        XCTAssertEqual(
            gate.wasInOperationPromptSession,
            true,
            "Device-bound generation must run inside an operation-prompt session (the uniform rule)."
        )

        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .unlocked,
            "A resign during in-session generation is deferred, never a mid-action lock."
        )
        XCTAssertEqual(harness.relockCount, relocksBefore)

        gate.resume()
        let identity = try await action.value
        XCTAssertEqual(identity.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)

        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .locked,
            "Still away at the prompts' end -> the deferred away is processed fail-closed."
        )
        XCTAssertGreaterThan(harness.relockCount, relocksBefore)
    }

    func test_secureEnclaveGeneration_withoutCoordinator_stillGenerates() async throws {
        // Back-compat composition: rigs without a coordinator (and any caller
        // that has not wired one) must keep working — enrollment is additive.
        let target = makeHiddenSecureEnclaveGenerationService()

        let identity = try await target.service.generateSecureEnclaveCustodyKey(
            name: "SE Custody Plain",
            email: nil,
            expirySeconds: nil,
            configurationIdentity: .compatibleP256V4
        )

        XCTAssertEqual(identity.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)
    }
}
#endif
