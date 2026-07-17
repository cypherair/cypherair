#if os(macOS)
import Foundation
import XCTest
@testable import CypherAir

/// Short operation-prompt window — key provisioning: generate / import keep
/// long Rust work outside the session, and enroll only the Secure Enclave wrap
/// window so the wrap prompt's own sheet resign is deferred and decided at the
/// session's end.
@MainActor
final class KeyProvisioningOperationPromptCompositionTests: XCTestCase {
    /// Suspends inside an injected checkpoint and records whether the
    /// coordinator saw that checkpoint as part of an operation session.
    private final class CheckpointGate: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Never>?
        private var observedInSession: Bool?
        private var isArmed = true
        let suspendedExpectation = XCTestExpectation(description: "provisioning checkpoint suspended")
        private let coordinator: AuthenticationPromptCoordinator

        init(coordinator: AuthenticationPromptCoordinator) {
            self.coordinator = coordinator
        }

        var wasInOperationPromptSession: Bool? {
            lock.withLock { observedInSession }
        }

        /// The checkpoint suspends only on its first firing (provisioning a
        /// fixture key for the import test must not re-arm the gate).
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

    func test_generateKey_runsInsideOperationPromptSession_resignDeferred_thenLockedWhenStillAway() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount
        let gate = CheckpointGate(coordinator: harness.coordinator)
        let made = TestHelpers.makeKeyManagement(
            authenticationPromptCoordinator: harness.coordinator,
            provisioningWrappingPromptCheckpoint: gate.checkpoint
        )

        let action = Task {
            try await made.service.generateKey(
                name: "Provision Composition",
                email: nil,
                expirySeconds: nil,
                suite: .ed25519LegacyCurve25519Legacy
            )
        }
        await fulfillment(of: [gate.suspendedExpectation], timeout: 30)
        await harness.settle() // the session-began hop must land before the resign

        XCTAssertEqual(
            gate.wasInOperationPromptSession,
            true,
            "The key-generation SE wrap window must run inside an operation-prompt session."
        )

        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .unlocked,
            "A resign during the in-session wrap window is deferred, never a mid-action lock."
        )
        XCTAssertEqual(harness.relockCount, relocksBefore)

        gate.resume()
        let identity = try await action.value
        XCTAssertFalse(identity.fingerprint.isEmpty, "The action completes despite the deferred away.")

        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .locked,
            "Still away at the prompts' end -> the deferred away is processed fail-closed."
        )
        XCTAssertGreaterThan(harness.relockCount, relocksBefore)
    }

    func test_importKey_runsInsideOperationPromptSession_resignDiscardedWhenForegroundReturns() async throws {
        // Fixture: generate + export on a plain service, so only the import
        // under test runs against the gated checkpoint.
        let fixture = TestHelpers.makeKeyManagement()
        let original = try await fixture.service.generateKey(
            name: "Import Composition",
            email: nil,
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let passphrase = "import-composition-pass"
        let exported = try await fixture.service.exportKey(
            fingerprint: original.fingerprint,
            passphrase: passphrase
        )

        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount
        let gate = CheckpointGate(coordinator: harness.coordinator)
        let made = TestHelpers.makeKeyManagement(
            authenticationPromptCoordinator: harness.coordinator,
            provisioningWrappingPromptCheckpoint: gate.checkpoint
        )

        let action = Task {
            try await made.service.importKey(armoredData: exported, passphrase: passphrase)
        }
        await fulfillment(of: [gate.suspendedExpectation], timeout: 30)
        await harness.settle()

        XCTAssertEqual(
            gate.wasInOperationPromptSession,
            true,
            "The key-import SE wrap window must run inside an operation-prompt session."
        )

        harness.deliverResign()
        harness.deliverReturn() // it was the prompt's own resign: the user never left
        gate.resume()
        let imported = try await action.value
        XCTAssertEqual(imported.fingerprint, original.fingerprint)

        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .unlocked,
            "Foreground returned before the prompts' end -> the deferred away is discarded."
        )
        XCTAssertEqual(harness.relockCount, relocksBefore)
    }

    func test_generateKey_resignBeforeWrapWindowLocksImmediately() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount
        let gate = CheckpointGate(coordinator: harness.coordinator)
        let made = TestHelpers.makeKeyManagement(
            authenticationPromptCoordinator: harness.coordinator,
            provisioningCheckpoint: gate.checkpoint
        )

        let action = Task {
            try await made.service.generateKey(
                name: "Provision Outside Prompt",
                email: nil,
                expirySeconds: nil,
                suite: .ed25519LegacyCurve25519Legacy
            )
        }
        await fulfillment(of: [gate.suspendedExpectation], timeout: 30)

        XCTAssertEqual(
            gate.wasInOperationPromptSession,
            false,
            "The pre-wrap provisioning checkpoint must stay outside the operation-prompt session."
        )

        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .locked,
            "A genuine resign before the wrap prompt locks immediately at grace=0."
        )
        XCTAssertGreaterThan(harness.relockCount, relocksBefore)

        gate.resume()
        _ = try await action.value
    }
}
#endif
