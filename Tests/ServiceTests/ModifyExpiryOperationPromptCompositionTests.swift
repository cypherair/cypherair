#if os(macOS)
import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

/// The composition regression test: lock controller + prompt coordinator + the
/// actual modify-expiry flow, asserting the pre-authentication runs INSIDE an
/// operation-prompt session and that a resign delivered during it is deferred
/// (the app stays unlocked mid-action) and decided at the prompts' end.
@MainActor
final class ModifyExpiryOperationPromptCompositionTests: XCTestCase {
    /// Suspends inside the pre-auth so the test can deliver a resign while the
    /// "system sheet" is up, and records whether the coordinator saw the prompt
    /// as part of an operation session.
    private final class GatedExpiryAuthenticator: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Never>?
        private var observedInSession: Bool?
        let context = LAContext()
        let suspendedExpectation = XCTestExpectation(description: "expiry pre-auth suspended")
        private let coordinator: AuthenticationPromptCoordinator

        init(coordinator: AuthenticationPromptCoordinator) {
            self.coordinator = coordinator
        }

        var wasInOperationPromptSession: Bool? {
            lock.withLock { observedInSession }
        }

        func authenticate(_: SecAccessControl, _: String) async throws -> LAContext {
            let inSession = coordinator.isOperationPromptInProgress
            lock.withLock { observedInSession = inSession }
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                lock.withLock { continuation = cont }
                suspendedExpectation.fulfill()
            }
            return context
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

    private func makeFlow(
        harness: OperationPromptLockHarness
    ) async throws -> (
        made: (
            service: KeyManagementService,
            mockSE: MockSecureEnclave,
            mockKC: MockKeychain,
            mockAuth: MockAuthenticator,
            metadataPersistence: any KeyMetadataPersistence
        ),
        stub: GatedExpiryAuthenticator,
        fingerprint: String
    ) {
        let stub = GatedExpiryAuthenticator(coordinator: harness.coordinator)
        let made = TestHelpers.makeKeyManagement(
            authenticationPromptCoordinator: harness.coordinator,
            expiryAuthenticator: stub.authenticate
        )
        let identity = try await made.service.generateKey(
            name: "Composition",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        return (made, stub, identity.fingerprint)
    }

    func test_preAuthRunsInsideOperationPromptSession_resignDeferred_thenLockedWhenStillAway() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        let flow = try await makeFlow(harness: harness)
        await harness.unlockForTest()
        XCTAssertEqual(harness.lockState, .unlocked)
        let relocksBefore = harness.relockCount

        let action = Task {
            try await flow.made.service.modifyExpiry(
                fingerprint: flow.fingerprint,
                newExpirySeconds: 60 * 60
            )
        }
        await fulfillment(of: [flow.stub.suspendedExpectation], timeout: 10)
        await harness.settle() // the session-began hop must land before the resign

        XCTAssertEqual(
            flow.stub.wasInOperationPromptSession,
            true,
            "The pre-authentication must run inside an operation-prompt session."
        )

        // The pre-auth sheet's own resign arrives while the prompt is up.
        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .unlocked,
            "A resign during the in-session pre-auth is deferred, never a mid-action lock."
        )
        XCTAssertEqual(harness.relockCount, relocksBefore, "No relock before the deferred decision.")

        flow.stub.resume()
        let updated = try await action.value
        XCTAssertEqual(updated.fingerprint, flow.fingerprint, "The action completes despite the deferred away.")

        await harness.settle() // the session-ended hop lands: the deferral is decided
        XCTAssertEqual(
            harness.lockState,
            .locked,
            "Still away at the prompts' end -> the deferred away is processed fail-closed."
        )
        XCTAssertGreaterThan(harness.relockCount, relocksBefore)
    }

    func test_preAuthResignDiscarded_whenForegroundReturnsBeforePromptsEnd() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        let flow = try await makeFlow(harness: harness)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount

        let action = Task {
            try await flow.made.service.modifyExpiry(
                fingerprint: flow.fingerprint,
                newExpirySeconds: 60 * 60
            )
        }
        await fulfillment(of: [flow.stub.suspendedExpectation], timeout: 10)
        await harness.settle()

        harness.deliverResign()
        harness.deliverReturn() // it was the prompt's own resign: the user never left
        flow.stub.resume()
        _ = try await action.value
        await harness.settle()

        XCTAssertEqual(
            harness.lockState,
            .unlocked,
            "Foreground returned before the prompts' end -> the deferred away is discarded."
        )
        XCTAssertEqual(harness.relockCount, relocksBefore)
    }
}
#endif
