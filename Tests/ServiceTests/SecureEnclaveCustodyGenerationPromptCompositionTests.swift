#if os(macOS)
import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Short operation-prompt window — Secure Enclave custody generation (P7D):
/// only custody authorization plus immediate handle loading runs inside the
/// session; certificate building and metadata commit stay outside it.
@MainActor
final class SecureEnclaveCustodyGenerationPromptCompositionTests: KeyManagementServiceTestCase {
    /// Suspends inside a checkpoint and records whether the coordinator saw
    /// that checkpoint as part of an operation session.
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

    func test_secureEnclaveGeneration_authorizationWindowResignDeferred_thenLockedWhenStillAway() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount
        let gate = GatedCustodyAuthenticator(coordinator: harness.coordinator)
        let target = makeHiddenSecureEnclaveGenerationService(
            authenticationPromptCoordinator: harness.coordinator,
            custodyOperationAuthenticator: gate.authenticate
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
            "The device-bound generation authorization window must run inside an operation-prompt session."
        )

        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .unlocked,
            "A resign during in-session custody authorization is deferred, never a mid-action lock."
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

    func test_secureEnclaveGeneration_postCommitResignLocksImmediately() async throws {
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
                name: "SE Custody Outside Prompt",
                email: nil,
                expirySeconds: nil,
                configurationIdentity: .compatibleP256V4
            )
        }
        await fulfillment(of: [gate.suspendedExpectation], timeout: 30)

        XCTAssertEqual(
            gate.wasInOperationPromptSession,
            false,
            "The post-identity-commit checkpoint must stay outside the operation-prompt session."
        )

        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(
            harness.lockState,
            .locked,
            "A genuine resign after the authorization window locks immediately at grace=0."
        )
        XCTAssertGreaterThan(harness.relockCount, relocksBefore)

        gate.resume()
        _ = try await action.value
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

    func test_secureEnclaveGeneration_custodyPreAuthenticationRunsInsideOperationPromptSession() async throws {
        // The custody pre-authentication and immediate handle load share one
        // short operation-prompt session, so the sheet's own resign is deferred
        // without covering the rest of generation.
        let coordinator = AuthenticationPromptCoordinator()
        let observer = SessionObservingCustodyAuthenticator(coordinator: coordinator)
        let target = makeHiddenSecureEnclaveGenerationService(
            authenticationPromptCoordinator: coordinator,
            custodyOperationAuthenticator: observer.authenticate
        )

        let identity = try await target.service.generateSecureEnclaveCustodyKey(
            name: "SE Custody P7F",
            email: nil,
            expirySeconds: nil,
            configurationIdentity: .compatibleP256V4
        )

        XCTAssertEqual(identity.privateKeyCustodyKind, .appleSecureEnclavePrivateOperations)
        XCTAssertEqual(observer.calls, 1)
        XCTAssertEqual(
            observer.sawOperationPromptInProgress,
            true,
            "The custody pre-authentication must run while the operation-prompt session is open."
        )
        XCTAssertEqual(observer.context.invalidateCount, 1)
    }
}

private final class SessionObservingCustodyAuthenticator: @unchecked Sendable {
    private let coordinator: AuthenticationPromptCoordinator
    private let lock = NSLock()
    private var callsStorage = 0
    private var sawOperationPromptInProgressStorage: Bool?
    let context = RecordingLAContext()

    init(coordinator: AuthenticationPromptCoordinator) {
        self.coordinator = coordinator
    }

    var calls: Int {
        lock.withLock { callsStorage }
    }

    var sawOperationPromptInProgress: Bool? {
        lock.withLock { sawOperationPromptInProgressStorage }
    }

    @Sendable func authenticate(_ reason: String) async throws -> LAContext {
        lock.withLock {
            callsStorage += 1
            sawOperationPromptInProgressStorage = coordinator.isOperationPromptInProgress
        }
        return context
    }
}

private final class GatedCustodyAuthenticator: @unchecked Sendable {
    private let coordinator: AuthenticationPromptCoordinator
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    private var observedInSession: Bool?
    let context = RecordingLAContext()
    let suspendedExpectation = XCTestExpectation(description: "custody authorization suspended")

    init(coordinator: AuthenticationPromptCoordinator) {
        self.coordinator = coordinator
    }

    var wasInOperationPromptSession: Bool? {
        lock.withLock { observedInSession }
    }

    @Sendable func authenticate(_ reason: String) async throws -> LAContext {
        lock.withLock {
            observedInSession = coordinator.isOperationPromptInProgress
        }
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
#endif
