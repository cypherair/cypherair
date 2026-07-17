import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// App Access Protection policy switch branch logic of
/// `AppAccessPolicySwitchWorkflow`, plus the macOS composition pin that the
/// authentication / reprotection window runs inside one operation-prompt session.
@MainActor
final class AppAccessPolicySwitchWorkflowTests: XCTestCase {
    private final class TrackingLAContext: LAContext {
        private(set) var invalidateCount = 0
        override func invalidate() {
            invalidateCount += 1
            super.invalidate()
        }
    }

    private final class Spy {
        var currentPolicy: AppSessionAuthenticationPolicy = .userPresence
        var hasRootSecret = true
        var canEvaluateResult = true
        var authResult: AppSessionAuthenticationResult = .failed
        var onEvaluate: (() async -> Void)?
        private(set) var operationLog: [String] = []
        private(set) var evaluatedPolicies: [AppSessionAuthenticationPolicy] = []
        private(set) var reprotectCalls: [(AppSessionAuthenticationPolicy, AppSessionAuthenticationPolicy)] = []

        func evaluate(
            _ policy: AppSessionAuthenticationPolicy
        ) async -> AppSessionAuthenticationResult {
            operationLog.append("evaluate")
            evaluatedPolicies.append(policy)
            await onEvaluate?()
            return authResult
        }

        func reprotect(_ from: AppSessionAuthenticationPolicy, _ to: AppSessionAuthenticationPolicy) {
            operationLog.append("reprotect")
            reprotectCalls.append((from, to))
        }

        func discard() {
            operationLog.append("discard")
        }
    }

    private func makeWorkflow(
        spy: Spy,
        coordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator()
    ) -> AppAccessPolicySwitchWorkflow {
        AppAccessPolicySwitchWorkflow(
            currentPolicy: { spy.currentPolicy },
            hasPersistedRootSecret: { spy.hasRootSecret },
            canEvaluate: { _ in spy.canEvaluateResult },
            evaluateAppSession: { policy, reason, source in
                XCTAssertFalse(reason.isEmpty)
                XCTAssertEqual(source, "appAccessPolicy.switch")
                return await spy.evaluate(policy)
            },
            reprotectPersistedRootSecret: { from, to, _ in
                spy.reprotect(from, to)
            },
            discardHandoffContextForPolicyChange: {
                spy.discard()
            },
            authenticationPromptCoordinator: coordinator,
            traceStore: AuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        )
    }

    func test_run_withRootSecret_evaluatesStrictestPolicy_thenReprotects_thenDiscards() async throws {
        let spy = Spy()
        let context = TrackingLAContext()
        spy.authResult = .authenticated(context: context)
        let workflow = makeWorkflow(spy: spy)

        try await workflow.run(to: .biometricsOnly)

        XCTAssertEqual(spy.operationLog, ["evaluate", "reprotect", "discard"])
        XCTAssertEqual(
            spy.evaluatedPolicies,
            [AppSessionAuthenticationPolicy.strictestPolicyForRootSecretReprotection(
                from: .userPresence,
                to: .biometricsOnly
            )]
        )
        XCTAssertEqual(spy.reprotectCalls.count, 1)
        XCTAssertEqual(spy.reprotectCalls[0].0, .userPresence)
        XCTAssertEqual(spy.reprotectCalls[0].1, .biometricsOnly)
        XCTAssertEqual(context.invalidateCount, 1, "The authenticated context is invalidated exactly once.")
    }

    func test_run_noChange_isANoOp() async throws {
        let spy = Spy()
        let workflow = makeWorkflow(spy: spy)

        try await workflow.run(to: .userPresence)

        XCTAssertTrue(spy.operationLog.isEmpty)
    }

    func test_run_failedAuthentication_throwsAndTouchesNothing() async {
        let spy = Spy()
        spy.authResult = .failed
        let workflow = makeWorkflow(spy: spy)

        do {
            try await workflow.run(to: .biometricsOnly)
            XCTFail("Expected AuthenticationError.failed")
        } catch AuthenticationError.failed {
        } catch {
            XCTFail("Expected AuthenticationError.failed, got \(error)")
        }

        XCTAssertEqual(spy.operationLog, ["evaluate"], "No reprotect, no discard after a failed prompt.")
    }

    func test_run_withoutRootSecret_discardsWithoutPrompt() async throws {
        let spy = Spy()
        spy.hasRootSecret = false
        let workflow = makeWorkflow(spy: spy)

        try await workflow.run(to: .biometricsOnly)

        XCTAssertEqual(spy.operationLog, ["discard"], "No prompt when there is no root secret to re-protect.")
    }

    func test_run_withoutRootSecret_biometricsUnavailable_throws() async {
        let spy = Spy()
        spy.hasRootSecret = false
        spy.canEvaluateResult = false
        let workflow = makeWorkflow(spy: spy)

        do {
            try await workflow.run(to: .biometricsOnly)
            XCTFail("Expected appAccessBiometricsUnavailable")
        } catch AuthenticationError.appAccessBiometricsUnavailable {
        } catch {
            XCTFail("Expected appAccessBiometricsUnavailable, got \(error)")
        }

        XCTAssertTrue(spy.operationLog.isEmpty)
    }

    #if os(macOS)
    func test_run_insideOperationPromptSession_resignDeferredAndDecidedAtPromptsEnd() async throws {
        let harness = OperationPromptLockHarness(gracePeriod: 0)
        await harness.unlockForTest()
        let relocksBefore = harness.relockCount

        let spy = Spy()
        spy.authResult = .authenticated(context: LAContext())
        let workflow = makeWorkflow(spy: spy, coordinator: harness.coordinator)

        let promptOpen = expectation(description: "policy-switch prompt open")
        let gate = AsyncGate()
        var observedInSession: Bool?
        spy.onEvaluate = {
            observedInSession = harness.coordinator.isOperationPromptInProgress
            promptOpen.fulfill()
            await gate.wait()
        }

        let action = Task {
            try await workflow.run(to: .biometricsOnly)
        }
        await fulfillment(of: [promptOpen], timeout: 10)
        await harness.settle() // the session-began hop must land before the resign

        XCTAssertEqual(
            observedInSession,
            true,
            "The policy-switch prompt must run inside an operation-prompt session."
        )

        harness.deliverResign()
        await harness.settle()
        XCTAssertEqual(harness.lockState, .unlocked, "Deferred, never a mid-action lock.")
        XCTAssertEqual(harness.relockCount, relocksBefore)

        gate.open()
        try await action.value
        await harness.settle()
        XCTAssertEqual(harness.lockState, .locked, "Still away at the prompts' end -> fail-closed lock.")
        XCTAssertGreaterThan(harness.relockCount, relocksBefore)
    }

    /// Minimal main-actor gate for suspending a stub mid-action.
    private final class AsyncGate {
        private var continuation: CheckedContinuation<Void, Never>?
        private var isOpen = false

        func wait() async {
            if isOpen { return }
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                continuation = cont
            }
        }

        func open() {
            isOpen = true
            let cont = continuation
            continuation = nil
            cont?.resume()
        }
    }
    #endif
}
