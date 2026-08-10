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

    private struct SwitchStepFailure: Error {}

    private final class Spy {
        var currentPolicy: AppSessionAuthenticationPolicy = .userPresence
        var hasRootSecret = true
        var canEvaluateResult = true
        var authResult: AppSessionAuthenticationResult = .failed
        var onEvaluate: (() async -> Void)?
        var reprotectError: Error?
        private(set) var operationLog: [String] = []
        private(set) var evaluatedPolicies: [AppSessionAuthenticationPolicy] = []
        private(set) var reprotectCalls: [(AppSessionAuthenticationPolicy, AppSessionAuthenticationPolicy)] = []
        /// Mirrors the persisted journal: the target recorded before the
        /// Keychain gate moves, cleared by the commit.
        private(set) var journaledTarget: AppSessionAuthenticationPolicy?
        private(set) var committedPolicies: [AppSessionAuthenticationPolicy] = []

        func evaluate(
            _ policy: AppSessionAuthenticationPolicy
        ) async -> AppSessionAuthenticationResult {
            operationLog.append("evaluate")
            evaluatedPolicies.append(policy)
            await onEvaluate?()
            return authResult
        }

        func beginJournal(_ target: AppSessionAuthenticationPolicy) {
            operationLog.append("journal")
            journaledTarget = target
        }

        func reprotect(_ from: AppSessionAuthenticationPolicy, _ to: AppSessionAuthenticationPolicy) throws {
            operationLog.append("reprotect")
            reprotectCalls.append((from, to))
            if let reprotectError {
                throw reprotectError
            }
        }

        func commit(_ target: AppSessionAuthenticationPolicy) {
            operationLog.append("commit")
            committedPolicies.append(target)
            currentPolicy = target
            journaledTarget = nil
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
            evaluateAppSession: { policy, reason in
                XCTAssertFalse(reason.isEmpty)
                return await spy.evaluate(policy)
            },
            beginPolicySwitchJournal: { target in
                spy.beginJournal(target)
            },
            reprotectPersistedRootSecret: { from, to, _ in
                try spy.reprotect(from, to)
            },
            commitPolicySwitch: { target in
                spy.commit(target)
            },
            discardHandoffContextForPolicyChange: {
                spy.discard()
            },
            authenticationPromptCoordinator: coordinator
        )
    }

    func test_run_withRootSecret_evaluatesStrictestPolicy_thenReprotects_thenDiscards() async throws {
        let spy = Spy()
        let context = TrackingLAContext()
        spy.authResult = .authenticated(context: context)
        let workflow = makeWorkflow(spy: spy)

        try await workflow.run(to: .biometricsOnly)

        // The journal opens before the Keychain gate moves and the preference is
        // committed only after it has moved — the ordering issue #747 depends on.
        XCTAssertEqual(spy.operationLog, ["evaluate", "journal", "reprotect", "commit", "discard"])
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
        XCTAssertEqual(spy.committedPolicies, [.biometricsOnly])
        XCTAssertNil(spy.journaledTarget, "A completed switch leaves no recorded intent.")
        XCTAssertEqual(context.invalidateCount, 1, "The authenticated context is invalidated exactly once.")
    }

    /// A re-protection failure cannot tell whether the access-control update
    /// landed before it threw, so the intent must survive: the effective policy
    /// stays the stricter of the pair and the next authenticated launch
    /// converges the two stores (issue #747).
    func test_run_failedReprotection_keepsJournalOpenAndDoesNotCommit() async {
        let spy = Spy()
        spy.authResult = .authenticated(context: TrackingLAContext())
        spy.reprotectError = SwitchStepFailure()
        let workflow = makeWorkflow(spy: spy)

        do {
            try await workflow.run(to: .biometricsOnly)
            XCTFail("Expected the re-protection failure to propagate")
        } catch is SwitchStepFailure {
        } catch {
            XCTFail("Expected SwitchStepFailure, got \(error)")
        }

        XCTAssertEqual(spy.operationLog, ["evaluate", "journal", "reprotect"])
        XCTAssertEqual(spy.journaledTarget, .biometricsOnly)
        XCTAssertTrue(spy.committedPolicies.isEmpty)
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
        XCTAssertNil(
            spy.journaledTarget,
            "A cancelled prompt mutates nothing, so it must not leave an intent a later launch would replay."
        )
    }

    func test_run_withoutRootSecret_discardsWithoutPrompt() async throws {
        let spy = Spy()
        spy.hasRootSecret = false
        let workflow = makeWorkflow(spy: spy)

        try await workflow.run(to: .biometricsOnly)

        XCTAssertEqual(
            spy.operationLog,
            ["commit", "discard"],
            "No prompt when there is no root secret to re-protect, and no gate to journal against."
        )
        XCTAssertEqual(spy.committedPolicies, [.biometricsOnly])
        XCTAssertNil(spy.journaledTarget)
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

    // MARK: - Launch-time convergence (issue #747)

    private func makeIsolatedConfig() -> AppConfiguration {
        let suiteName = "com.cypherair.tests.appaccesspolicyrecovery.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        addTeardownBlock {
            UserDefaults(suiteName: suiteName)?.removePersistentDomain(forName: suiteName)
        }
        return AppConfiguration(defaults: defaults)
    }

    func test_recovery_interruptedSwitch_reprotectsToTargetAndCommits() {
        let config = makeIsolatedConfig()
        config.beginAppSessionAuthenticationPolicySwitch(to: .biometricsOnly)
        var reprotectCalls: [(AppSessionAuthenticationPolicy, AppSessionAuthenticationPolicy)] = []

        AppAccessPolicySwitchRecovery.recover(
            config: config,
            authenticationContext: LAContext(),
            reprotectPersistedRootSecretIfPresent: { from, to, _ in
                reprotectCalls.append((from, to))
                return true
            }
        )

        XCTAssertEqual(reprotectCalls.count, 1)
        XCTAssertEqual(reprotectCalls[0].0, .userPresence)
        XCTAssertEqual(reprotectCalls[0].1, .biometricsOnly)
        XCTAssertEqual(config.committedAppSessionAuthenticationPolicy, .biometricsOnly)
        XCTAssertNil(config.pendingAppSessionAuthenticationPolicySwitch)
    }

    /// A failed re-protection must not clear the journal — clearing it blind is
    /// exactly the silent disagreement the journal exists to record.
    func test_recovery_failedReprotection_leavesJournalOpenAndPolicyStricter() {
        let config = makeIsolatedConfig()
        config.beginAppSessionAuthenticationPolicySwitch(to: .biometricsOnly)

        AppAccessPolicySwitchRecovery.recover(
            config: config,
            authenticationContext: LAContext(),
            reprotectPersistedRootSecretIfPresent: { _, _, _ in
                throw SwitchStepFailure()
            }
        )

        XCTAssertEqual(config.pendingAppSessionAuthenticationPolicySwitch, .biometricsOnly)
        XCTAssertEqual(config.committedAppSessionAuthenticationPolicy, .userPresence)
        XCTAssertEqual(
            config.appSessionAuthenticationPolicy,
            .biometricsOnly,
            "The effective policy stays the stricter of the pair until the two stores agree."
        )
    }

    /// Only the journal clear was lost: both stores already name the target, so
    /// the Keychain gate must not be touched again.
    func test_recovery_commitGapState_finishesBookkeepingWithoutReprotecting() {
        let config = makeIsolatedConfig()
        config.completeAppSessionAuthenticationPolicySwitch(to: .biometricsOnly)
        config.beginAppSessionAuthenticationPolicySwitch(to: .biometricsOnly)
        var reprotectCalled = false

        AppAccessPolicySwitchRecovery.recover(
            config: config,
            authenticationContext: LAContext(),
            reprotectPersistedRootSecretIfPresent: { _, _, _ in
                reprotectCalled = true
                return true
            }
        )

        XCTAssertFalse(reprotectCalled)
        XCTAssertNil(config.pendingAppSessionAuthenticationPolicySwitch)
        XCTAssertEqual(config.committedAppSessionAuthenticationPolicy, .biometricsOnly)
    }

    func test_recovery_withoutJournal_isANoOp() {
        let config = makeIsolatedConfig()
        var reprotectCalled = false

        AppAccessPolicySwitchRecovery.recover(
            config: config,
            authenticationContext: LAContext(),
            reprotectPersistedRootSecretIfPresent: { _, _, _ in
                reprotectCalled = true
                return true
            }
        )

        XCTAssertFalse(reprotectCalled)
        XCTAssertEqual(config.appSessionAuthenticationPolicy, .userPresence)
        XCTAssertNil(config.pendingAppSessionAuthenticationPolicySwitch)
    }

    /// No persisted root secret means no gate to converge with; the journal
    /// still clears so the preference stops reading as the stricter policy.
    func test_recovery_withoutPersistedRootSecret_commitsTarget() {
        let config = makeIsolatedConfig()
        config.completeAppSessionAuthenticationPolicySwitch(to: .biometricsOnly)
        config.beginAppSessionAuthenticationPolicySwitch(to: .userPresence)

        AppAccessPolicySwitchRecovery.recover(
            config: config,
            authenticationContext: LAContext(),
            reprotectPersistedRootSecretIfPresent: { _, _, _ in false }
        )

        XCTAssertEqual(config.appSessionAuthenticationPolicy, .userPresence)
        XCTAssertNil(config.pendingAppSessionAuthenticationPolicySwitch)
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
