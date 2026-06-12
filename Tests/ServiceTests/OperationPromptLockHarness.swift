#if os(macOS)
import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Shared composition harness for the uniform operation-prompt enrollment tests
/// (P3′ stage 2′ + the uniform rule): a REAL `AuthenticationPromptCoordinator`
/// wired to a REAL `AppLockController` through the same `Task { @MainActor in }`
/// hop pattern `AppContainer.wireOperationPromptLifecycle` uses, with closure-spy
/// dependencies (grace 0, auto-success auth, relock counter).
///
/// This is the test class that was missing when #495 shipped: unit tests covered
/// the mutation flow and the `.authenticating` rule separately, so a prompt that
/// ran OUTSIDE any operation-prompt session — and therefore locked the app
/// mid-action on its own sheet resign — was invisible to both. Flow tests inject
/// `coordinator` into the production seam under test, suspend inside the prompt,
/// and use `deliverResign()` / `deliverReturn()` + `settle()` to drive the
/// deferred-away decision.
///
/// Usage gotcha: always `settle()` AFTER the in-flow stub signals it is running
/// and BEFORE `deliverResign()`. The mirror opens only when the session-began
/// hop lands on the main actor; a resign delivered before that is processed as
/// a genuine away (designed fail-closed), which makes the test flaky, not the
/// production code wrong.
@MainActor
final class OperationPromptLockHarness {
    /// Captured by the controller's closures; holds no reference back to the
    /// harness or controller, so there is no retain cycle.
    final class State {
        var gracePeriod: Int? = 0
        private(set) var relockCount = 0
        private(set) var contentClearCount = 0
        func relock() { relockCount += 1 }
        func contentClear() { contentClearCount += 1 }
    }

    let coordinator = AuthenticationPromptCoordinator()
    let state: State
    let controller: AppLockController

    var relockCount: Int { state.relockCount }
    var lockState: AppLockController.LockState { controller.lockState }

    init(gracePeriod: Int? = 0) {
        let state = State()
        state.gracePeriod = gracePeriod
        self.state = state
        let controller = AppLockController(
            gracePeriodProvider: { state.gracePeriod },
            lastAuthenticationDateProvider: { nil },
            evaluateAppSessionAuthentication: { _, _ in .authenticated(context: nil) },
            recordSuccessfulAuthentication: { _ in },
            discardHandoffContext: { _ in },
            relockProtectedData: { state.relock() },
            postAuthenticationHandler: { _, _ in },
            contentClearHandler: { state.contentClear() },
            shouldBypassAuthentication: { false },
            traceStore: AuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        )
        self.controller = controller

        // Replicates AppContainer.wireOperationPromptLifecycle verbatim: the
        // hooks fire on the thread that adjusted the prompt depth and hop to
        // the main actor; the controller's session counter is what
        // handleAwayEvent consults.
        coordinator.onOperationPromptSessionBegan = { [weak controller] in
            Task { @MainActor in
                controller?.handleOperationPromptSessionBegan()
            }
        }
        coordinator.onOperationPromptsEnded = { [weak controller] in
            Task { @MainActor in
                controller?.handleOperationPromptsEnded()
            }
        }
    }

    /// Drain a bounded number of main-actor hops so the coordinator's
    /// session-began/ended hops and fire-and-forget lock `Task`s settle
    /// deterministically (the `AppLockControllerTests.settle()` pattern).
    func settle() async {
        for _ in 0..<20 {
            await Task.yield()
        }
    }

    /// Drive the controller to `.unlocked` (auto-success auth stub).
    func unlockForTest() async {
        await controller.handleForegroundActive(source: "harness.boot")
        await settle()
    }

    /// A macOS resign-active delivered while (presumably) a session is open.
    func deliverResign(source: String = "macResignActive") {
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: source)
    }

    /// The user comes back before the session ends: only the foreground-active
    /// signal matters for the deferred-away decision at the prompts' end.
    func deliverReturn() {
        controller.noteForegroundActive(true)
    }
}
#endif
