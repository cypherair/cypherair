#if os(macOS)
import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Shared composition harness for short operation-prompt window tests: a REAL
/// `AuthenticationPromptCoordinator`
/// wired to a REAL `AppLockController` through the same `Task { @MainActor in }`
/// hop pattern `AppContainer.wireOperationPromptLifecycle` uses, with closure-spy
/// dependencies (grace 0, auto-success auth, relock counter).
///
/// This harness covers the composition seam that per-unit tests miss: a prompt
/// that runs OUTSIDE any operation-prompt session — and therefore would lock the
/// app mid-action on its own sheet resign — is invisible when the mutation flow
/// and the `.authenticating` rule are tested separately. Flow tests inject
/// `coordinator` into the production seam under test, suspend inside the prompt,
/// and use `deliverResign()` / `deliverReturn()` + `settle()` to drive the
/// deferred-away decision.
///
/// The controller also receives the coordinator's live operation-prompt state,
/// so tests cover the production fallback for begin/end main-actor hop lag.
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

    let coordinator: AuthenticationPromptCoordinator
    let state: State
    let controller: AppLockController

    var relockCount: Int { state.relockCount }
    var lockState: AppLockController.LockState { controller.lockState }

    init(gracePeriod: Int? = 0) {
        let coordinator = AuthenticationPromptCoordinator()
        let state = State()
        state.gracePeriod = gracePeriod
        self.coordinator = coordinator
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
            operationPromptInProgressProvider: { [weak coordinator] in
                coordinator?.isOperationPromptInProgress ?? false
            }
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
