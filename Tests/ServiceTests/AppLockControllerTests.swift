import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class AppLockControllerTests: XCTestCase {
    // MARK: - Spy (captured by the controller's closures; holds no reference to
    // the controller, so there is no retain cycle).

    final class Spy {
        var gracePeriod: Int? = 0
        var lastAuthenticationDate: Date?
        var bypass = false
        var operationPromptActive = false

        /// Outcome the auth stub returns (once unpaused).
        var authOutcome: Result<AppSessionAuthenticationResult, Error> = .success(.authenticated(context: nil))
        /// When true, the auth stub suspends until `resumeAuth()` is called.
        var pauseAuth = false
        var authContinuation: CheckedContinuation<Void, Never>?
        /// Invoked (on the main actor) the moment the auth stub suspends.
        var onAuthSuspended: (() -> Void)?

        /// When true, the post-auth handler suspends until `resumePostAuth()` is called.
        var pausePostAuth = false
        var postAuthContinuation: CheckedContinuation<Void, Never>?
        /// Invoked (on the main actor) the moment the post-auth handler suspends.
        var onPostAuthSuspended: (() -> Void)?

        /// Ordered log of the controller's fail-closed steps, for ordering assertions.
        private(set) var operationLog: [String] = []

        private(set) var evaluateCount = 0
        private(set) var evaluateReasons: [String] = []
        private(set) var recordedContexts: [LAContext?] = []
        private(set) var discardReasons: [String] = []
        private(set) var relockCount = 0
        private(set) var postAuthCount = 0
        private(set) var postAuthContexts: [LAContext?] = []
        private(set) var contentClearCount = 0

        func evaluate(reason: String) async throws -> AppSessionAuthenticationResult {
            evaluateCount += 1
            evaluateReasons.append(reason)
            operationLog.append("evaluate")
            if pauseAuth {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    authContinuation = continuation
                    onAuthSuspended?()
                }
            }
            return try authOutcome.get()
        }

        func resumeAuth() {
            let continuation = authContinuation
            authContinuation = nil
            continuation?.resume()
        }

        func recordSuccessful(_ context: LAContext?) {
            recordedContexts.append(context)
            operationLog.append("record")
        }
        func discard(_ reason: String) { discardReasons.append(reason) }
        func relock() async {
            relockCount += 1
            operationLog.append("relock")
        }
        func postAuth(_ context: LAContext?, _ source: String) async {
            postAuthCount += 1
            postAuthContexts.append(context)
            operationLog.append("postAuth")
            if pausePostAuth {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    postAuthContinuation = continuation
                    onPostAuthSuspended?()
                }
            }
        }
        func resumePostAuth() {
            let continuation = postAuthContinuation
            postAuthContinuation = nil
            continuation?.resume()
        }
        func contentClear() {
            contentClearCount += 1
            operationLog.append("contentClear")
        }
    }

    private func makeController(spy: Spy) -> AppLockController {
        AppLockController(
            gracePeriodProvider: { spy.gracePeriod },
            lastAuthenticationDateProvider: { spy.lastAuthenticationDate },
            evaluateAppSessionAuthentication: { reason, _ in try await spy.evaluate(reason: reason) },
            recordSuccessfulAuthentication: { spy.recordSuccessful($0) },
            discardHandoffContext: { spy.discard($0) },
            relockProtectedData: { await spy.relock() },
            postAuthenticationHandler: { await spy.postAuth($0, $1) },
            contentClearHandler: { spy.contentClear() },
            shouldBypassAuthentication: { spy.bypass },
            isOperationPromptActive: { spy.operationPromptActive },
            traceStore: AuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        )
    }

    /// Drain a bounded number of main-actor hops so fire-and-forget `Task`s
    /// (`lockNow` / interval-0 `handleAwayEvent`) settle deterministically.
    private func settle() async {
        for _ in 0..<20 {
            await Task.yield()
        }
    }

    // MARK: - Boot / happy path

    func test_bootsLocked_failClosed() {
        let controller = makeController(spy: Spy())
        XCTAssertEqual(controller.lockState, .locked)
        XCTAssertTrue(controller.isLocked)
        XCTAssertFalse(controller.isAuthenticating)
        XCTAssertNil(controller.authenticationFailure)
    }

    func test_foregroundActive_fromLocked_unlocksAndHandsOffContext() async {
        let spy = Spy()
        let context = LAContext()
        spy.authOutcome = .success(.authenticated(context: context))
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive(source: "test")

        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)
        XCTAssertEqual(spy.relockCount, 1, "Unlock must relock before prompting (fail-closed).")
        XCTAssertEqual(spy.contentClearCount, 1)
        XCTAssertEqual(spy.recordedContexts.count, 1)
        XCTAssertTrue(spy.recordedContexts.first.flatMap { $0 } === context)
        XCTAssertEqual(spy.postAuthCount, 1)
        XCTAssertTrue(spy.postAuthContexts.first.flatMap { $0 } === context)
        XCTAssertEqual(
            spy.operationLog,
            ["contentClear", "relock", "evaluate", "record", "postAuth"],
            "Fail-closed ordering: relock before the prompt; post-auth after the context is recorded."
        )
    }

    func test_foregroundActive_authReturnsFalse_entersAuthenticationFailed() async {
        let spy = Spy()
        spy.authOutcome = .success(.failed)
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive(source: "test")

        XCTAssertEqual(controller.lockState, .authenticationFailed(.authenticationFailed))
        XCTAssertTrue(controller.isLocked)
        XCTAssertEqual(spy.recordedContexts.count, 0, "A failed auth must not record/hand off a context.")
        XCTAssertTrue(spy.discardReasons.contains("authReturnedFalse"))
    }

    func test_foregroundActive_authThrowsBiometricsLockedOut_mapsReason() async {
        let spy = Spy()
        spy.authOutcome = .failure(AuthenticationError.appAccessBiometricsLockedOut)
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive(source: "test")

        XCTAssertEqual(controller.lockState, .authenticationFailed(.biometricsLockedOut))
        XCTAssertEqual(controller.authenticationFailure, .biometricsLockedOut)
        XCTAssertEqual(spy.recordedContexts.count, 0)
    }

    func test_foregroundActive_authThrowsLABiometryLockout_mapsToLockedOut() async {
        let spy = Spy()
        spy.authOutcome = .failure(LAError(.biometryLockout))
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive(source: "test")

        XCTAssertEqual(controller.authenticationFailure, .biometricsLockedOut)
    }

    func test_foregroundActive_authThrowsGenericError_mapsToAuthenticationFailed() async {
        let spy = Spy()
        spy.authOutcome = .failure(AuthenticationError.cancelled)
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive(source: "test")

        XCTAssertEqual(controller.authenticationFailure, .authenticationFailed)
    }

    func test_retryUnlock_fromFailed_succeeds() async {
        let spy = Spy()
        spy.authOutcome = .success(.failed)
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "test")
        XCTAssertEqual(controller.authenticationFailure, .authenticationFailed)

        spy.authOutcome = .success(.authenticated(context: nil))
        await controller.retryUnlock(source: "test")

        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 2)
    }

    // MARK: - Grace

    func test_foregroundActive_whenUnlockedWithinGrace_doesNotReauthenticate() async {
        let spy = Spy()
        spy.gracePeriod = 180
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)

        // First unlock.
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive(source: "first")
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)

        // A foreground round-trip inside the grace window stays unlocked.
        await controller.handleForegroundActive(source: "withinGrace")
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1, "No re-auth within the grace window (cover ≠ lock).")
    }

    func test_foregroundActive_whenUnlockedButGraceExpired_reauthenticates() async {
        let spy = Spy()
        spy.gracePeriod = 60
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive(source: "first")
        XCTAssertEqual(spy.evaluateCount, 1)

        // Last auth is well past the grace window, and a genuine away (non-zero interval
        // → deferred, stays unlocked) precedes the resume — re-auth requires a genuine
        // resume, not a spurious `.active`.
        spy.lastAuthenticationDate = Date(timeIntervalSinceNow: -600)
        controller.handleAwayEvent(source: "background")
        await settle()
        await controller.handleForegroundActive(source: "graceExpired")
        XCTAssertEqual(spy.evaluateCount, 2)
    }

    func test_failClosedGrace_nilProviderTreatedAsImmediate() async {
        let spy = Spy()
        spy.gracePeriod = nil
        spy.lastAuthenticationDate = Date()
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "first")
        XCTAssertEqual(controller.lockState, .unlocked)

        // nil grace → 0 → a genuine away locks immediately, and the next resume
        // re-authenticates (nil treated as Immediately).
        controller.handleAwayEvent(source: "background")
        await settle()
        XCTAssertEqual(controller.lockState, .locked)
        await controller.handleForegroundActive(source: "again")
        XCTAssertEqual(spy.evaluateCount, 2)
    }

    // MARK: - Bypass

    func test_bypass_goesStraightToUnlocked_withoutAuth() async {
        let spy = Spy()
        spy.bypass = true
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "test")
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 0)
        XCTAssertEqual(spy.relockCount, 0)
    }

    // MARK: - Foreground-active gate (R2: lock-surface auto-invoke while backgrounded)

    /// `handleForegroundActive` while NOT foreground-active is a pure no-op: it must
    /// neither authenticate nor consume the away epoch, so a later genuine foreground
    /// still authenticates. This is the lock surface's `.task` firing as the surface
    /// is inserted during a background lock transition.
    func test_foregroundActive_whileNotForegroundActive_isNoOp() async {
        let spy = Spy()
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)

        // Lock surface auto-invoke while the app is not foreground-active.
        controller.noteForegroundActive(false)
        await controller.handleForegroundActive(source: "lockSurface.appear")
        XCTAssertEqual(controller.lockState, .locked, "A not-foreground-active foreground call must not unlock.")
        XCTAssertEqual(spy.evaluateCount, 0, "No auth may be attempted while not foreground-active.")
        XCTAssertEqual(spy.relockCount, 0)
        XCTAssertEqual(spy.contentClearCount, 0)

        // The genuine foreground return then drives auth (epoch was not consumed).
        controller.noteForegroundActive(true)
        await controller.handleForegroundActive(source: "scenePhase.active")
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1, "The genuine foreground-active return authenticates.")
    }

    /// Repro of the reported bug: at grace=0, after a normal unlock, the lock surface
    /// is inserted during the `.background` lock transition and its `.task` fires
    /// `handleForegroundActive` while backgrounded. That call must be a no-op so the
    /// FIRST genuine return auto-authenticates (previously it was gated as spurious).
    func test_graceZero_lockSurfaceTaskDuringBackground_thenGenuineReturnAutoAuths() async {
        let spy = Spy()
        spy.gracePeriod = 0
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)

        // Normal in-app unlock (foreground-active by default).
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive(source: "unlock")
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)

        // Background (grace=0): observer sets not-foreground, then the away locks.
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "scenePhase.background")
        await settle()
        XCTAssertEqual(controller.lockState, .locked)

        // The lock surface is inserted during the background transition; its `.task`
        // fires while backgrounded — must be a no-op (epoch not consumed).
        await controller.handleForegroundActive(source: "lockSurface.appear")
        XCTAssertEqual(controller.lockState, .locked, "The backgrounded lock-surface auto-invoke must not consume the epoch.")
        XCTAssertEqual(spy.evaluateCount, 1)

        // FIRST genuine return → auth auto-starts (the regressed behavior).
        controller.noteForegroundActive(true)
        await controller.handleForegroundActive(source: "scenePhase.active")
        XCTAssertEqual(controller.lockState, .unlocked, "The first genuine return after a normal unlock auto-authenticates.")
        XCTAssertEqual(spy.evaluateCount, 2)
    }

    // MARK: - Away events

    func test_awayEvent_intervalZero_locksAndRelocks() async {
        let spy = Spy()
        spy.gracePeriod = 0
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive(source: "unlock")
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksAfterUnlock = spy.relockCount

        controller.handleAwayEvent(source: "background")
        await settle()

        XCTAssertEqual(controller.lockState, .locked, "Interval 0 locks on the away event.")
        XCTAssertEqual(spy.relockCount, relocksAfterUnlock + 1, "Entering locked fails closed via relock.")
        XCTAssertTrue(spy.discardReasons.contains { $0.hasPrefix("away:") })
    }

    func test_awayEvent_nonZeroInterval_doesNotRelockImmediately() async {
        let spy = Spy()
        spy.gracePeriod = 180
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive(source: "unlock")
        let relocksAfterUnlock = spy.relockCount

        controller.handleAwayEvent(source: "background")
        await settle()

        XCTAssertEqual(controller.lockState, .unlocked, "A non-zero interval defers locking to the next resume.")
        XCTAssertEqual(spy.relockCount, relocksAfterUnlock, "No eager relock for a non-zero interval.")
        XCTAssertTrue(spy.discardReasons.contains { $0.hasPrefix("away:") }, "Handoff context is discarded on away (fail-closed).")
    }

    func test_lockNow_locksImmediatelyRegardlessOfGrace() async {
        let spy = Spy()
        spy.gracePeriod = 300
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive(source: "unlock")
        XCTAssertEqual(controller.lockState, .unlocked)

        controller.lockNow(source: "menu")
        await settle()

        XCTAssertEqual(controller.lockState, .locked)
    }

    // MARK: - Concurrency / guards

    func test_concurrentForegroundActive_startsOnlyOneAuth() async {
        let spy = Spy()
        spy.pauseAuth = true
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)

        let suspended = expectation(description: "auth suspended")
        spy.onAuthSuspended = { suspended.fulfill() }

        async let first: Void = controller.handleForegroundActive(source: "a")
        await fulfillment(of: [suspended], timeout: 2)

        // A second resume while the first is in flight must not start a second prompt.
        await controller.handleForegroundActive(source: "b")
        XCTAssertEqual(controller.lockState, .authenticating)
        XCTAssertEqual(spy.evaluateCount, 1)

        spy.resumeAuth()
        await first
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)
    }

    #if os(macOS)
    func test_authenticatingRule_resignDuringOwnUnlock_isNotAnAwayEvent() async {
        let spy = Spy()
        spy.pauseAuth = true
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        let suspended = expectation(description: "auth suspended")
        spy.onAuthSuspended = { suspended.fulfill() }

        async let unlock: Void = controller.handleForegroundActive(source: "unlock")
        await fulfillment(of: [suspended], timeout: 2)
        let relocksDuringAuth = spy.relockCount

        // The macOS system auth sheet resigns the app while the controller drives
        // the unlock; under the `.authenticating` rule that is explicit state, not
        // an away event.
        controller.handleAwayEvent(source: "macResignActive")
        await settle()

        XCTAssertEqual(controller.lockState, .authenticating, "The sheet's own resign is not an away event.")
        XCTAssertEqual(spy.relockCount, relocksDuringAuth, "No relock from the resign during the unlock.")

        spy.resumeAuth()
        await unlock
        XCTAssertEqual(controller.lockState, .unlocked, "The unlock completes despite the resign.")
    }

    func test_authenticatingRule_resignDuringOperationPrompt_isDeferredNotProcessed() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        // A private-key operation prompt is in flight when the resign arrives.
        spy.operationPromptActive = true
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()

        XCTAssertEqual(
            controller.lockState,
            .unlocked,
            "A resign during an operation prompt must not lock mid-operation, even at grace=0."
        )
        XCTAssertEqual(spy.relockCount, relocksBefore, "No relock while the away decision is deferred.")
    }

    func test_authenticatingRule_deferredAway_processedAtPromptsEnd_whenStillAway() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)

        spy.operationPromptActive = true
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()
        XCTAssertEqual(controller.lockState, .unlocked)

        // The prompts end and the app is STILL not foreground-active: the user
        // genuinely left during the operation — the deferred away is processed now
        // (grace=0 → lock, fail-closed).
        spy.operationPromptActive = false
        controller.handleOperationPromptsEnded()
        await settle()

        XCTAssertEqual(controller.lockState, .locked, "The deferred away locks once the prompts end.")
        XCTAssertGreaterThan(spy.relockCount, 0, "Protected App-Data relocks fail-closed.")
    }

    func test_authenticatingRule_deferredAway_discardedAtPromptsEnd_whenForegroundReturned() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        spy.operationPromptActive = true
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()

        // The prompt completes and focus returned to the app before the prompts
        // ended: the resign was the prompt's own — the deferred away is discarded.
        controller.noteForegroundActive(true)
        spy.operationPromptActive = false
        controller.handleOperationPromptsEnded()
        await settle()

        XCTAssertEqual(controller.lockState, .unlocked, "The prompt's own resign never locks.")
        XCTAssertEqual(spy.relockCount, relocksBefore)
    }

    func test_authenticatingRule_lockNowDuringOperationPrompt_stillWins() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)

        // Screen-lock / "Lock Now" routes through lockNow, which the
        // `.authenticating` rule never filters: a genuine lock signal wins even
        // mid-prompt.
        spy.operationPromptActive = true
        controller.lockNow(source: "screenLock")
        await settle()

        XCTAssertEqual(controller.lockState, .locked, "Genuine lock signals win during a prompt.")
    }

    func test_authenticatingRule_multipleResignsDuringOnePrompt_decideOnceAtPromptsEnd() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)

        spy.operationPromptActive = true
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        controller.noteForegroundActive(true)
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()
        XCTAssertEqual(controller.lockState, .unlocked, "All resigns during the prompt are deferred.")

        let relocksBefore = spy.relockCount
        spy.operationPromptActive = false
        controller.handleOperationPromptsEnded()
        await settle()

        XCTAssertEqual(controller.lockState, .locked, "Still away at the prompts' end → one lock decision.")
        XCTAssertEqual(spy.relockCount, relocksBefore + 1, "Exactly one relock cycle for the whole prompt session.")
    }

    func test_authenticatingRule_lockNowClearsPendingDeferredAway_noSecondLockCycle() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)

        spy.operationPromptActive = true
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()

        // An explicit lock mid-prompt wins immediately…
        controller.lockNow(source: "screenLock")
        await settle()
        XCTAssertEqual(controller.lockState, .locked)
        let relocksAfterLockNow = spy.relockCount

        // …and supersedes the deferred away: the prompts' end is a no-op.
        spy.operationPromptActive = false
        controller.handleOperationPromptsEnded()
        await settle()

        XCTAssertEqual(controller.lockState, .locked)
        XCTAssertEqual(spy.relockCount, relocksAfterLockNow, "No redundant second relock cycle.")
    }

    func test_authenticatingRule_promptsEndWithoutDeferredAway_isNoOp() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        controller.handleOperationPromptsEnded()
        await settle()

        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.relockCount, relocksBefore)
    }
    #endif

    func test_lockDuringInFlightAuth_invalidatesUnlock_realBackgroundWins() async {
        // `lockNow` is platform-agnostic (not subject to the macOS in-flight guard),
        // so it exercises the "an away happened during auth → discard the result and
        // stay locked" path on every platform.
        let spy = Spy()
        spy.pauseAuth = true
        spy.authOutcome = .success(.authenticated(context: LAContext()))
        let controller = makeController(spy: spy)
        let suspended = expectation(description: "auth suspended")
        spy.onAuthSuspended = { suspended.fulfill() }

        async let unlock: Void = controller.handleForegroundActive(source: "unlock")
        await fulfillment(of: [suspended], timeout: 2)

        controller.lockNow(source: "lockDuringAuth")
        await settle()
        XCTAssertEqual(controller.lockState, .locked)

        spy.resumeAuth()
        await unlock

        XCTAssertEqual(controller.lockState, .locked, "A lock during auth wins; the unlock result is discarded.")
        XCTAssertEqual(spy.recordedContexts.count, 0, "No context is handed off for an invalidated unlock.")
    }

    func test_lockDuringPostAuth_relocksAndStaysLocked_realBackgroundWins() async {
        let spy = Spy()
        spy.gracePeriod = 180
        spy.pausePostAuth = true
        spy.authOutcome = .success(.authenticated(context: LAContext()))
        let controller = makeController(spy: spy)
        let suspended = expectation(description: "postAuth suspended")
        spy.onPostAuthSuspended = { suspended.fulfill() }

        async let unlock: Void = controller.handleForegroundActive(source: "unlock")
        await fulfillment(of: [suspended], timeout: 2)

        // lockNow is platform-agnostic (NOT subject to the macOS in-flight guard that
        // swallows handleAwayEvent during controller-driven auth), so it actually
        // invalidates the in-flight attempt on macOS where unit tests run — exercising
        // "an away during the post-auth fan-out → discard + REAL relock."
        controller.lockNow(source: "lockDuringPostAuth")
        await settle()                                   // lockNow's enterLocked relocks + sets .locked
        let relocksAfterLockNow = spy.relockCount
        XCTAssertEqual(controller.lockState, .locked)

        spy.resumePostAuth()
        await unlock

        XCTAssertEqual(controller.lockState, .locked, "Stays locked; the unlock result is discarded.")
        XCTAssertGreaterThan(
            spy.relockCount,
            relocksAfterLockNow,
            "The stale post-auth path must perform its OWN real relock — post-auth reopened Protected App-Data."
        )
    }

    // MARK: - Spurious-foreground / duplicate-prompt loop regression (R1)

    func test_graceZero_spuriousForegroundDoesNotReauth_noLoop() async {
        let spy = Spy()
        spy.gracePeriod = 0
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive(source: "cold")
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)

        // The biometric sheet's own dismissal (and Control Center / app-switcher peek /
        // banner) deliver spurious `.active`s with no genuine `.background`. At grace=0
        // these MUST NOT re-authenticate — that was the infinite Face ID loop.
        for _ in 0..<6 {
            await controller.handleForegroundActive(source: "scenePhase.active#spurious")
        }
        XCTAssertEqual(spy.evaluateCount, 1, "Spurious .active must not re-auth at grace=0 (no loop).")
        XCTAssertEqual(controller.lockState, .unlocked)

        // A genuine away at grace=0 locks; the next foreground is exactly one fresh prompt.
        controller.handleAwayEvent(source: "scenePhase.background")
        await settle()
        XCTAssertEqual(controller.lockState, .locked)
        await controller.handleForegroundActive(source: "scenePhase.active#genuineReturn")
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 2, "Exactly one auth per genuine return.")
    }

    func test_authenticationFailed_spuriousForegroundDoesNotAutoRetry() async {
        let spy = Spy()
        spy.gracePeriod = 0
        spy.authOutcome = .success(.failed)
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive(source: "cold")
        XCTAssertEqual(controller.authenticationFailure, .authenticationFailed)
        XCTAssertEqual(spy.evaluateCount, 1)

        // A cancelled/failed auth must leave the retry affordance visible; the just-
        // dismissed failed sheet's `.active` must NOT auto-retry (the cancel→reprompt loop).
        for _ in 0..<5 {
            await controller.handleForegroundActive(source: "scenePhase.active#postCancel")
        }
        XCTAssertEqual(spy.evaluateCount, 1, "A spurious .active after a failed/cancelled auth must not auto-retry.")
        XCTAssertEqual(controller.authenticationFailure, .authenticationFailed)

        // The explicit retry button still works (it bypasses the spurious-foreground gate).
        spy.authOutcome = .success(.authenticated(context: nil))
        await controller.retryUnlock(source: "retryButton")
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 2)
    }

    // MARK: - Local Data Reset

    func test_resetAfterLocalDataReset_clearsToLocked() {
        let spy = Spy()
        let controller = makeController(spy: spy)
        controller.resetAfterLocalDataReset(preserveAuthentication: false)
        XCTAssertEqual(controller.lockState, .locked)
        XCTAssertTrue(spy.discardReasons.contains("localDataReset"))
    }

    func test_resetAfterLocalDataReset_preserveAuthentication_staysUnlocked() {
        let spy = Spy()
        let controller = makeController(spy: spy)
        controller.resetAfterLocalDataReset(preserveAuthentication: true)
        XCTAssertEqual(controller.lockState, .unlocked)
    }
}
