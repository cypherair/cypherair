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

    private func makeController(
        spy: Spy,
        operationPromptInProgressProvider: (() -> Bool)? = nil,
        cancelEmbeddedUnlockEvaluationIfInFlight: (@MainActor () -> Bool)? = nil
    ) -> AppLockController {
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
            operationPromptInProgressProvider: operationPromptInProgressProvider,
            cancelEmbeddedUnlockEvaluationIfInFlight: cancelEmbeddedUnlockEvaluationIfInFlight
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
    /// FIRST genuine return auto-authenticates.
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

    // MARK: - Resume-time cover hold (resume-race)

    /// The cosmetic cover must NOT drop in the synchronous window between the
    /// foreground signal (`noteForegroundActive(true)`, which sets
    /// `isForegroundActive`) and the async lock decision (`handleForegroundActive`).
    /// Otherwise protected content flashes before the lock surface can appear.
    func test_resumeCover_heldSynchronouslyOnForegroundReturn_untilDecisionResolves() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)

        // Away → covered because not foreground-active.
        controller.noteForegroundActive(false)
        XCTAssertTrue(controller.isCosmeticallyCovered)

        // Genuine foreground return: isForegroundActive flips true, but the cover
        // must be held by the resolve flag so it does not drop for a frame.
        controller.noteForegroundActive(true)
        XCTAssertTrue(controller.isForegroundActive)
        XCTAssertTrue(controller.isResolvingForegroundLock)
        XCTAssertTrue(controller.isCosmeticallyCovered)

        // Resolve the foreground (from .locked → full unlock flow).
        await controller.handleForegroundActive(source: "scenePhase.active")

        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertFalse(controller.isResolvingForegroundLock, "The resume hold releases once the decision resolves.")
        XCTAssertFalse(controller.isCosmeticallyCovered)
    }

    /// While authentication is in flight the cover stays up together with the lock
    /// surface (`.authenticating`), and is released only after the flow resolves.
    func test_resumeCover_remainsCoveredWhileAuthenticating() async {
        let spy = Spy()
        spy.gracePeriod = 0
        spy.pauseAuth = true
        let controller = makeController(spy: spy)

        controller.noteForegroundActive(false)
        controller.noteForegroundActive(true)

        let suspended = expectation(description: "auth suspended")
        spy.onAuthSuspended = { suspended.fulfill() }
        let task = Task { await controller.handleForegroundActive(source: "scenePhase.active") }
        await fulfillment(of: [suspended], timeout: 1.0)

        XCTAssertEqual(controller.lockState, .authenticating)
        XCTAssertTrue(
            controller.isLocked,
            "`.authenticating` must read as locked — the shield renders its lock face off `isLocked`, so this is what makes the lock face win during auth prompts (#723)."
        )
        XCTAssertTrue(controller.isResolvingForegroundLock, "Cover stays held through the authentication.")
        XCTAssertTrue(controller.isCosmeticallyCovered)

        spy.resumeAuth()
        await task.value

        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertFalse(controller.isResolvingForegroundLock)
        XCTAssertFalse(controller.isCosmeticallyCovered)
    }

    /// A within-grace foreground return does not re-authenticate; the resume hold
    /// must still be released so content (correctly preserved) becomes visible.
    func test_resumeCover_withinGrace_releasesCoverAndStaysUnlocked() async {
        let spy = Spy()
        spy.gracePeriod = 300
        spy.lastAuthenticationDate = Date()
        let controller = makeController(spy: spy)

        // Prime to unlocked.
        await controller.handleForegroundActive(source: "unlock")
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)

        // Away (non-zero grace: no immediate lock) then a genuine return.
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "scenePhase.background")
        controller.noteForegroundActive(true)
        XCTAssertTrue(controller.isCosmeticallyCovered, "Cover held across the resume gap.")

        await controller.handleForegroundActive(source: "scenePhase.active")

        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1, "A within-grace return must not re-authenticate.")
        XCTAssertFalse(controller.isResolvingForegroundLock)
        XCTAssertFalse(controller.isCosmeticallyCovered)
    }

    /// The resume hold is released on EVERY exit path — including the
    /// not-foreground-active early return — so the cover can never stick up. Here
    /// the app loses the foreground again before the decision runs; the flag clears
    /// and the cover then rests solely on `!isForegroundActive`.
    func test_resumeCover_clearedEvenWhenForegroundLostBeforeResolution() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)

        controller.noteForegroundActive(false)
        controller.noteForegroundActive(true)
        XCTAssertTrue(controller.isResolvingForegroundLock)

        // The app goes not-foreground again before handleForegroundActive runs.
        controller.noteForegroundActive(false)
        XCTAssertTrue(controller.isResolvingForegroundLock, "Still set; only handleForegroundActive clears it.")
        XCTAssertTrue(controller.isCosmeticallyCovered)

        await controller.handleForegroundActive(source: "scenePhase.active")

        XCTAssertEqual(spy.evaluateCount, 0, "A not-foreground-active resolution must not authenticate.")
        XCTAssertFalse(controller.isResolvingForegroundLock, "The hold must never stick, even on the early return.")
        XCTAssertTrue(controller.isCosmeticallyCovered, "Still covered — now via !isForegroundActive.")
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

    // MARK: - macOS in-window unlock (issue #724): the embedded exception to
    // the `.authenticating` swallow.

    func test_awayDuringEmbeddedUnlockEvaluation_cancelsAndProcessesGenuineAway() async {
        let spy = Spy()
        spy.gracePeriod = 0
        spy.pauseAuth = true
        var cancelCount = 0
        let controller = makeController(
            spy: spy,
            cancelEmbeddedUnlockEvaluationIfInFlight: {
                cancelCount += 1
                return true
            }
        )
        let suspended = expectation(description: "auth suspended")
        spy.onAuthSuspended = { suspended.fulfill() }

        async let unlock: Void = controller.handleForegroundActive(source: "unlock")
        await fulfillment(of: [suspended], timeout: 2)

        // The embedded in-window prompt resigns nothing, so this resign is a
        // REAL app switch: the attempt is cancelled and the away processes
        // as genuine (grace 0 → immediate relock).
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()
        XCTAssertEqual(cancelCount, 1, "The in-flight embedded evaluation is cancelled.")
        XCTAssertEqual(controller.lockState, .locked, "The genuine away relocks at grace 0.")
        XCTAssertGreaterThan(spy.relockCount, 1, "A real relock cycle ran (beyond the unlock flow's own).")

        // The cancelled evaluation lands as an error against the bumped away
        // generation and settles without a failure flash.
        spy.authOutcome = .failure(AuthenticationError.cancelled)
        spy.resumeAuth()
        await unlock
        XCTAssertEqual(controller.lockState, .locked)
        XCTAssertEqual(spy.recordedContexts.count, 0, "No context is handed off for an invalidated attempt.")

        // The away epoch was NOT consumed by the interrupted attempt: the next
        // genuine foreground return auto-authenticates afresh.
        let evaluationsBefore = spy.evaluateCount
        spy.pauseAuth = false
        spy.authOutcome = .success(.authenticated(context: nil))
        controller.noteForegroundActive(true)
        await controller.handleForegroundActive(source: "return")
        XCTAssertEqual(spy.evaluateCount, evaluationsBefore + 1)
        XCTAssertEqual(controller.lockState, .unlocked)
    }

    func test_awayDuringSystemSheetUnlockEvaluation_staysSwallowedWithPresenterWired() async {
        // The production posture during the Standard-mode password sheet: the
        // cancel seam is WIRED but reports no embedded evaluation in flight —
        // the sheet's own resign must keep today's swallow.
        let spy = Spy()
        spy.pauseAuth = true
        let controller = makeController(
            spy: spy,
            cancelEmbeddedUnlockEvaluationIfInFlight: { false }
        )
        let suspended = expectation(description: "auth suspended")
        spy.onAuthSuspended = { suspended.fulfill() }

        async let unlock: Void = controller.handleForegroundActive(source: "unlock")
        await fulfillment(of: [suspended], timeout: 2)
        let relocksDuringAuth = spy.relockCount

        controller.handleAwayEvent(source: "macResignActive")
        await settle()
        XCTAssertEqual(controller.lockState, .authenticating, "The sheet's own resign is not an away event.")
        XCTAssertEqual(spy.relockCount, relocksDuringAuth)

        spy.resumeAuth()
        await unlock
        XCTAssertEqual(controller.lockState, .unlocked, "The sheet unlock completes despite the resign.")
    }

    func test_lockNow_cancelsInFlightEmbeddedEvaluation() async {
        let spy = Spy()
        spy.pauseAuth = true
        var cancelCount = 0
        let controller = makeController(
            spy: spy,
            cancelEmbeddedUnlockEvaluationIfInFlight: {
                cancelCount += 1
                return true
            }
        )
        let suspended = expectation(description: "auth suspended")
        spy.onAuthSuspended = { suspended.fulfill() }

        async let unlock: Void = controller.handleForegroundActive(source: "unlock")
        await fulfillment(of: [suspended], timeout: 2)

        controller.lockNow(source: "screenLock")
        XCTAssertEqual(
            cancelCount,
            1,
            "An explicit lock dismisses the pending in-window prompt instead of leaving it armed."
        )
        await settle()

        spy.authOutcome = .failure(AuthenticationError.cancelled)
        spy.resumeAuth()
        await unlock
        XCTAssertEqual(controller.lockState, .locked)
    }

    func test_authenticatingRule_resignDuringOperationPrompt_isDeferredNotProcessed() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        // A private-key operation prompt is in flight when the resign arrives
        // (the began-hop has landed on the main actor).
        controller.handleOperationPromptSessionBegan()
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

        controller.handleOperationPromptSessionBegan()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()
        XCTAssertEqual(controller.lockState, .unlocked)

        // The prompts end and the app is STILL not foreground-active: the user
        // genuinely left during the operation — the deferred away is processed now
        // (grace=0 → lock, fail-closed).
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

        controller.handleOperationPromptSessionBegan()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()

        // The prompt completes and focus returned to the app before the prompts
        // ended: the resign was the prompt's own — the deferred away is discarded.
        controller.noteForegroundActive(true)
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
        controller.handleOperationPromptSessionBegan()
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

        controller.handleOperationPromptSessionBegan()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        controller.noteForegroundActive(true)
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()
        XCTAssertEqual(controller.lockState, .unlocked, "All resigns during the prompt are deferred.")

        let relocksBefore = spy.relockCount
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

        controller.handleOperationPromptSessionBegan()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()

        // Adversarial ordering: the prompts-ended hop runs BEFORE lockNow's
        // queued enterLocked task. lockNow clears the deferral synchronously, so
        // the hop must be a no-op and exactly one relock cycle runs.
        let relocksBeforeLock = spy.relockCount
        controller.lockNow(source: "screenLock")
        controller.handleOperationPromptsEnded()
        await settle()

        XCTAssertEqual(controller.lockState, .locked)
        XCTAssertEqual(
            spy.relockCount,
            relocksBeforeLock + 1,
            "Exactly one relock cycle: the deferred away is superseded synchronously by lockNow."
        )
    }

    func test_authenticatingRule_overlappingSessionHops_keepMirrorOpen() async {
        // Counter-not-Bool: a new session's began-hop can land before the previous
        // session's ended-hop. The mirror must stay open for the live session.
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)

        controller.handleOperationPromptSessionBegan()   // session 1
        controller.handleOperationPromptSessionBegan()   // session 2 began-hop arrives early
        controller.handleOperationPromptsEnded()         // session 1 ended-hop arrives late

        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()
        XCTAssertEqual(controller.lockState, .unlocked, "The live session keeps the resign deferred.")

        controller.handleOperationPromptsEnded()         // session 2 ends, still away
        await settle()
        XCTAssertEqual(controller.lockState, .locked, "The deferred away is decided at the true end.")
    }

    func test_authenticatingRule_beginHopDelay_livePromptStillDefersResign() async {
        // The coordinator live-depth closes the other side of the hop race: if
        // a prompt begins and a resign arrives before the began-hop opens the
        // main-actor mirror, the live prompt still marks the resign ambiguous.
        let spy = Spy()
        spy.gracePeriod = 0
        let coordinator = AuthenticationPromptCoordinator()
        let controller = makeController(
            spy: spy,
            operationPromptInProgressProvider: {
                coordinator.isOperationPromptInProgress
            }
        )
        coordinator.onOperationPromptSessionBegan = { [weak controller] in
            Task { @MainActor in controller?.handleOperationPromptSessionBegan() }
        }
        coordinator.onOperationPromptsEnded = { [weak controller] in
            Task { @MainActor in controller?.handleOperationPromptsEnded() }
        }

        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        let prompt = coordinator.beginOperationPrompt()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")

        XCTAssertEqual(
            controller.lockState,
            .unlocked,
            "The live prompt must defer a resign that beats the began-hop."
        )
        XCTAssertEqual(spy.relockCount, relocksBefore, "No relock before the deferred decision.")

        coordinator.endOperationPrompt(prompt)
        await settle()

        XCTAssertEqual(controller.lockState, .locked, "Still away at the decision point -> fail-closed lock.")
        XCTAssertGreaterThan(spy.relockCount, relocksBefore)
    }

    func test_authenticatingRule_endHopDelay_livePromptEndedTreatsResignAsRealAway() async {
        // When the prompt has ended but the ended-hop has not landed, the stale
        // mirror must not swallow a real macOS away. Live-depth false wins.
        let spy = Spy()
        spy.gracePeriod = 0
        let coordinator = AuthenticationPromptCoordinator()
        let controller = makeController(
            spy: spy,
            operationPromptInProgressProvider: {
                coordinator.isOperationPromptInProgress
            }
        )
        coordinator.onOperationPromptSessionBegan = { [weak controller] in
            Task { @MainActor in controller?.handleOperationPromptSessionBegan() }
        }
        coordinator.onOperationPromptsEnded = { [weak controller] in
            Task { @MainActor in controller?.handleOperationPromptsEnded() }
        }

        await controller.handleForegroundActive(source: "boot")
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        let prompt = coordinator.beginOperationPrompt()
        await settle() // began-hop lands: mirror opens
        coordinator.endOperationPrompt(prompt)

        controller.noteForegroundActive(false)
        controller.handleAwayEvent(source: "macResignActive")
        await settle()

        XCTAssertEqual(
            controller.lockState,
            .locked,
            "A resign after live prompt end is a real away even if the ended-hop is still queued."
        )
        XCTAssertGreaterThan(spy.relockCount, relocksBefore)
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
