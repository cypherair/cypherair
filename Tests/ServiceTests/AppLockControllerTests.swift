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
        private(set) var discardCount = 0
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
        func discard() { discardCount += 1 }
        func relock() async {
            relockCount += 1
            operationLog.append("relock")
        }
        func postAuth(_ context: LAContext?) async {
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

    /// Stands in for the wall clock the macOS away relock deadline waits on, so
    /// the deadline is driven rather than waited out. The controller suspends in
    /// `wait(_:)`; the test decides when — or whether — it returns.
    @MainActor
    final class AwayDeadlineClock {
        /// One entry per arming, holding the seconds the controller asked for.
        private(set) var requestedIntervals: [TimeInterval] = []
        private var pending: CheckedContinuation<Void, Error>?

        var isPending: Bool { pending != nil }
        var armCount: Int { requestedIntervals.count }

        func wait(_ seconds: TimeInterval) async throws {
            requestedIntervals.append(seconds)
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    pending = continuation
                }
            } onCancel: { [weak self] in
                Task { @MainActor in
                    self?.resumePending(throwing: CancellationError())
                }
            }
        }

        /// The deadline arrives.
        func arrive() {
            resumePending(throwing: nil)
        }

        /// Fail a wait still in flight so its task finishes. No test may end
        /// with a task suspended in here: the suspended task keeps the
        /// continuation, the clock, and everything they capture alive past the
        /// test that made them.
        func cancelPending() {
            resumePending(throwing: CancellationError())
        }

        private func resumePending(throwing error: Error?) {
            guard let continuation = pending else {
                return
            }
            pending = nil
            if let error {
                continuation.resume(throwing: error)
            } else {
                continuation.resume()
            }
        }
    }

    private func makeController(
        spy: Spy,
        awayDeadline: AwayDeadlineClock = AwayDeadlineClock(),
        operationPromptInProgressProvider: (() -> Bool)? = nil
    ) -> AppLockController {
        // Any test that goes away with a non-zero interval leaves a task
        // suspended in the clock; end it with the test that armed it rather
        // than letting it outlive the test case.
        addTeardownBlock {
            await MainActor.run {
                awayDeadline.cancelPending()
            }
        }
        return AppLockController(
            gracePeriodProvider: { spy.gracePeriod },
            lastAuthenticationDateProvider: { spy.lastAuthenticationDate },
            evaluateAppSessionAuthentication: { reason in try await spy.evaluate(reason: reason) },
            recordSuccessfulAuthentication: { spy.recordSuccessful($0) },
            discardHandoffContext: { spy.discard() },
            relockProtectedData: { await spy.relock() },
            postAuthenticationHandler: { await spy.postAuth($0) },
            contentClearHandler: { spy.contentClear() },
            operationPromptInProgressProvider: operationPromptInProgressProvider,
            waitForAwayRelockDeadline: { try await awayDeadline.wait($0) }
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

        await controller.handleForegroundActive()

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

        await controller.handleForegroundActive()

        XCTAssertEqual(controller.lockState, .authenticationFailed(.authenticationFailed))
        XCTAssertTrue(controller.isLocked)
        XCTAssertEqual(spy.recordedContexts.count, 0, "A failed auth must not record/hand off a context.")
        XCTAssertEqual(spy.discardCount, 1, "A failed auth discards the handoff context (fail-closed).")
    }

    func test_foregroundActive_authThrowsBiometricsLockedOut_mapsReason() async {
        let spy = Spy()
        spy.authOutcome = .failure(AuthenticationError.appAccessBiometricsLockedOut)
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive()

        XCTAssertEqual(controller.lockState, .authenticationFailed(.biometricsLockedOut))
        XCTAssertEqual(controller.authenticationFailure, .biometricsLockedOut)
        XCTAssertEqual(spy.recordedContexts.count, 0)
    }

    func test_foregroundActive_authThrowsLABiometryLockout_mapsToLockedOut() async {
        let spy = Spy()
        spy.authOutcome = .failure(LAError(.biometryLockout))
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive()

        XCTAssertEqual(controller.authenticationFailure, .biometricsLockedOut)
    }

    func test_foregroundActive_authThrowsGenericError_mapsToAuthenticationFailed() async {
        let spy = Spy()
        spy.authOutcome = .failure(AuthenticationError.cancelled)
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive()

        XCTAssertEqual(controller.authenticationFailure, .authenticationFailed)
    }

    func test_retryUnlock_fromFailed_succeeds() async {
        let spy = Spy()
        spy.authOutcome = .success(.failed)
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.authenticationFailure, .authenticationFailed)

        spy.authOutcome = .success(.authenticated(context: nil))
        await controller.retryUnlock()

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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)

        // A foreground round-trip inside the grace window stays unlocked.
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1, "No re-auth within the grace window (cover ≠ lock).")
    }

    func test_foregroundActive_whenUnlockedButGraceExpired_reauthenticates() async {
        let spy = Spy()
        spy.gracePeriod = 60
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive()
        XCTAssertEqual(spy.evaluateCount, 1)

        // Last auth is well past the grace window, and a genuine away (non-zero interval
        // → deferred, stays unlocked) precedes the resume — re-auth requires a genuine
        // resume, not a spurious `.active`.
        spy.lastAuthenticationDate = Date(timeIntervalSinceNow: -600)
        controller.handleAwayEvent()
        await settle()
        await controller.handleForegroundActive()
        XCTAssertEqual(spy.evaluateCount, 2)
    }

    func test_failClosedGrace_nilProviderTreatedAsImmediate() async {
        let spy = Spy()
        spy.gracePeriod = nil
        spy.lastAuthenticationDate = Date()
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)

        // nil grace → 0 → a genuine away locks immediately, and the next resume
        // re-authenticates (nil treated as Immediately).
        controller.handleAwayEvent()
        await settle()
        XCTAssertEqual(controller.lockState, .locked)
        await controller.handleForegroundActive()
        XCTAssertEqual(spy.evaluateCount, 2)
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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .locked, "A not-foreground-active foreground call must not unlock.")
        XCTAssertEqual(spy.evaluateCount, 0, "No auth may be attempted while not foreground-active.")
        XCTAssertEqual(spy.relockCount, 0)
        XCTAssertEqual(spy.contentClearCount, 0)

        // The genuine foreground return then drives auth (epoch was not consumed).
        controller.noteForegroundActive(true)
        await controller.handleForegroundActive()
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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)

        // Background (grace=0): observer sets not-foreground, then the away locks.
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        await settle()
        XCTAssertEqual(controller.lockState, .locked)

        // The lock surface is inserted during the background transition; its `.task`
        // fires while backgrounded — must be a no-op (epoch not consumed).
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .locked, "The backgrounded lock-surface auto-invoke must not consume the epoch.")
        XCTAssertEqual(spy.evaluateCount, 1)

        // FIRST genuine return → auth auto-starts (the regressed behavior).
        controller.noteForegroundActive(true)
        await controller.handleForegroundActive()
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
        await controller.handleForegroundActive()

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
        let task = Task { await controller.handleForegroundActive() }
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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)

        // Away (non-zero grace: no immediate lock) then a genuine return.
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        controller.noteForegroundActive(true)
        XCTAssertTrue(controller.isCosmeticallyCovered, "Cover held across the resume gap.")

        await controller.handleForegroundActive()

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

        await controller.handleForegroundActive()

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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksAfterUnlock = spy.relockCount
        let discardsAfterUnlock = spy.discardCount

        controller.handleAwayEvent()
        await settle()

        XCTAssertEqual(controller.lockState, .locked, "Interval 0 locks on the away event.")
        XCTAssertEqual(spy.relockCount, relocksAfterUnlock + 1, "Entering locked fails closed via relock.")
        XCTAssertGreaterThan(spy.discardCount, discardsAfterUnlock)
    }

    func test_awayEvent_nonZeroInterval_doesNotRelockImmediately() async {
        let spy = Spy()
        spy.gracePeriod = 180
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive()
        let relocksAfterUnlock = spy.relockCount
        let discardsAfterUnlock = spy.discardCount

        controller.handleAwayEvent()
        await settle()

        XCTAssertEqual(controller.lockState, .unlocked, "A non-zero interval defers locking to the next resume.")
        XCTAssertEqual(spy.relockCount, relocksAfterUnlock, "No eager relock for a non-zero interval.")
        XCTAssertGreaterThan(spy.discardCount, discardsAfterUnlock, "Handoff context is discarded on away (fail-closed).")
    }

    #if os(macOS)

    // MARK: - Away relock deadline (macOS)
    //
    // macOS keeps the process running while the app is away, so the grace
    // interval is a bound only if something enforces it there. These pin that
    // the deadline armed at away decides on the same predicate as the foreground
    // return, and that it stops existing the moment that pair — unlocked and
    // away — no longer holds.

    /// The past-grace invariant: the session must not survive the grace window
    /// just because the user has not come back yet.
    func test_awayDeadline_pastGrace_relocksWhileStillAway() async {
        let spy = Spy()
        spy.gracePeriod = 60
        spy.authOutcome = .success(.authenticated(context: nil))
        let deadline = AwayDeadlineClock()
        let controller = makeController(spy: spy, awayDeadline: deadline)
        // 20 seconds into the window already, so a deadline anchored to the last
        // authentication (40 seconds left) is a different number from a fresh
        // full interval (60) — an away must not extend the session.
        spy.lastAuthenticationDate = Date(timeIntervalSinceNow: -20)
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksAfterUnlock = spy.relockCount
        let contentClearsAfterUnlock = spy.contentClearCount

        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        await settle()

        XCTAssertEqual(controller.lockState, .unlocked, "The session stays open for the rest of the grace window.")
        XCTAssertEqual(deadline.armCount, 1, "Away arms the relock deadline.")
        XCTAssertEqual(
            deadline.requestedIntervals.first ?? -1,
            40,
            accuracy: 5,
            "The deadline is the last authentication plus the interval — the anchor the foreground return uses. Leaving does not restart the window."
        )

        // The window ends while the user is still away.
        spy.lastAuthenticationDate = Date(timeIntervalSinceNow: -600)
        deadline.arrive()
        await settle()

        XCTAssertEqual(controller.lockState, .locked, "Past grace the app relocks without waiting for the user.")
        XCTAssertEqual(
            spy.relockCount,
            relocksAfterUnlock + 1,
            "Protected App-Data relocks (the wrapping root key is zeroized) at the deadline, not on the next return."
        )
        XCTAssertEqual(spy.contentClearCount, contentClearsAfterUnlock + 1, "Decrypted content is cleared with it.")
    }

    /// A return inside the grace window disarms the deadline; a wake-up that
    /// arrives afterwards must not relock the session the user is using.
    func test_awayDeadline_foregroundReturnDisarmsIt() async {
        let spy = Spy()
        spy.gracePeriod = 300
        spy.authOutcome = .success(.authenticated(context: nil))
        let deadline = AwayDeadlineClock()
        let controller = makeController(spy: spy, awayDeadline: deadline)
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive()
        let relocksAfterUnlock = spy.relockCount

        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        await settle()
        XCTAssertTrue(deadline.isPending)

        controller.noteForegroundActive(true)
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked, "A return within grace stays unlocked.")

        deadline.arrive()
        await settle()

        XCTAssertEqual(controller.lockState, .unlocked, "A stale wake-up must not relock a session in use.")
        XCTAssertEqual(spy.relockCount, relocksAfterUnlock)
    }

    /// The wake-up is when to look, not what to conclude: if the window has not
    /// actually passed — a clock adjustment, or an authentication recorded after
    /// the arming — it waits out the remainder instead of relocking early.
    func test_awayDeadline_beforeGraceEnds_waitsOutTheRemainder() async {
        let spy = Spy()
        spy.gracePeriod = 300
        spy.authOutcome = .success(.authenticated(context: nil))
        let deadline = AwayDeadlineClock()
        let controller = makeController(spy: spy, awayDeadline: deadline)
        spy.lastAuthenticationDate = Date(timeIntervalSinceNow: -20)
        await controller.handleForegroundActive()
        let relocksAfterUnlock = spy.relockCount

        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        await settle()

        deadline.arrive()
        await settle()

        XCTAssertEqual(controller.lockState, .unlocked, "An early wake-up must not relock inside the grace window.")
        XCTAssertEqual(spy.relockCount, relocksAfterUnlock)
        XCTAssertEqual(deadline.armCount, 2, "It re-arms rather than relocking.")
        XCTAssertEqual(
            deadline.requestedIntervals.last ?? -1,
            280,
            accuracy: 5,
            "It waits out what is left of the window, not a fresh interval."
        )
        XCTAssertTrue(deadline.isPending)
    }

    /// An explicit lock supersedes the deadline synchronously, so the pending
    /// wake-up cannot land a second relock cycle after it.
    func test_awayDeadline_lockNowDisarmsIt_noSecondRelockCycle() async {
        let spy = Spy()
        spy.gracePeriod = 300
        spy.authOutcome = .success(.authenticated(context: nil))
        let deadline = AwayDeadlineClock()
        let controller = makeController(spy: spy, awayDeadline: deadline)
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive()
        let relocksBeforeLock = spy.relockCount

        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        await settle()

        controller.lockNow()
        deadline.arrive()
        await settle()

        XCTAssertEqual(controller.lockState, .locked)
        XCTAssertEqual(spy.relockCount, relocksBeforeLock + 1, "Exactly one relock cycle.")
    }

    /// The unlock's own `.authenticating` rule swallows every resign while the
    /// flow runs, so an away during the post-auth fan-out reaches neither
    /// evaluation point: no away event arms the deadline, and the return finds
    /// its epoch already marked and stops before the grace check. The unlock
    /// arms for itself when it settles while the app is away — and the relock
    /// that follows is what lets the return re-authenticate.
    func test_awayDeadline_awayDuringPostAuth_armsAtUnlock_andReturnReauthenticates() async {
        let spy = Spy()
        spy.gracePeriod = 60
        spy.pausePostAuth = true
        spy.authOutcome = .success(.authenticated(context: nil))
        spy.lastAuthenticationDate = Date()
        let deadline = AwayDeadlineClock()
        let controller = makeController(spy: spy, awayDeadline: deadline)
        let suspended = expectation(description: "postAuth suspended")
        spy.onPostAuthSuspended = { suspended.fulfill() }

        async let unlock: Void = controller.handleForegroundActive()
        await fulfillment(of: [suspended], timeout: 2)

        // The user leaves while the post-auth fan-out is still running. The
        // `.authenticating` rule swallows the resign — no generation bump, no
        // arming from the away path.
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        await settle()
        XCTAssertEqual(deadline.armCount, 0, "The away event itself is swallowed mid-unlock.")

        spy.resumePostAuth()
        await unlock
        // The return below runs a second unlock; let its fan-out through.
        spy.pausePostAuth = false
        spy.onPostAuthSuspended = nil

        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(deadline.armCount, 1, "An unlock that settles while away arms the deadline itself.")

        // The window ends before the user comes back.
        spy.lastAuthenticationDate = Date(timeIntervalSinceNow: -600)
        deadline.arrive()
        await settle()
        XCTAssertEqual(controller.lockState, .locked, "Past grace it relocks, exactly as an ordinary away would.")

        // The return re-authenticates: the relock bumped the away generation, so
        // the spurious-foreground gate no longer suppresses it.
        let evaluationsBeforeReturn = spy.evaluateCount
        controller.noteForegroundActive(true)
        await controller.handleForegroundActive()

        XCTAssertEqual(spy.evaluateCount, evaluationsBeforeReturn + 1, "The return authenticates.")
        XCTAssertEqual(controller.lockState, .unlocked)
    }
    #endif

    func test_lockNow_locksImmediatelyRegardlessOfGrace() async {
        let spy = Spy()
        spy.gracePeriod = 300
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        spy.lastAuthenticationDate = Date()
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)

        controller.lockNow()
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

        async let first: Void = controller.handleForegroundActive()
        await fulfillment(of: [suspended], timeout: 2)

        // A second resume while the first is in flight must not start a second prompt.
        await controller.handleForegroundActive()
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

        async let unlock: Void = controller.handleForegroundActive()
        await fulfillment(of: [suspended], timeout: 2)
        let relocksDuringAuth = spy.relockCount

        // The macOS system auth sheet resigns the app while the controller drives
        // the unlock; under the `.authenticating` rule that is explicit state, not
        // an away event.
        controller.handleAwayEvent()
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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        // A private-key operation prompt is in flight when the resign arrives
        // (the began-hop has landed on the main actor).
        controller.handleOperationPromptSessionBegan()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)

        controller.handleOperationPromptSessionBegan()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        controller.handleOperationPromptSessionBegan()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)

        // Screen-lock / "Lock Now" routes through lockNow, which the
        // `.authenticating` rule never filters: a genuine lock signal wins even
        // mid-prompt.
        controller.handleOperationPromptSessionBegan()
        controller.lockNow()
        await settle()

        XCTAssertEqual(controller.lockState, .locked, "Genuine lock signals win during a prompt.")
    }

    func test_authenticatingRule_multipleResignsDuringOnePrompt_decideOnceAtPromptsEnd() async {
        let spy = Spy()
        spy.gracePeriod = 0
        let controller = makeController(spy: spy)
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)

        controller.handleOperationPromptSessionBegan()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        controller.noteForegroundActive(true)
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)

        controller.handleOperationPromptSessionBegan()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        await settle()

        // Adversarial ordering: the prompts-ended hop runs BEFORE lockNow's
        // queued enterLocked task. lockNow clears the deferral synchronously, so
        // the hop must be a no-op and exactly one relock cycle runs.
        let relocksBeforeLock = spy.relockCount
        controller.lockNow()
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
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)

        controller.handleOperationPromptSessionBegan()   // session 1
        controller.handleOperationPromptSessionBegan()   // session 2 began-hop arrives early
        controller.handleOperationPromptsEnded()         // session 1 ended-hop arrives late

        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
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

        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        let prompt = coordinator.beginOperationPrompt()
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()

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

        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        let relocksBefore = spy.relockCount

        let prompt = coordinator.beginOperationPrompt()
        await settle() // began-hop lands: mirror opens
        coordinator.endOperationPrompt(prompt)

        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
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
        await controller.handleForegroundActive()
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

        async let unlock: Void = controller.handleForegroundActive()
        await fulfillment(of: [suspended], timeout: 2)

        controller.lockNow()
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

        async let unlock: Void = controller.handleForegroundActive()
        await fulfillment(of: [suspended], timeout: 2)

        // lockNow is platform-agnostic (NOT subject to the macOS in-flight guard that
        // swallows handleAwayEvent during controller-driven auth), so it actually
        // invalidates the in-flight attempt on macOS where unit tests run — exercising
        // "an away during the post-auth fan-out → discard + REAL relock."
        controller.lockNow()
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

        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 1)

        // The biometric sheet's own dismissal (and Control Center / app-switcher peek /
        // banner) deliver spurious `.active`s with no genuine `.background`. At grace=0
        // these MUST NOT re-authenticate — that was the infinite Face ID loop.
        for _ in 0..<6 {
            await controller.handleForegroundActive()
        }
        XCTAssertEqual(spy.evaluateCount, 1, "Spurious .active must not re-auth at grace=0 (no loop).")
        XCTAssertEqual(controller.lockState, .unlocked)

        // A genuine away at grace=0 locks; the next foreground is exactly one fresh prompt.
        controller.handleAwayEvent()
        await settle()
        XCTAssertEqual(controller.lockState, .locked)
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 2, "Exactly one auth per genuine return.")
    }

    func test_authenticationFailed_spuriousForegroundDoesNotAutoRetry() async {
        let spy = Spy()
        spy.gracePeriod = 0
        spy.authOutcome = .success(.failed)
        let controller = makeController(spy: spy)

        await controller.handleForegroundActive()
        XCTAssertEqual(controller.authenticationFailure, .authenticationFailed)
        XCTAssertEqual(spy.evaluateCount, 1)

        // A cancelled/failed auth must leave the retry affordance visible; the just-
        // dismissed failed sheet's `.active` must NOT auto-retry (the cancel→reprompt loop).
        for _ in 0..<5 {
            await controller.handleForegroundActive()
        }
        XCTAssertEqual(spy.evaluateCount, 1, "A spurious .active after a failed/cancelled auth must not auto-retry.")
        XCTAssertEqual(controller.authenticationFailure, .authenticationFailed)

        // The explicit retry button still works (it bypasses the spurious-foreground gate).
        spy.authOutcome = .success(.authenticated(context: nil))
        await controller.retryUnlock()
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertEqual(spy.evaluateCount, 2)
    }

    // MARK: - Local Data Reset

    func test_resetAfterLocalDataReset_clearsToLocked() {
        let spy = Spy()
        let controller = makeController(spy: spy)
        controller.resetAfterLocalDataReset(preserveAuthentication: false)
        XCTAssertEqual(controller.lockState, .locked)
        XCTAssertEqual(spy.discardCount, 1, "The reset discards the handoff context (fail-closed).")
    }

    func test_resetAfterLocalDataReset_preserveAuthentication_staysUnlocked() {
        let spy = Spy()
        let controller = makeController(spy: spy)
        controller.resetAfterLocalDataReset(preserveAuthentication: true)
        XCTAssertEqual(controller.lockState, .unlocked)
    }
}
