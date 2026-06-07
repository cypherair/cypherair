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

        func recordSuccessful(_ context: LAContext?) { recordedContexts.append(context) }
        func discard(_ reason: String) { discardReasons.append(reason) }
        func relock() async { relockCount += 1 }
        func postAuth(_ context: LAContext?, _ source: String) async {
            postAuthCount += 1
            postAuthContexts.append(context)
        }
        func contentClear() { contentClearCount += 1 }
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

        // Last auth is well past the grace window.
        spy.lastAuthenticationDate = Date(timeIntervalSinceNow: -600)
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

        // nil grace → 0 → any foreground round-trip re-authenticates.
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
    func test_inFlightAuthGuard_suppressesMacOSResignDuringOwnAuth() async {
        let spy = Spy()
        spy.pauseAuth = true
        spy.authOutcome = .success(.authenticated(context: nil))
        let controller = makeController(spy: spy)
        let suspended = expectation(description: "auth suspended")
        spy.onAuthSuspended = { suspended.fulfill() }

        async let unlock: Void = controller.handleForegroundActive(source: "unlock")
        await fulfillment(of: [suspended], timeout: 2)
        let relocksDuringAuth = spy.relockCount

        // The macOS detached auth sheet resigns the app while we drive the unlock.
        controller.handleAwayEvent(source: "macResignActive")
        await settle()

        XCTAssertEqual(controller.lockState, .authenticating, "The self-induced resign is ignored.")
        XCTAssertEqual(spy.relockCount, relocksDuringAuth, "No relock from the suppressed away event.")

        spy.resumeAuth()
        await unlock
        XCTAssertEqual(controller.lockState, .unlocked, "The unlock completes despite the resign.")
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
