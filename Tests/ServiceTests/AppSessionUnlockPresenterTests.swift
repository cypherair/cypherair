import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Guards the macOS in-window unlock method matrix (issue #724 stage 2):
/// which mechanism an attempt uses per mode/availability, the one-shot
/// "Use Password…" request, the evaluate-only-after-mount ordering, and the
/// cancellation seam the controller's away rule depends on. Everything runs
/// through injected evaluator seams — no real LocalAuthentication.
@MainActor
final class AppSessionUnlockPresenterTests: XCTestCase {
    /// Deterministic async evaluator double: records invocations, then either
    /// returns a preset outcome immediately or suspends until resumed.
    private final class EvaluatorStub {
        private(set) var invocationCount = 0
        private(set) var lastContext: LAContext?
        var outcome: Result<AppSessionAuthenticationResult, Error> = .success(.authenticated(context: nil))
        var pause = false
        var onSuspended: (() -> Void)?
        private var continuation: CheckedContinuation<Void, Never>?

        func evaluate(context: LAContext?) async throws -> AppSessionAuthenticationResult {
            invocationCount += 1
            lastContext = context
            if pause {
                await withCheckedContinuation { (paused: CheckedContinuation<Void, Never>) in
                    continuation = paused
                    onSuspended?()
                }
            }
            return try outcome.get()
        }

        func resume() {
            let paused = continuation
            continuation = nil
            paused?.resume()
        }
    }

    @MainActor
    private final class Fixture {
        var policy: AppSessionAuthenticationPolicy = .userPresence
        var availability: AppSessionUnlockPresenter.EmbeddedBiometricsAvailability = .available
        let embedded = EvaluatorStub()
        let password = EvaluatorStub()
        private(set) lazy var presenter: AppSessionUnlockPresenter = AppSessionUnlockPresenter(
            appSessionPolicy: { [unowned self] in policy },
            probeEmbeddedBiometricsAvailability: { [unowned self] in availability },
            evaluateEmbeddedBiometrics: { [unowned self] context, _ in
                try await embedded.evaluate(context: context)
            },
            evaluatePasswordWithSystemSheet: { [unowned self] _ in
                try await password.evaluate(context: nil)
            }
        )
    }

    /// Runs one attempt on the main actor (matching production: the
    /// controller's unlock flow) and captures its outcome without moving the
    /// non-Sendable result across executors.
    @MainActor
    private final class AttemptDriver {
        private(set) var outcome: Result<AppSessionAuthenticationResult, Error>?

        init(_ presenter: AppSessionUnlockPresenter) {
            Task { @MainActor in
                do {
                    outcome = .success(try await presenter.evaluateAppSessionUnlock(reason: "test"))
                } catch {
                    outcome = .failure(error)
                }
            }
        }

        func settledOutcome() async throws -> Result<AppSessionAuthenticationResult, Error> {
            for _ in 0..<10_000 where outcome == nil {
                await Task.yield()
            }
            return try XCTUnwrap(outcome, "The attempt never settled.")
        }
    }

    /// Drive one attempt to completion, sending the mount signal as soon as
    /// the presenter publishes an embedded context (the surface's job in
    /// production).
    private func evaluateSimulatingMount(
        _ fixture: Fixture
    ) async throws -> AppSessionAuthenticationResult {
        let embeddedInvocationsBefore = fixture.embedded.invocationCount
        let passwordInvocationsBefore = fixture.password.invocationCount
        let driver = AttemptDriver(fixture.presenter)
        while fixture.presenter.presentedEmbeddedContext == nil,
              fixture.embedded.invocationCount == embeddedInvocationsBefore,
              fixture.password.invocationCount == passwordInvocationsBefore {
            await Task.yield()
        }
        if let context = fixture.presenter.presentedEmbeddedContext {
            fixture.presenter.embeddedAuthenticationViewDidMount(for: context)
        }
        return try await driver.settledOutcome().get()
    }

    // MARK: - Method matrix

    func test_available_runsEmbeddedEvaluation_onPublishedContext() async throws {
        let fixture = Fixture()
        let handoff = LAContext()
        fixture.embedded.outcome = .success(.authenticated(context: handoff))

        let result = try await evaluateSimulatingMount(fixture)

        XCTAssertEqual(fixture.embedded.invocationCount, 1)
        XCTAssertEqual(fixture.password.invocationCount, 0)
        XCTAssertTrue(result.isAuthenticated)
        XCTAssertNil(
            fixture.presenter.presentedEmbeddedContext,
            "The embedded presentation is cleared when the attempt ends."
        )
    }

    func test_embeddedEvaluation_waitsForViewMount() async throws {
        let fixture = Fixture()
        let driver = AttemptDriver(fixture.presenter)
        while fixture.presenter.presentedEmbeddedContext == nil {
            await Task.yield()
        }
        // Context published, mount signal not yet sent: evaluation must not
        // have started (the empirically load-bearing ordering — a context
        // evaluated before its paired view is mounted hangs or mis-presents).
        await Task.yield()
        XCTAssertEqual(fixture.embedded.invocationCount, 0)

        let context = try XCTUnwrap(fixture.presenter.presentedEmbeddedContext)
        fixture.presenter.embeddedAuthenticationViewDidMount(for: context)
        _ = try await driver.settledOutcome()
        XCTAssertEqual(fixture.embedded.invocationCount, 1)
    }

    func test_unavailable_standardMode_failsFastWithoutAnySystemUI() async {
        let fixture = Fixture()
        fixture.availability = .unavailable

        do {
            _ = try await fixture.presenter.evaluateAppSessionUnlock(reason: "test")
            XCTFail("Expected the attempt to fail fast.")
        } catch let error as AuthenticationError {
            guard case .appAccessBiometricsUnavailable = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
        // The deliberate #724 decision: the auto-invoked attempt never pops a
        // system sheet — password is an explicit user action.
        XCTAssertEqual(fixture.embedded.invocationCount, 0)
        XCTAssertEqual(fixture.password.invocationCount, 0)
        XCTAssertTrue(
            fixture.presenter.composesPasswordPrimary,
            "Standard mode without usable biometrics composes password-primary."
        )
    }

    func test_lockedOut_mapsToLockedOutReason() async {
        let fixture = Fixture()
        fixture.availability = .lockedOut

        do {
            _ = try await fixture.presenter.evaluateAppSessionUnlock(reason: "test")
            XCTFail("Expected the attempt to fail fast.")
        } catch let error as AuthenticationError {
            guard case .appAccessBiometricsLockedOut = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func test_highSecurity_neverOffersOrRunsPassword() async {
        let fixture = Fixture()
        fixture.policy = .biometricsOnly
        fixture.availability = .unavailable

        XCTAssertFalse(fixture.presenter.offersPasswordUnlock)
        XCTAssertFalse(
            fixture.presenter.composesPasswordPrimary,
            "High Security keeps the existing failure/retry surface."
        )

        // The request is a no-op outside Standard mode…
        fixture.presenter.requestPasswordUnlock()
        do {
            _ = try await fixture.presenter.evaluateAppSessionUnlock(reason: "test")
            XCTFail("Expected the attempt to fail fast.")
        } catch {}
        // …so the detached sheet can never run in High Security.
        XCTAssertEqual(fixture.password.invocationCount, 0)
    }

    // MARK: - The explicit password action

    func test_passwordRequest_fromSettledState_runsDetachedSheetOnce() async throws {
        let fixture = Fixture()
        fixture.password.outcome = .success(.authenticated(context: LAContext()))
        fixture.presenter.requestPasswordUnlock()

        let result = try await fixture.presenter.evaluateAppSessionUnlock(reason: "test")
        XCTAssertTrue(result.isAuthenticated)
        XCTAssertEqual(fixture.password.invocationCount, 1)
        XCTAssertEqual(
            fixture.embedded.invocationCount,
            0,
            "An explicit password attempt never presents the embedded prompt."
        )

        // One-shot: the next attempt is embedded again.
        _ = try await evaluateSimulatingMount(fixture)
        XCTAssertEqual(fixture.embedded.invocationCount, 1)
        XCTAssertEqual(fixture.password.invocationCount, 1)
    }

    func test_passwordRequest_duringEmbeddedAttempt_continuesSameAttemptOnSheet() async throws {
        let fixture = Fixture()
        fixture.embedded.pause = true
        fixture.password.outcome = .success(.authenticated(context: LAContext()))
        let embeddedStarted = expectation(description: "embedded evaluation started")
        fixture.embedded.onSuspended = { embeddedStarted.fulfill() }

        let driver = AttemptDriver(fixture.presenter)
        while fixture.presenter.presentedEmbeddedContext == nil {
            await Task.yield()
        }
        let context = try XCTUnwrap(fixture.presenter.presentedEmbeddedContext)
        fixture.presenter.embeddedAuthenticationViewDidMount(for: context)
        await fulfillment(of: [embeddedStarted], timeout: 2)

        // "Use Password…" while the embedded prompt pends: in production the
        // request invalidates the context and the pending evaluation fails
        // with a cancellation; the stub reproduces that failure.
        fixture.presenter.requestPasswordUnlock()
        fixture.embedded.outcome = .failure(AuthenticationError.cancelled)
        fixture.embedded.resume()

        let result = try await driver.settledOutcome().get()
        XCTAssertTrue(result.isAuthenticated)
        XCTAssertEqual(fixture.embedded.invocationCount, 1)
        XCTAssertEqual(
            fixture.password.invocationCount,
            1,
            "The SAME attempt continues on the detached sheet — no intermediate failure state."
        )
    }

    // MARK: - Cancellation (the controller's away/lockNow seam)

    func test_cancelEmbeddedEvaluationIfInFlight_reportsAndUnblocksPendingMountWait() async throws {
        let fixture = Fixture()
        XCTAssertFalse(
            fixture.presenter.cancelEmbeddedEvaluationIfInFlight(),
            "No embedded attempt in flight — the away rule must keep the system-sheet swallow."
        )

        fixture.embedded.outcome = .failure(AuthenticationError.cancelled)
        let driver = AttemptDriver(fixture.presenter)
        while fixture.presenter.presentedEmbeddedContext == nil {
            await Task.yield()
        }

        // Cancel BEFORE any mount signal: the pending mount wait must resolve
        // so the attempt reaches the (now invalidated) evaluation and settles
        // instead of hanging in `.authenticating` forever.
        XCTAssertTrue(fixture.presenter.cancelEmbeddedEvaluationIfInFlight())
        let outcome = try await driver.settledOutcome()
        if case .success = outcome {
            XCTFail("Expected the cancelled attempt to throw.")
        }
        XCTAssertEqual(fixture.embedded.invocationCount, 1)
        XCTAssertNil(fixture.presenter.presentedEmbeddedContext)
    }

    // MARK: - Availability refresh

    func test_availabilityRefreshes_atAttemptBoundaries() async {
        let fixture = Fixture()
        fixture.availability = .available
        XCTAssertEqual(fixture.presenter.embeddedBiometricsAvailability, .available)

        // Lockout happens while idle (e.g. failed attempts elsewhere): the
        // next attempt re-probes, fails fast, and the surface recomposes.
        fixture.availability = .lockedOut
        do {
            _ = try await fixture.presenter.evaluateAppSessionUnlock(reason: "test")
            XCTFail("Expected the attempt to fail fast.")
        } catch {}
        XCTAssertEqual(fixture.presenter.embeddedBiometricsAvailability, .lockedOut)
        XCTAssertTrue(fixture.presenter.composesPasswordPrimary)
    }
}
