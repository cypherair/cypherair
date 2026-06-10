import LocalAuthentication
import XCTest
@testable import CypherAir

#if os(macOS)
/// Unit tests for the `MacAuthenticationPresenter` presentation core (P3 in-window
/// authentication seam). These drive `presentingEvaluation` with test closures —
/// never a real LocalAuthentication evaluation — and exercise the serialization,
/// view-mount handshake, teardown, and cancellation behavior the host relies on.
@MainActor
final class MacAuthenticationPresenterTests: XCTestCase {
    private enum TestError: Error, Equatable {
        case evaluationFailed
    }

    /// Mutable flag shared with `@Sendable` evaluation closures; all mutation
    /// happens on the main actor (the presenter runs evaluations there).
    private final class Flag: @unchecked Sendable {
        var isSet = false
    }

    /// One-shot async gate so a test can hold an evaluation open.
    private final class Gate: @unchecked Sendable {
        private var continuation: CheckedContinuation<Void, Never>?
        private var isOpen = false

        @MainActor
        func wait() async {
            if isOpen { return }
            await withCheckedContinuation { continuation = $0 }
        }

        @MainActor
        func open() {
            isOpen = true
            continuation?.resume()
            continuation = nil
        }
    }

    private func makeRequest(source: String = "test") -> AuthenticationPresentationRequest {
        AuthenticationPresentationRequest(
            localizedReason: "test reason",
            purpose: .perOperation,
            source: source
        )
    }

    private func waitForActivePresentation(
        _ presenter: MacAuthenticationPresenter,
        excludingID excluded: Int? = nil
    ) async throws -> MacAuthenticationPresenter.ActivePresentation {
        for _ in 0..<10_000 {
            if let presentation = presenter.activePresentation, presentation.id != excluded {
                return presentation
            }
            await Task.yield()
        }
        XCTFail("Timed out waiting for an active presentation")
        throw TestError.evaluationFailed
    }

    func test_presentingEvaluation_gatesEvaluationOnViewMount_andTearsDown() async throws {
        let presenter = MacAuthenticationPresenter()
        let evaluated = Flag()
        let context = LAContext()
        let expectedContextID = ObjectIdentifier(context)
        let evaluatedContext = Flag()

        let task = Task {
            try await presenter.presentingEvaluation(
                context: context,
                request: makeRequest()
            ) { evaluationContext throws in
                evaluated.isSet = true
                evaluatedContext.isSet = ObjectIdentifier(evaluationContext) == expectedContextID
                return 42
            }
        }

        let presentation = try await waitForActivePresentation(presenter)
        XCTAssertTrue(presentation.context === context, "Host must mount the caller's context")
        XCTAssertEqual(presentation.request.source, "test")
        XCTAssertFalse(evaluated.isSet, "Evaluation must not run before the view-mount handshake")

        presenter.viewDidMount(presentation.id)
        let value = try await task.value

        XCTAssertEqual(value, 42)
        XCTAssertTrue(evaluated.isSet)
        XCTAssertTrue(evaluatedContext.isSet, "Evaluation must receive the same context the host mounted")
        XCTAssertNil(presenter.activePresentation, "Teardown must clear the presentation")
    }

    func test_presentingEvaluation_serializesOverlappingPresentations_inOrder() async throws {
        let presenter = MacAuthenticationPresenter()
        let gate = Gate()

        let first = Task {
            try await presenter.presentingEvaluation(
                context: LAContext(),
                request: makeRequest(source: "first")
            ) { _ in
                await gate.wait()
                return "first"
            }
        }
        let firstPresentation = try await waitForActivePresentation(presenter)
        XCTAssertEqual(firstPresentation.request.source, "first")
        presenter.viewDidMount(firstPresentation.id)

        let second = Task {
            try await presenter.presentingEvaluation(
                context: LAContext(),
                request: makeRequest(source: "second")
            ) { _ in "second" }
        }
        // Give the second presentation every chance to (incorrectly) preempt.
        for _ in 0..<50 { await Task.yield() }
        XCTAssertEqual(
            presenter.activePresentation?.id,
            firstPresentation.id,
            "An overlapping presentation must queue behind the active one"
        )

        gate.open()
        let firstValue = try await first.value
        XCTAssertEqual(firstValue, "first")

        let secondPresentation = try await waitForActivePresentation(
            presenter,
            excludingID: firstPresentation.id
        )
        XCTAssertEqual(secondPresentation.request.source, "second")
        presenter.viewDidMount(secondPresentation.id)
        let secondValue = try await second.value
        XCTAssertEqual(secondValue, "second")
        XCTAssertNil(presenter.activePresentation)
    }

    func test_presentingEvaluation_tearsDownWhenEvaluationThrows() async throws {
        let presenter = MacAuthenticationPresenter()

        let task = Task {
            try await presenter.presentingEvaluation(
                context: LAContext(),
                request: makeRequest()
            ) { _ -> Int in
                throw TestError.evaluationFailed
            }
        }
        let presentation = try await waitForActivePresentation(presenter)
        presenter.viewDidMount(presentation.id)

        do {
            _ = try await task.value
            XCTFail("Expected the evaluation error to propagate")
        } catch let error as TestError {
            XCTAssertEqual(error, .evaluationFailed)
        }
        XCTAssertNil(presenter.activePresentation, "Teardown must clear the presentation on failure")

        // The hand-off mutex must be released: a subsequent presentation runs.
        let next = Task {
            try await presenter.presentingEvaluation(
                context: LAContext(),
                request: makeRequest(source: "next")
            ) { _ in true }
        }
        let nextPresentation = try await waitForActivePresentation(presenter)
        presenter.viewDidMount(nextPresentation.id)
        let nextValue = try await next.value
        XCTAssertTrue(nextValue)
    }

    func test_viewDidMount_ignoresStaleIdentifier() async throws {
        let presenter = MacAuthenticationPresenter()
        let evaluated = Flag()

        let task = Task {
            try await presenter.presentingEvaluation(
                context: LAContext(),
                request: makeRequest()
            ) { _ in
                evaluated.isSet = true
                return true
            }
        }
        let presentation = try await waitForActivePresentation(presenter)

        presenter.viewDidMount(presentation.id - 1)
        for _ in 0..<50 { await Task.yield() }
        XCTAssertFalse(evaluated.isSet, "A stale host must not release the mount handshake")

        presenter.viewDidMount(presentation.id)
        _ = try await task.value
        XCTAssertTrue(evaluated.isSet)
    }

    func test_cancellationWhileAwaitingMount_throwsAndReleasesPresenter() async throws {
        let presenter = MacAuthenticationPresenter()
        let evaluated = Flag()

        let task = Task {
            try await presenter.presentingEvaluation(
                context: LAContext(),
                request: makeRequest()
            ) { _ in
                evaluated.isSet = true
                return true
            }
        }
        _ = try await waitForActivePresentation(presenter)
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("Expected cancellation to propagate")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertFalse(evaluated.isSet, "A cancelled presentation must not evaluate")
        XCTAssertNil(presenter.activePresentation)

        // The presenter must remain usable after a cancelled presentation.
        let next = Task {
            try await presenter.presentingEvaluation(
                context: LAContext(),
                request: makeRequest(source: "next")
            ) { _ in true }
        }
        let nextPresentation = try await waitForActivePresentation(presenter)
        presenter.viewDidMount(nextPresentation.id)
        let nextValue = try await next.value
        XCTAssertTrue(nextValue)
    }
}
#endif

/// `PassthroughAuthenticationPresenter` must be a pure pass-through on every
/// platform: same context in, evaluation result out, no presentation state.
final class PassthroughAuthenticationPresenterTests: XCTestCase {
    func test_presentingEvaluation_runsEvaluationVerbatim() async throws {
        let presenter = PassthroughAuthenticationPresenter()
        let context = LAContext()
        let expectedContextID = ObjectIdentifier(context)

        let result = try await presenter.presentingEvaluation(
            context: context,
            request: AuthenticationPresentationRequest(
                localizedReason: "test",
                purpose: .perOperation,
                source: "test"
            )
        ) { evaluationContext throws in
            ObjectIdentifier(evaluationContext) == expectedContextID
                ? "same-context"
                : "different-context"
        }

        XCTAssertEqual(result, "same-context")
    }
}
