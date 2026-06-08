#if os(macOS)
import LocalAuthentication
import XCTest
@testable import CypherAir

/// PR-1 of the auth-lifecycle redesign (in-window authentication seam). Exercises the
/// `MacAuthenticationPresenter` presentation core — serialization, the view-mount
/// handshake, and teardown — without driving real LocalAuthentication (the `nonisolated`
/// seam entry points that call `evaluatePolicy` / `evaluateAccessControl` are validated
/// on device).
@MainActor
final class MacAuthenticationPresenterTests: XCTestCase {
    /// `@MainActor` reference holder so test closures can record state without capturing
    /// a mutable `var` into a `@Sendable` task closure.
    @MainActor
    private final class Recorder {
        var log: [Int] = []
        var bodyRan = false
    }

    private func makeRequest() -> AuthenticationPresentationRequest {
        AuthenticationPresentationRequest(localizedReason: "test", purpose: .perOperation, source: "test")
    }

    /// Yields the cooperative pool until `condition` holds or a bounded number of
    /// iterations elapse — avoids fixed sleeps; all work is on the main actor.
    private func yieldUntil(_ condition: () -> Bool, iterations: Int = 1000) async {
        var remaining = iterations
        while !condition() && remaining > 0 {
            await Task.yield()
            remaining -= 1
        }
    }

    func testPresentPublishesThenTearsDownAfterViewMount() async {
        let presenter = MacAuthenticationPresenter()
        let recorder = Recorder()
        XCTAssertNil(presenter.activePresentation)

        let task = Task { @MainActor in
            await presenter.present(context: LAContext(), request: makeRequest()) {
                recorder.bodyRan = true
            }
        }

        // The presentation is published, but `body` waits for the view-mount handshake.
        await yieldUntil { presenter.activePresentation != nil }
        XCTAssertNotNil(presenter.activePresentation)
        XCTAssertFalse(recorder.bodyRan)

        presenter.viewDidMount()
        await task.value

        XCTAssertTrue(recorder.bodyRan)
        XCTAssertNil(presenter.activePresentation)
    }

    func testPresentationsSerializeFirstInFirstOut() async {
        let presenter = MacAuthenticationPresenter()
        let recorder = Recorder()

        let first = Task { @MainActor in
            await presenter.present(context: LAContext(), request: makeRequest()) {
                recorder.log.append(1)
            }
        }
        await yieldUntil { presenter.activePresentation != nil }
        let firstID = presenter.activePresentation?.id

        // A second request arrives while the first is still presenting; it must queue
        // (no second presentation is published, no body runs) until the first completes.
        let second = Task { @MainActor in
            await presenter.present(context: LAContext(), request: makeRequest()) {
                recorder.log.append(2)
            }
        }
        await Task.yield()
        await Task.yield()
        XCTAssertEqual(presenter.activePresentation?.id, firstID)
        XCTAssertEqual(recorder.log, [])

        // Complete the first; the second then becomes the active presentation.
        presenter.viewDidMount()
        await first.value
        await yieldUntil { presenter.activePresentation != nil && presenter.activePresentation?.id != firstID }
        XCTAssertEqual(recorder.log, [1])

        presenter.viewDidMount()
        await second.value

        XCTAssertEqual(recorder.log, [1, 2])
        XCTAssertNil(presenter.activePresentation)
    }
}
#endif
