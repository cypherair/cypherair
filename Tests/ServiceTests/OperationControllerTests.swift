import Foundation
import XCTest
@testable import CypherAir

private actor RunnerCallCounter {
    var count = 0

    func increment() {
        count += 1
    }

    func currentValue() -> Int {
        count
    }
}

@MainActor
private final class OperationGate {
    private var continuations: [Int: CheckedContinuation<Void, Never>] = [:]

    func suspend(operationID: Int) async {
        await withCheckedContinuation { continuation in
            continuations[operationID] = continuation
        }
    }

    func isSuspended(operationID: Int) -> Bool {
        continuations[operationID] != nil
    }

    func resume(operationID: Int) {
        continuations.removeValue(forKey: operationID)?.resume()
    }
}

private enum CommonHelpersTestError: Error {
    case delayedFailure
}

@MainActor
final class OperationControllerTests: XCTestCase {
    func test_operationController_runFileOperation_usesBackgroundRunnerAndClearsState() async {
        let runnerCallCounter = RunnerCallCounter()
        let controller = OperationController(
            backgroundRunner: { operation in
                await runnerCallCounter.increment()
                try await operation()
            }
        )

        controller.runFileOperation(
            mapError: { _ in .internalError(reason: "unexpected") }
        ) { progress in
            _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
        }

        while controller.isRunning {
            await Task.yield()
        }

        let runnerCallCount = await runnerCallCounter.currentValue()
        XCTAssertEqual(runnerCallCount, 1)
        XCTAssertNil(controller.progress)
        XCTAssertFalse(controller.isShowingError)
    }

    func test_operationController_copyToClipboard_showsNoticeWhenRequested() {
        let controller = OperationController()

        controller.copyToClipboard("ciphertext", shouldShowNotice: true)

        XCTAssertTrue(controller.isShowingClipboardNotice)
    }

    func test_operationController_copyToClipboard_skipsNoticeWhenDisabled() {
        let controller = OperationController()

        controller.copyToClipboard("ciphertext", shouldShowNotice: false)

        XCTAssertFalse(controller.isShowingClipboardNotice)
    }

    func test_operationController_cancel_keepsBusyUntilTaskFinishes() async {
        let gate = OperationGate()
        let controller = OperationController()

        controller.runFileOperation(mapError: { _ in .internalError(reason: "unexpected") }) { progress in
            _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
            await gate.suspend(operationID: 1)
        }

        await waitUntil("operation to suspend before cancellation") {
            guard controller.isRunning, controller.progress != nil else { return false }
            return gate.isSuspended(operationID: 1)
        }

        controller.cancel()

        XCTAssertTrue(controller.isRunning)
        XCTAssertTrue(controller.isCancelling)
        XCTAssertNotNil(controller.progress)

        gate.resume(operationID: 1)

        await waitUntil("controller to finish cancelling") {
            controller.isRunning == false
        }

        XCTAssertFalse(controller.isCancelling)
        XCTAssertNil(controller.progress)
        XCTAssertFalse(controller.isShowingError)
    }

    func test_operationController_staleCompletionDoesNotClearReplacementOperation() async {
        let gate = OperationGate()
        let controller = OperationController()
        var startedOperations = 0

        controller.runFileOperation(mapError: { _ in .internalError(reason: "unexpected") }) { progress in
            startedOperations += 1
            let operationID = startedOperations
            _ = progress.onProgress(bytesProcessed: UInt64(operationID), totalBytes: 10)
            await gate.suspend(operationID: operationID)
        }

        await waitUntil("first operation to suspend") {
            guard controller.isRunning, controller.progress != nil else { return false }
            return gate.isSuspended(operationID: 1)
        }

        controller.cancel()
        controller.runFileOperation(mapError: { _ in .internalError(reason: "unexpected") }) { progress in
            startedOperations += 1
            let operationID = startedOperations
            _ = progress.onProgress(bytesProcessed: UInt64(operationID), totalBytes: 10)
            await gate.suspend(operationID: operationID)
        }

        await waitUntil("replacement operation to suspend") {
            guard controller.isRunning, !controller.isCancelling else { return false }
            return gate.isSuspended(operationID: 2)
        }

        let replacementProgress = controller.progress
        gate.resume(operationID: 1)
        await Task.yield()
        await Task.yield()

        XCTAssertTrue(controller.isRunning)
        XCTAssertFalse(controller.isCancelling)
        XCTAssertTrue(controller.progress === replacementProgress)

        gate.resume(operationID: 2)
        await waitUntil("replacement operation to finish") {
            controller.isRunning == false
        }
    }

    func test_operationController_staleErrorDoesNotSurfaceForReplacementOperation() async {
        let gate = OperationGate()
        let controller = OperationController()
        var startedOperations = 0

        controller.run(mapError: { _ in .internalError(reason: "stale failure") }) {
            startedOperations += 1
            let operationID = startedOperations
            await gate.suspend(operationID: operationID)
            if operationID == 1 {
                throw CommonHelpersTestError.delayedFailure
            }
        }

        await waitUntil("first operation to suspend") {
            guard controller.isRunning else { return false }
            return gate.isSuspended(operationID: 1)
        }

        controller.cancel()
        controller.run(mapError: { _ in .internalError(reason: "replacement failure") }) {
            startedOperations += 1
            let operationID = startedOperations
            await gate.suspend(operationID: operationID)
        }

        await waitUntil("replacement operation to suspend") {
            guard controller.isRunning, !controller.isCancelling else { return false }
            return gate.isSuspended(operationID: 2)
        }

        gate.resume(operationID: 1)
        await Task.yield()
        await Task.yield()

        XCTAssertFalse(controller.isShowingError)
        XCTAssertNil(controller.error)

        gate.resume(operationID: 2)
        await waitUntil("replacement operation to finish") {
            controller.isRunning == false
        }

        XCTAssertFalse(controller.isShowingError)
        XCTAssertNil(controller.error)
    }

    private func waitUntil(
        _ description: String,
        timeoutNanoseconds: UInt64 = 1_000_000_000,
        condition: @escaping @MainActor () async -> Bool
    ) async {
        let deadline = DispatchTime.now().uptimeNanoseconds + timeoutNanoseconds
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if await condition() {
                return
            }
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTFail("Timed out waiting for \(description)")
    }
}
