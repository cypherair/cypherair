import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class FileOperationActionTests: XCTestCase {
    @MainActor
    func test_fileOperationAction_injectedActionSkipsDefaultAction() async throws {
        let progress = FileProgressReporter()
        var defaultCalled = false
        let action = FileOperationAction<String, String>(
            injectedAction: { request in
                "injected-\(request)"
            },
            defaultAction: { _, _ in
                defaultCalled = true
                return "default"
            }
        )

        let result = try await action("request", progress: progress)

        XCTAssertEqual(result, "injected-request")
        XCTAssertFalse(defaultCalled)
    }

    @MainActor
    func test_fileOperationAction_defaultReceivesCallerProgress() async throws {
        let expectedProgress = FileProgressReporter()
        var receivedProgress: FileProgressReporter?
        let action = FileOperationAction<Int, Int>(
            injectedAction: nil,
            defaultAction: { request, progress in
                receivedProgress = progress
                return request + 1
            }
        )

        let result = try await action(1, progress: expectedProgress)

        XCTAssertEqual(result, 2)
        XCTAssertTrue(receivedProgress === expectedProgress)
    }

    @MainActor
    func test_fileOperationAction_defaultPreservesCancelledCallerProgress() async throws {
        let cancelledProgress = FileProgressReporter()
        cancelledProgress.cancel()
        var receivedProgress: FileProgressReporter?
        let action = FileOperationAction<String, Bool>(
            injectedAction: nil,
            defaultAction: { _, progress in
                receivedProgress = progress
                return progress.isCancelled
            }
        )

        let result = try await action("request", progress: cancelledProgress)

        XCTAssertTrue(result)
        XCTAssertTrue(receivedProgress === cancelledProgress)
    }
}
