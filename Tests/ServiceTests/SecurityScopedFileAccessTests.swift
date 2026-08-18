import Foundation
import XCTest
@testable import CypherAir

private final class MockScopedResource: SecurityScopedResource {
    var carriesExtension = true
    private(set) var startCalls = 0
    private(set) var stopCalls = 0

    func startAccessingSecurityScopedResource() -> Bool {
        startCalls += 1
        return carriesExtension
    }

    func stopAccessingSecurityScopedResource() {
        stopCalls += 1
    }
}

@MainActor
final class SecurityScopedFileAccessTests: XCTestCase {
    func test_withAccess_releasesEveryClaimedResource() async {
        let first = MockScopedResource()
        let second = MockScopedResource()
        var didRun = false

        await SecurityScopedFileAccess.withAccess(to: [first, second]) {
            didRun = true
        }

        XCTAssertTrue(didRun)
        XCTAssertEqual(first.stopCalls, 1)
        XCTAssertEqual(second.stopCalls, 1)
    }

    /// A file in the app's own container carries no sandbox extension, so
    /// claiming one answers `false`. That is an absence, not a refusal: the work
    /// still runs, and nothing is released that was never held. Opened documents
    /// arrive both ways — in place from Finder or Files, and as a container copy
    /// another app handed over — and one route reads both.
    func test_withAccess_runsWithoutAnExtensionAndReleasesNothing() async {
        let containerFile = MockScopedResource()
        containerFile.carriesExtension = false
        let externalFile = MockScopedResource()
        var didRun = false

        await SecurityScopedFileAccess.withAccess(to: [containerFile, externalFile]) {
            didRun = true
        }

        XCTAssertTrue(didRun)
        XCTAssertEqual(containerFile.startCalls, 1)
        XCTAssertEqual(containerFile.stopCalls, 0)
        XCTAssertEqual(externalFile.stopCalls, 1)
    }

    func test_withAccess_releasesTheClaimWhenTheOperationThrows() throws {
        let resource = MockScopedResource()

        XCTAssertThrowsError(
            try SecurityScopedFileAccess.withAccess(to: resource) {
                throw CypherAirError.operationCancelled
            }
        )
        XCTAssertEqual(resource.stopCalls, 1)
    }
}
