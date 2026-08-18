import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class AppStartupCoordinatorTests: XCTestCase {
    func test_appStartupCoordinator_cleansTemporaryArtifacts() throws {
        let baseDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirStartupTemp-\(UUID().uuidString)", isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: baseDirectory)
        }
        try makeSweepableTemporaryArtifacts(in: baseDirectory)

        let store = CypherAir.AppTemporaryArtifactStore(temporaryDirectory: baseDirectory)
        AppStartupCoordinator().cleanupTemporaryFiles(
            temporaryArtifactStore: store
        )

        XCTAssertTrue(store.remainingTemporaryArtifacts().isEmpty)
    }

    /// Launch schedules the sweep rather than running it, so the wiring that
    /// makes it happen at all is worth its own case: nothing on the launch path
    /// blocks on it, and it still finishes.
    func test_appStartupCoordinator_scheduledCleanupSweepsWithoutBlockingTheCaller() async throws {
        let baseDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirScheduledSweep-\(UUID().uuidString)", isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: baseDirectory)
        }
        try makeSweepableTemporaryArtifacts(in: baseDirectory)

        let store = CypherAir.AppTemporaryArtifactStore(temporaryDirectory: baseDirectory)
        AppStartupCoordinator().scheduleTemporaryFileCleanup(temporaryArtifactStore: store)

        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline, !store.remainingTemporaryArtifacts().isEmpty {
            await Task.yield()
        }
        XCTAssertTrue(store.remainingTemporaryArtifacts().isEmpty)
    }

    func test_appStartupCoordinator_mergedStartupMessages_joinsAndDeduplicatesRecoveryDiagnostics() {
        let coordinator = AppStartupCoordinator()
        let merged = coordinator.mergedStartupMessages(
            recoveryDiagnostics: [
                "Protected app data is unavailable and may require recovery.",
                "Protected app data has pending recovery work that must complete before protected content can open.",
                "Protected app data is unavailable and may require recovery."
            ]
        )

        XCTAssertEqual(
            merged,
            """
            Protected app data is unavailable and may require recovery.
            Protected app data has pending recovery work that must complete before protected content can open.
            """
        )
    }

    func test_appStartupCoordinator_mergedStartupMessages_recoveryDiagnostic_isGeneric() {
        let coordinator = AppStartupCoordinator()
        let merged = coordinator.mergedStartupMessages(
            recoveryDiagnostics: [
                "A previous secure key protection change could not be fully recovered. CypherAir X will retry recovery on next launch."
            ]
        )

        XCTAssertNotNil(merged)
        XCTAssertFalse(merged?.contains("fingerprint") == true)
        XCTAssertFalse(merged?.contains("89abcdef") == true)
    }


    private func makeSweepableTemporaryArtifacts(in temporaryDirectory: URL) throws {
        let decryptedDir = temporaryDirectory.appendingPathComponent("decrypted", isDirectory: true)
        let streamingDir = temporaryDirectory.appendingPathComponent("streaming", isDirectory: true)
        let exportURL = temporaryDirectory.appendingPathComponent("export-\(UUID().uuidString)-sample.asc")

        try FileManager.default.createDirectory(
            at: decryptedDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: streamingDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try Data("export".utf8).write(to: exportURL, options: .atomic)
    }
}
