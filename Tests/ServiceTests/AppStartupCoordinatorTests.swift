import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class AppStartupCoordinatorTests: TutorialSandboxDefaultsSerializedTestCase {
    func test_appStartupCoordinator_cleansTemporaryArtifactsAndTutorialSandboxDefaults() throws {
        let baseDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirStartupTemp-\(UUID().uuidString)", isDirectory: true)
        let preferencesDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirStartupPrefs-\(UUID().uuidString)", isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: baseDirectory)
            try? FileManager.default.removeItem(at: preferencesDirectory)
        }
        try makeSweepableTemporaryArtifacts(in: baseDirectory)
        try FileManager.default.createDirectory(at: preferencesDirectory, withIntermediateDirectories: true)
        let fixedTutorialSuiteName = AppTemporaryArtifactStore.tutorialSandboxDefaultsSuiteName
        let fixedTutorialPlist = preferencesDirectory.appendingPathComponent("\(fixedTutorialSuiteName).plist")
        try Data("fixed".utf8).write(to: fixedTutorialPlist, options: .atomic)
        let unrelatedSuiteName = "com.cypherair.tests.startup.\(UUID().uuidString)"
        let unrelatedPlist = preferencesDirectory.appendingPathComponent("\(unrelatedSuiteName).plist")
        try Data("keep".utf8).write(to: unrelatedPlist, options: .atomic)

        let store = CypherAir.AppTemporaryArtifactStore(
            temporaryDirectory: baseDirectory,
            preferencesDirectory: preferencesDirectory
        )
        AppStartupCoordinator().cleanupTemporaryFiles(
            temporaryArtifactStore: store
        )

        XCTAssertTrue(store.remainingTemporaryArtifacts().isEmpty)
        XCTAssertTrue(store.remainingTutorialSandboxDefaultsSuites().isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixedTutorialPlist.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: unrelatedPlist.path))
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
        let tutorialDir = temporaryDirectory
            .appendingPathComponent("CypherAirGuidedTutorial-\(UUID().uuidString)", isDirectory: true)

        try FileManager.default.createDirectory(
            at: decryptedDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: streamingDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(at: tutorialDir, withIntermediateDirectories: true)
        try Data("export".utf8).write(to: exportURL, options: .atomic)
    }
}
