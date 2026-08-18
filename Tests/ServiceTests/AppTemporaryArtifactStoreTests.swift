import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class AppTemporaryArtifactStoreTests: XCTestCase {
    func test_appTemporaryArtifactStore_operationArtifactsUseUniqueOwnerDirectoriesAndProtection() throws {
        let store = CypherAir.AppTemporaryArtifactStore()
        let inputURL = URL(fileURLWithPath: "/tmp/repeated-name.txt")

        let first = try store.makeStreamingArtifact(for: inputURL)
        let second = try store.makeStreamingArtifact(for: inputURL)
        defer {
            first.cleanup()
            second.cleanup()
        }

        XCTAssertNotEqual(first.fileURL, second.fileURL)
        XCTAssertNotEqual(first.ownerDirectoryURL, second.ownerDirectoryURL)
        XCTAssertEqual(first.fileURL.lastPathComponent, "repeated-name.txt.gpg")
        XCTAssertTrue(first.fileURL.path.contains("/streaming/op-"))
        try assertCompleteFileProtection(at: try XCTUnwrap(first.ownerDirectoryURL))
        try assertCompleteFileProtection(at: try XCTUnwrap(second.ownerDirectoryURL))
    }

    /// The sweep no longer finishes before the session starts, so "present in
    /// `tmp/`" no longer means "abandoned". Everything this store handed out has
    /// to survive it — an export the share sheet is still offering, an operation
    /// that started while the sweep was running — and the root above a surviving
    /// operation has to survive with it.
    func test_sweepAbandonedArtifacts_sparesWhatThisSessionOwns() throws {
        let temporaryDirectory = try makeTemporaryDirectory()
        let store = CypherAir.AppTemporaryArtifactStore(temporaryDirectory: temporaryDirectory)

        let abandonedOperation = temporaryDirectory
            .appendingPathComponent("decrypted/op-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: abandonedOperation, withIntermediateDirectories: true)
        try Data("stale plaintext".utf8).write(to: abandonedOperation.appendingPathComponent("output"))
        let abandonedExport = temporaryDirectory
            .appendingPathComponent("export-\(UUID().uuidString)-stale.asc")
        try Data("stale export".utf8).write(to: abandonedExport)

        let liveOperation = try XCTUnwrap(store.makeDecryptedArtifact(for: "message.gpg").ownerDirectoryURL)
        let liveExport = try store.writeProtectedExportData(Data("live".utf8), suggestedFilename: "key.asc")

        let result = store.sweepAbandonedArtifacts()

        XCTAssertTrue(result.failures.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: abandonedOperation.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: abandonedExport.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: liveOperation.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: liveExport.path))
        // The root is only dropped when the sweep emptied it, and this one still
        // holds a live operation.
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: temporaryDirectory.appendingPathComponent("decrypted").path
        ))
    }

    /// The reset is the other scope: the session is being destroyed, so its live
    /// artifacts go too, and the roots go with them — which is what keeps the
    /// reset's own post-condition answerable.
    func test_removeAllTemporaryArtifacts_takesLiveArtifactsAndLeavesNothingRemaining() throws {
        let temporaryDirectory = try makeTemporaryDirectory()
        let store = CypherAir.AppTemporaryArtifactStore(temporaryDirectory: temporaryDirectory)

        let liveOperation = try XCTUnwrap(store.makeDecryptedArtifact(for: "message.gpg").ownerDirectoryURL)
        let liveExport = try store.writeProtectedExportData(Data("live".utf8), suggestedFilename: "key.asc")

        let result = store.removeAllTemporaryArtifacts()

        XCTAssertTrue(result.failures.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: liveOperation.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: liveExport.path))
        XCTAssertTrue(store.remainingTemporaryArtifacts().isEmpty)
    }

    private func makeTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirArtifactStoreTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        return directory
    }

    private func assertCompleteFileProtection(
        at url: URL,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual(
            attributes[.protectionKey] as? FileProtectionType,
            .complete,
            file: file,
            line: line
        )
    }
}
