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
    /// to survive it — an export the share sheet is still offering, the running
    /// tutorial's store, an operation that started while the sweep was running —
    /// and the root above a surviving operation has to survive with it.
    func test_sweepAbandonedArtifacts_sparesWhatThisSessionOwns() throws {
        let temporaryDirectory = try makeTemporaryDirectory()
        let store = CypherAir.AppTemporaryArtifactStore(
            temporaryDirectory: temporaryDirectory,
            documentInboxDirectory: temporaryDirectory.appendingPathComponent("Inbox", isDirectory: true)
        )

        let abandonedOperation = temporaryDirectory
            .appendingPathComponent("decrypted/op-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: abandonedOperation, withIntermediateDirectories: true)
        try Data("stale plaintext".utf8).write(to: abandonedOperation.appendingPathComponent("output"))
        let abandonedExport = temporaryDirectory
            .appendingPathComponent("export-\(UUID().uuidString)-stale.asc")
        try Data("stale export".utf8).write(to: abandonedExport)

        let liveOperation = try XCTUnwrap(store.makeDecryptedArtifact(for: "message.gpg").ownerDirectoryURL)
        let liveExport = try store.writeProtectedExportData(Data("live".utf8), suggestedFilename: "key.asc")
        let liveTutorial = try store.makeTutorialSandboxDirectory()

        let result = store.sweepAbandonedArtifacts()

        XCTAssertTrue(result.failures.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: abandonedOperation.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: abandonedExport.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: liveOperation.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: liveExport.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: liveTutorial.path))
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
        let store = CypherAir.AppTemporaryArtifactStore(
            temporaryDirectory: temporaryDirectory,
            documentInboxDirectory: temporaryDirectory.appendingPathComponent("Inbox", isDirectory: true)
        )

        let liveOperation = try XCTUnwrap(store.makeDecryptedArtifact(for: "message.gpg").ownerDirectoryURL)
        let liveExport = try store.writeProtectedExportData(Data("live".utf8), suggestedFilename: "key.asc")

        let result = store.removeAllTemporaryArtifacts()

        XCTAssertTrue(result.failures.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: liveOperation.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: liveExport.path))
        XCTAssertTrue(store.remainingTemporaryArtifacts().isEmpty)
    }

    /// The inbox fills up without the app asking, so a document a previous
    /// session was interrupted over is left there — and it is exactly the
    /// unmanaged copy of a reader's file that must not persist.
    func test_sweepAbandonedArtifacts_erasesDocumentsLeftInTheInbox() throws {
        let temporaryDirectory = try makeTemporaryDirectory()
        let inbox = temporaryDirectory.appendingPathComponent("Inbox", isDirectory: true)
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        let abandoned = inbox.appendingPathComponent("handed-over.gpg")
        try Data("someone's message".utf8).write(to: abandoned)

        let store = CypherAir.AppTemporaryArtifactStore(
            temporaryDirectory: temporaryDirectory,
            documentInboxDirectory: inbox
        )

        XCTAssertEqual(store.remainingTemporaryArtifacts(), ["handed-over.gpg"])

        let result = store.sweepAbandonedArtifacts()

        XCTAssertTrue(result.failures.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: abandoned.path))
        XCTAssertTrue(store.remainingTemporaryArtifacts().isEmpty)
    }

    /// Adopting is a move, so the inbox is empty afterwards rather than holding
    /// a second copy someone has to remember to erase.
    func test_adoptOpenedDocument_movesTheInboxCopyUnderTheStore() throws {
        let temporaryDirectory = try makeTemporaryDirectory()
        let inbox = temporaryDirectory.appendingPathComponent("Inbox", isDirectory: true)
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        let handedOver = inbox.appendingPathComponent("handed-over.gpg")
        try Data("someone's message".utf8).write(to: handedOver)

        let store = CypherAir.AppTemporaryArtifactStore(
            temporaryDirectory: temporaryDirectory,
            documentInboxDirectory: inbox
        )
        let artifact = try store.adoptOpenedDocument(at: handedOver)
        defer { artifact.cleanup() }

        XCTAssertFalse(FileManager.default.fileExists(atPath: handedOver.path))
        XCTAssertEqual(artifact.fileURL.lastPathComponent, "handed-over.gpg")
        XCTAssertTrue(artifact.fileURL.path.contains("/opened/op-"))
        XCTAssertEqual(
            try Data(contentsOf: artifact.fileURL),
            Data("someone's message".utf8)
        )
        try assertCompleteFileProtection(at: artifact.fileURL)
    }

    /// The only files the store will delete on an open are the ones the system
    /// copied into the container. A document opened where it lives belongs to
    /// the reader.
    func test_eraseOpenedDocumentCopy_leavesDocumentsOutsideTheInboxAlone() throws {
        let temporaryDirectory = try makeTemporaryDirectory()
        let inbox = temporaryDirectory.appendingPathComponent("Inbox", isDirectory: true)
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        let inPlace = temporaryDirectory.appendingPathComponent("their-own.asc")
        try Data("the reader's file".utf8).write(to: inPlace)

        let store = CypherAir.AppTemporaryArtifactStore(
            temporaryDirectory: temporaryDirectory,
            documentInboxDirectory: inbox
        )

        XCTAssertFalse(store.ownsOpenedDocumentCopy(at: inPlace))
        store.eraseOpenedDocumentCopy(at: inPlace)

        XCTAssertTrue(FileManager.default.fileExists(atPath: inPlace.path))
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
