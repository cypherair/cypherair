import Foundation
import XCTest
@testable import CypherAir

/// The overwrite is invisible once the file is gone, so every case here observes
/// it through a second hard link to the same inode: the link survives the unlink
/// and shows what the bytes became. The two phases are exercised separately
/// because they carry different promises — the path goes away synchronously, the
/// zero pass does not have to.
final class TemporaryArtifactEraserTests: XCTestCase {
    private var root = URL(fileURLWithPath: "/")

    override func setUpWithError() throws {
        try super.setUpWithError()
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirEraserTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
        try super.tearDownWithError()
    }

    func test_unlinkRetainingContents_removesThePathBeforeAnyByteIsWritten() throws {
        // Past one chunk with a partial tail, the only interesting size.
        let plaintext = Data(repeating: 0x41, count: 64 * 1024 + 17)
        let output = root.appendingPathComponent("decrypted-output")
        try plaintext.write(to: output)
        let witness = try makeWitness(for: output)

        let pending = try TemporaryArtifactEraser.unlinkRetainingContents(at: output)

        // The half with the deadline: the name is gone, and the bytes are still
        // intact behind the surviving link — nothing was written on this thread.
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        XCTAssertEqual(try Data(contentsOf: witness), plaintext)

        pending.overwriteNow()

        XCTAssertEqual(try Data(contentsOf: witness), Data(count: plaintext.count))
    }

    func test_unlinkRetainingContents_overwritesEveryFileInAnOwnedDirectory() throws {
        let owned = root.appendingPathComponent("op-tree", isDirectory: true)
        let nested = owned.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        let topPlaintext = Data("top-level plaintext".utf8)
        let top = owned.appendingPathComponent("output")
        try topPlaintext.write(to: top)
        let topWitness = try makeWitness(for: top)

        let hiddenPlaintext = Data("plaintext under a dot-name".utf8)
        let hidden = nested.appendingPathComponent(".sidecar")
        try hiddenPlaintext.write(to: hidden)
        let hiddenWitness = try makeWitness(for: hidden)

        try TemporaryArtifactEraser.unlinkRetainingContents(at: owned).overwriteNow()

        XCTAssertFalse(FileManager.default.fileExists(atPath: owned.path))
        XCTAssertEqual(try Data(contentsOf: topWitness), Data(count: topPlaintext.count))
        XCTAssertEqual(try Data(contentsOf: hiddenWitness), Data(count: hiddenPlaintext.count))
    }

    func test_unlinkRetainingContents_doesNotWriteThroughASymbolicLinkToAFile() throws {
        let outsiderContents = Data("belongs to someone else".utf8)
        let outsider = root.appendingPathComponent("outsider")
        try outsiderContents.write(to: outsider)

        let owned = root.appendingPathComponent("op-with-file-link", isDirectory: true)
        try FileManager.default.createDirectory(at: owned, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(
            at: owned.appendingPathComponent("link"),
            withDestinationURL: outsider
        )

        try TemporaryArtifactEraser.unlinkRetainingContents(at: owned).overwriteNow()

        XCTAssertFalse(FileManager.default.fileExists(atPath: owned.path))
        XCTAssertEqual(try Data(contentsOf: outsider), outsiderContents)
    }

    /// The catastrophic case: descending a linked directory would erase a tree
    /// the artifact does not own.
    func test_unlinkRetainingContents_doesNotDescendASymbolicLinkToADirectory() throws {
        let outsiderDirectory = root.appendingPathComponent("outsider-tree", isDirectory: true)
        try FileManager.default.createDirectory(at: outsiderDirectory, withIntermediateDirectories: true)
        let outsiderContents = Data("belongs to someone else".utf8)
        let outsiderFile = outsiderDirectory.appendingPathComponent("kept")
        try outsiderContents.write(to: outsiderFile)

        let owned = root.appendingPathComponent("op-with-directory-link", isDirectory: true)
        try FileManager.default.createDirectory(at: owned, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(
            at: owned.appendingPathComponent("link"),
            withDestinationURL: outsiderDirectory
        )

        try TemporaryArtifactEraser.unlinkRetainingContents(at: owned).overwriteNow()

        XCTAssertFalse(FileManager.default.fileExists(atPath: owned.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: outsiderDirectory.path))
        XCTAssertEqual(try Data(contentsOf: outsiderFile), outsiderContents)
    }

    func test_appTemporaryArtifactCleanup_erasesTheOwnedDirectory() async throws {
        let owned = root.appendingPathComponent("op-artifact", isDirectory: true)
        try FileManager.default.createDirectory(at: owned, withIntermediateDirectories: true)
        let plaintext = Data("decrypted plaintext".utf8)
        let output = owned.appendingPathComponent("decrypted")
        try plaintext.write(to: output)
        let witness = try makeWitness(for: output)

        AppTemporaryArtifact(
            fileURL: output,
            exportFilename: ExportFilename("decrypted"),
            ownerDirectoryURL: owned
        ).cleanup()

        XCTAssertFalse(FileManager.default.fileExists(atPath: owned.path))
        await waitUntil("the scheduled zero pass to reach the artifact's bytes") {
            (try? Data(contentsOf: witness)) == Data(count: plaintext.count)
        }
    }

    private func makeWitness(for url: URL) throws -> URL {
        let witness = root.appendingPathComponent("witness-\(UUID().uuidString)")
        try FileManager.default.linkItem(at: url, to: witness)
        return witness
    }

    private func waitUntil(
        _ description: String,
        timeout: TimeInterval = 5,
        condition: () -> Bool
    ) async {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() {
                return
            }
            await Task.yield()
        }
        XCTFail("Timed out waiting for \(description)")
    }
}
