import Foundation
import XCTest
@testable import CypherAir

/// The overwrite is what separates this from `removeItem`, and it is invisible
/// once the file is gone — so every case here observes it through a second hard
/// link to the same inode, which survives the unlink and shows what the bytes
/// became.
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

    func test_erase_overwritesFileContentsBeforeUnlinking() throws {
        // Past one chunk with a partial tail, the only interesting size.
        let plaintext = Data(repeating: 0x41, count: 64 * 1024 + 17)
        let output = root.appendingPathComponent("decrypted-output")
        try plaintext.write(to: output)
        let witness = try makeWitness(for: output)

        try TemporaryArtifactEraser.erase(at: output)

        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        XCTAssertEqual(try Data(contentsOf: witness), Data(count: plaintext.count))
    }

    func test_erase_overwritesEveryFileInAnOwnedDirectory() throws {
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

        try TemporaryArtifactEraser.erase(at: owned)

        XCTAssertFalse(FileManager.default.fileExists(atPath: owned.path))
        XCTAssertEqual(try Data(contentsOf: topWitness), Data(count: topPlaintext.count))
        XCTAssertEqual(try Data(contentsOf: hiddenWitness), Data(count: hiddenPlaintext.count))
    }

    func test_erase_doesNotWriteThroughASymbolicLink() throws {
        let outsiderContents = Data("belongs to someone else".utf8)
        let outsider = root.appendingPathComponent("outsider")
        try outsiderContents.write(to: outsider)

        let owned = root.appendingPathComponent("op-with-link", isDirectory: true)
        try FileManager.default.createDirectory(at: owned, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(
            at: owned.appendingPathComponent("link"),
            withDestinationURL: outsider
        )

        try TemporaryArtifactEraser.erase(at: owned)

        XCTAssertFalse(FileManager.default.fileExists(atPath: owned.path))
        XCTAssertEqual(try Data(contentsOf: outsider), outsiderContents)
    }

    func test_appTemporaryArtifactCleanup_erasesTheOwnedDirectory() throws {
        let owned = root.appendingPathComponent("op-artifact", isDirectory: true)
        try FileManager.default.createDirectory(at: owned, withIntermediateDirectories: true)
        let plaintext = Data("decrypted plaintext".utf8)
        let output = owned.appendingPathComponent("decrypted")
        try plaintext.write(to: output)
        let witness = try makeWitness(for: output)

        AppTemporaryArtifact(fileURL: output, ownerDirectoryURL: owned).cleanup()

        XCTAssertFalse(FileManager.default.fileExists(atPath: owned.path))
        XCTAssertEqual(try Data(contentsOf: witness), Data(count: plaintext.count))
    }

    private func makeWitness(for url: URL) throws -> URL {
        let witness = root.appendingPathComponent("witness-\(UUID().uuidString)")
        try FileManager.default.linkItem(at: url, to: witness)
        return witness
    }
}
