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
