import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class FileExportControllerTests: XCTestCase {
    func test_fileExportController_prepareDataExport_finishRemovesTemporaryFile() throws {
        let controller = FileExportController()

        try controller.prepareDataExport(
            Data("export me".utf8),
            suggestedFilename: "sample.asc"
        )

        guard let url = controller.payload?.url else {
            XCTFail("Expected a payload URL")
            return
        }

        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        try assertCompleteFileProtection(at: url)
        controller.finish()
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    func test_fileExportController_prepareFileExport_doesNotOwnSourceFile() throws {
        let controller = FileExportController()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirFileExportSource-\(UUID().uuidString).asc")
        try Data("source".utf8).write(to: url, options: .atomic)
        defer { try? FileManager.default.removeItem(at: url) }

        controller.prepareFileExport(fileURL: url, suggestedFilename: "source.asc")

        XCTAssertEqual(controller.payload?.url, url)
        controller.finish()
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
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
