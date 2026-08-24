import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class FileExportControllerTests: XCTestCase {
    func test_fileExportController_prepareDataExport_finishRemovesTemporaryFile() throws {
        let controller = FileExportController()

        try controller.prepareDataExport(
            Data("export me".utf8),
            filename: ExportFilename("sample.asc")
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

    /// The staging path is where an export briefly lives in `tmp/`, and it is
    /// visible to anything that can list that directory. It must not repeat the
    /// name the user picked or the app derived — that name says what the file is.
    func test_fileExportController_prepareDataExport_stagingPathCarriesNoUserFacingName() throws {
        let controller = FileExportController()

        try controller.prepareDataExport(
            Data("export me".utf8),
            filename: ExportFilename("tax-return-2025.pdf.gpg")
        )
        defer { controller.finish() }

        let payload = try XCTUnwrap(controller.payload)
        XCTAssertEqual(payload.filename.value, "tax-return-2025.pdf.gpg")
        XCTAssertFalse(payload.url.lastPathComponent.contains("tax-return"))
        XCTAssertTrue(payload.url.lastPathComponent.hasPrefix("export-"))
        XCTAssertNotNil(UUID(uuidString: String(payload.url.lastPathComponent.dropFirst("export-".count))))
    }

    /// The offered name and the file are taken from the artifact together, so
    /// the picker's two questions — the transferable item and the default
    /// filename — read one stored pair rather than two arguments a caller
    /// matched up by hand.
    func test_fileExportController_prepareFileExport_pairsTheArtifactsFileAndName() throws {
        let controller = FileExportController()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirFileExportSource-\(UUID().uuidString).asc")
        try Data("source".utf8).write(to: url, options: .atomic)
        defer { try? FileManager.default.removeItem(at: url) }
        let output = AppTemporaryArtifact(
            fileURL: url,
            exportFilename: ExportFilename("source.asc")
        ).temporaryFileOutput

        controller.prepareFileExport(output)

        XCTAssertEqual(controller.payload?.url, url)
        XCTAssertEqual(controller.payload?.filename.value, "source.asc")
        XCTAssertTrue(controller.isPresented)

        // The controller does not own an artifact it was merely handed.
        controller.finish()
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        XCTAssertNil(controller.payload)
        XCTAssertFalse(controller.isPresented)
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
