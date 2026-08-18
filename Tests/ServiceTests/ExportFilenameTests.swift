import Foundation
import XCTest
@testable import CypherAir

/// `ExportFilename` is the single place a name is sanitised, so everything the
/// save panel must never be handed is settled here.
final class ExportFilenameTests: XCTestCase {
    func test_exportFilename_keepsNamesTheAppComposes() {
        XCTAssertEqual(ExportFilename("encrypted.asc").value, "encrypted.asc")
        XCTAssertEqual(ExportFilename("revocation-A1B2C3D4.asc").value, "revocation-A1B2C3D4.asc")
        XCTAssertEqual(ExportFilename("decrypted").value, "decrypted")
    }

    /// A user's own file keeps every extension it already has, so decrypting
    /// what this produces gives the original name back.
    func test_exportFilename_appendsExtensionWithoutReplacingTheOriginalOne() {
        XCTAssertEqual(ExportFilename(base: "photo.jpg", pathExtension: "gpg").value, "photo.jpg.gpg")
        XCTAssertEqual(ExportFilename(base: "archive", pathExtension: "sig").value, "archive.sig")
    }

    /// The reachable defect: a file whose name is nothing but spaces used to be
    /// offered as typed, or trimmed down to a hidden `.gpg`.
    func test_exportFilename_whitespaceOnlyNameFallsBackWithoutLosingTheExtension() {
        XCTAssertEqual(ExportFilename(base: "   ", pathExtension: "gpg").value, "export.gpg")
        XCTAssertEqual(ExportFilename("   .gpg").value, "export.gpg")
        XCTAssertEqual(ExportFilename("").value, "export")
    }

    func test_exportFilename_neverProducesAHiddenFile() {
        XCTAssertEqual(ExportFilename(base: ".ssh-config", pathExtension: "gpg").value, "ssh-config.gpg")
        XCTAssertEqual(ExportFilename("...").value, "export")
    }

    func test_exportFilename_dropsDirectoryPartsAndControlCharacters() {
        XCTAssertEqual(ExportFilename("../../etc/passwd.asc").value, "passwd.asc")
        XCTAssertEqual(ExportFilename(base: "/tmp/report", pathExtension: "gpg").value, "report.gpg")
        XCTAssertEqual(ExportFilename("re\u{0000}po\nrt.asc").value, "report.asc")
    }

    /// A 255-byte name is what the file system already allows, so appending an
    /// extension to one must not produce a name that cannot be written.
    func test_exportFilename_staysWritableWhenTheBaseIsAlreadyAtTheLimit() {
        let filename = ExportFilename(base: String(repeating: "a", count: 255), pathExtension: "gpg")

        XCTAssertEqual(filename.value.utf8.count, 255)
        XCTAssertTrue(filename.value.hasSuffix(".gpg"))
    }

    func test_exportFilename_countsBytesRatherThanCharacters() {
        // Four bytes per emoji, so 64 of them plus ".gpg" is exactly the limit.
        let filename = ExportFilename(base: String(repeating: "🔐", count: 80), pathExtension: "gpg")

        XCTAssertLessThanOrEqual(filename.value.utf8.count, 255)
        XCTAssertTrue(filename.value.hasSuffix(".gpg"))
        XCTAssertTrue(filename.value.hasPrefix("🔐"))
    }
}
