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

    /// Dots and whitespace hide behind each other, so stripping each once leaves
    /// the other's leftovers: `". .secret"` came out as the hidden `.secret`.
    func test_exportFilename_stripsInterleavedDotsAndWhitespaceToAFixedPoint() {
        XCTAssertEqual(ExportFilename(base: " . .bashrc", pathExtension: "gpg").value, "bashrc.gpg")
        XCTAssertEqual(ExportFilename(base: ". .secret", pathExtension: "gpg").value, "secret.gpg")
        XCTAssertEqual(ExportFilename(base: ".\t.\u{00AD}.hidden", pathExtension: "gpg").value, "hidden.gpg")
        XCTAssertEqual(ExportFilename(". . . x.txt").value, "x.txt")
        // `init(_:)` splits the final extension off first, so this one is base
        // ". " plus extension "secret": the base sanitises away to the fallback.
        XCTAssertEqual(ExportFilename(". .secret").value, "export.secret")
    }

    /// Trimming drops whole graphemes, so one multi-byte character can take the
    /// stem from over-budget straight to empty — which would leave the name
    /// starting at its own extension's dot. Keeping the inner extension is a
    /// preference; staying visible is the invariant.
    func test_exportFilename_truncationNeverProducesAHiddenFile() {
        let filename = ExportFilename(
            base: "é." + String(repeating: "a", count: 249),
            pathExtension: "gpg"
        )

        XCTAssertFalse(filename.value.hasPrefix("."))
        XCTAssertTrue(filename.value.hasPrefix("é"))
        XCTAssertLessThanOrEqual(filename.value.utf8.count, 255)

        // Sweep the window where the stem empties: short multi-byte stems
        // against an inner extension long enough to consume the budget.
        for stemLength in 1...6 {
            for innerExtensionLength in 244...252 {
                let base = String(repeating: "é", count: stemLength)
                    + "." + String(repeating: "a", count: innerExtensionLength)
                let value = ExportFilename(base: base, pathExtension: "gpg").value

                XCTAssertFalse(value.hasPrefix("."), "hidden name from \(stemLength)/\(innerExtensionLength)")
                XCTAssertFalse(value.isEmpty, "empty name from \(stemLength)/\(innerExtensionLength)")
                XCTAssertLessThanOrEqual(value.utf8.count, 255)
            }
        }
    }

    func test_exportFilename_dropsDirectoryPartsAndControlCharacters() {
        XCTAssertEqual(ExportFilename("../../etc/passwd.asc").value, "passwd.asc")
        XCTAssertEqual(ExportFilename(base: "/tmp/report", pathExtension: "gpg").value, "report.gpg")
        XCTAssertEqual(ExportFilename("re\u{0000}po\nrt.asc").value, "report.asc")
    }

    /// The extension is the position that matters most and is easiest to miss:
    /// the name it comes from is the ciphertext's, which whoever sent the file
    /// chose. `invoice.pd<U+00AD>f` reads as `invoice.pdf` and is not.
    func test_exportFilename_sanitisesTheExtensionPositionToo() {
        XCTAssertEqual(ExportFilename("report.p\ndf").value, "report.pdf")
        XCTAssertEqual(ExportFilename("statement.t\u{007F}xt").value, "statement.txt")
        XCTAssertEqual(ExportFilename("invoice.pd\u{00AD}f").value, "invoice.pdf")
        XCTAssertEqual(ExportFilename("notes.\u{200B}txt").value, "notes.txt")
        XCTAssertEqual(ExportFilename(base: "notes", pathExtension: "t\u{FEFF}xt").value, "notes.txt")
        // An extension that is nothing but invisible scalars is no extension.
        XCTAssertEqual(ExportFilename("archive.\u{FEFF}").value, "archive")
    }

    /// Sweeps the whole Cc block plus the invisible Cf scalars, in the position
    /// the base-only sanitiser used to miss.
    func test_exportFilename_admitsNoControlOrInvisibleScalarInAnyPosition() {
        let suspects = Array(0x00...0x1F) + Array(0x7F...0x9F) + [0x00AD, 0x200B, 0x200E, 0x202E, 0xFEFF]

        for scalarValue in suspects {
            guard let scalar = Unicode.Scalar(scalarValue) else { continue }
            let hostile = "doc\(Character(scalar))ument.p\(Character(scalar))df"

            XCTAssertFalse(
                ExportFilename(hostile).value.unicodeScalars.contains(scalar),
                String(format: "U+%04X survived sanitising", scalarValue)
            )
        }
    }

    /// A 255-byte name is what the file system already allows, so appending an
    /// extension to one must not produce a name that cannot be written.
    func test_exportFilename_staysWritableWhenTheBaseIsAlreadyAtTheLimit() {
        let filename = ExportFilename(base: String(repeating: "a", count: 255), pathExtension: "gpg")

        XCTAssertEqual(filename.value.utf8.count, 255)
        XCTAssertTrue(filename.value.hasSuffix(".gpg"))
    }

    /// Trimming has to come out of the stem. Taking it off the end instead eats
    /// the extension the user's file carried — breaking the round-trip PRODUCT
    /// §5 promises — and leaves a bare `..` where it used to be.
    func test_exportFilename_truncatesTheStemAndKeepsBothExtensions() {
        let filename = ExportFilename(
            base: String(repeating: "a", count: 250) + ".jpg",
            pathExtension: "gpg"
        )

        XCTAssertEqual(filename.value.utf8.count, 255)
        XCTAssertTrue(filename.value.hasSuffix(".jpg.gpg"))
        XCTAssertFalse(filename.value.contains(".."))
    }

    func test_exportFilename_countsBytesRatherThanCharacters() {
        // Four bytes each, and whole Characters come off, so the last one that
        // fits under 255 with ".gpg" is the 62nd.
        let filename = ExportFilename(base: String(repeating: "🔐", count: 80), pathExtension: "gpg")

        XCTAssertEqual(filename.value, String(repeating: "🔐", count: 62) + ".gpg")
        XCTAssertEqual(filename.value.utf8.count, 252)
    }
}
