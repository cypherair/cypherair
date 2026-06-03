import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class ImportedTextInputStateTests: XCTestCase {
    func test_importedTextInputState_preservesRawData_untilVisibleTextChanges() {
        var state = ImportedTextInputState()
        let text = "-----BEGIN PGP MESSAGE-----\nVersion: Test\n\nabc\n-----END PGP MESSAGE-----"
        let data = Data(text.utf8)

        state.setImportedFile(data: data, fileName: "encrypted.asc", text: text)

        XCTAssertTrue(state.hasImportedFile)
        XCTAssertEqual(state.rawData, data)
        XCTAssertEqual(state.fileName, "encrypted.asc")
        XCTAssertEqual(state.textSnapshot, text)
        XCTAssertFalse(state.invalidateIfEditedTextDiffers(text))
        XCTAssertEqual(state.rawData, data)

        XCTAssertTrue(state.invalidateIfEditedTextDiffers(text + "\n"))
        XCTAssertFalse(state.hasImportedFile)
        XCTAssertNil(state.rawData)
        XCTAssertNil(state.fileName)
        XCTAssertNil(state.textSnapshot)
    }

    func test_importedTextInputState_clear_removesAuthoritativeData() {
        var state = ImportedTextInputState()
        let text = "-----BEGIN PGP SIGNED MESSAGE-----\n\nhello"
        state.setImportedFile(data: Data(text.utf8), fileName: "signed.asc", text: text)

        state.clear()

        XCTAssertFalse(state.hasImportedFile)
        XCTAssertNil(state.rawData)
        XCTAssertNil(state.fileName)
        XCTAssertNil(state.textSnapshot)
    }

    func test_importedTextInputState_reimport_replacesPreviousBytesAndSnapshot() {
        var state = ImportedTextInputState()
        state.setImportedFile(
            data: Data("old".utf8),
            fileName: "old.asc",
            text: "old"
        )

        state.setImportedFile(
            data: Data("new".utf8),
            fileName: "new.asc",
            text: "new"
        )

        XCTAssertTrue(state.hasImportedFile)
        XCTAssertEqual(state.rawData, Data("new".utf8))
        XCTAssertEqual(state.fileName, "new.asc")
        XCTAssertEqual(state.textSnapshot, "new")
    }
}
