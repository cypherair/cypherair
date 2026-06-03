import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class ArmoredTextMessageClassifierTests: XCTestCase {
    func test_armoredTextMessageClassifier_armoredEncryptedMessage_matches() throws {
        let data = try FixtureLoader.loadData("gpg_encrypted_message", ext: "asc")

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .encryptedTextMessage)
    }

    func test_armoredTextMessageClassifier_cleartextSignedMessage_doesNotMatch() throws {
        let data = try FixtureLoader.loadData("gpg_cleartext_signed", ext: "asc")

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .other)
    }

    func test_armoredTextMessageClassifier_binaryMessage_doesNotMatch() throws {
        let data = try FixtureLoader.loadData("gpg_encrypted_message", ext: "gpg")

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .other)
    }

    func test_armoredTextMessageClassifier_oversizedArmoredMessage_doesNotMatch() {
        let oversizedText =
            "-----BEGIN PGP MESSAGE-----\n"
            + String(repeating: "A", count: ArmoredTextMessageClassifier.maxInspectableFileSize + 1)
        let data = Data(oversizedText.utf8)

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .other)
    }
}
