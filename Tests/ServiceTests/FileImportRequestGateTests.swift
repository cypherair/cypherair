import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class FileImportRequestGateTests: XCTestCase {
    func test_fileImportRequestGate_consumesCurrentTokenOnce() {
        var gate = FileImportRequestGate()
        let token = gate.begin()

        XCTAssertEqual(gate.currentToken, Optional(token))
        XCTAssertTrue(gate.consumeIfCurrent(token))
        XCTAssertNil(gate.currentToken)
        XCTAssertFalse(gate.consumeIfCurrent(token))
    }

    func test_fileImportRequestGate_invalidateSuppressesOldCompletion() {
        var gate = FileImportRequestGate()
        let oldToken = gate.begin()

        gate.invalidate()

        XCTAssertNil(gate.currentToken)
        XCTAssertFalse(gate.consumeIfCurrent(oldToken))

        let newToken = gate.begin()

        XCTAssertFalse(gate.consumeIfCurrent(oldToken))
        XCTAssertEqual(gate.currentToken, Optional(newToken))
        XCTAssertTrue(gate.consumeIfCurrent(newToken))
    }

    func test_fileImportRequestGate_nilOrRepeatedCompletionDoesNotRestoreRequest() {
        var gate = FileImportRequestGate()
        let token = gate.begin()

        XCTAssertFalse(gate.consumeIfCurrent(nil))
        XCTAssertEqual(gate.currentToken, Optional(token))
        XCTAssertTrue(gate.consumeIfCurrent(token))
        XCTAssertFalse(gate.consumeIfCurrent(token))
        XCTAssertNil(gate.currentToken)
    }
}
