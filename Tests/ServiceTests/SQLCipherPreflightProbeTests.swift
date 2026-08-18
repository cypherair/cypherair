import Foundation
import XCTest
@testable import CypherAir

final class SQLCipherPreflightProbeTests: XCTestCase {
    func test_sqlCipherRawKeySpecUsesHexRawKeySyntax() throws {
        let key = Data((0..<32).map { UInt8($0) })

        let keySpec = try SQLCipherRawKey.keySpec(for: key)

        XCTAssertEqual(
            String(decoding: keySpec.copiedBytes(), as: UTF8.self),
            "x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'"
        )
    }

    /// A `Data` slice does not start at index zero. The spec must be built from
    /// the key's bytes, not from whatever its indices happen to be.
    func test_sqlCipherRawKeySpecRendersASlicedKeyFromItsOwnBytes() throws {
        let padded = Data(repeating: 0xEE, count: 4) + Data(repeating: 0xAB, count: 32)
        let key = padded.dropFirst(4)

        let keySpec = try SQLCipherRawKey.keySpec(for: key)

        XCTAssertEqual(
            String(decoding: keySpec.copiedBytes(), as: UTF8.self),
            "x'\(String(repeating: "ab", count: 32))'"
        )
    }

    func test_sqlCipherRawKeySpecRejectsNonRandomKeyLength() throws {
        assertThrowsError(try SQLCipherRawKey.keySpec(for: Data([0x01]))) { error in
            XCTAssertEqual(error as? SQLCipherRawKeyError, .invalidRawKeyLength(1))
        }
    }

}
