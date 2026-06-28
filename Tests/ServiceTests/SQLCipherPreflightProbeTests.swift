import Foundation
import XCTest
@testable import CypherAir

final class SQLCipherPreflightProbeTests: XCTestCase {
    func test_sqlCipherRawKeySpecUsesHexRawKeySyntax() throws {
        let key = (0..<32).map { UInt8($0) }

        let keySpec = try SQLCipherRawKey.keySpecBytes(for: key)

        XCTAssertEqual(
            String(decoding: keySpec, as: UTF8.self),
            "x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'"
        )
    }

    func test_sqlCipherRawKeySpecRejectsNonRandomKeyLength() throws {
        XCTAssertThrowsError(try SQLCipherRawKey.keySpecBytes(for: [0x01])) { error in
            XCTAssertEqual(error as? SQLCipherRawKeyError, .invalidRawKeyLength(1))
        }
    }

    func test_sqlCipherPreflightProbe_validatesRuntimeAndEncryptedDatabase() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirSQLCipher-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let result = try SQLCipherPreflightProbe.run(in: directory)

        XCTAssertTrue(result.cipherVersion.hasPrefix("4.16.0"))
        XCTAssertTrue(result.cipherVersion.contains("community"))
        XCTAssertTrue(result.hasCodecCompileOption)
        XCTAssertTrue(result.tempStoreCompileOption)
        XCTAssertTrue(result.remainingDatabaseSidecars.isEmpty)
    }
}
