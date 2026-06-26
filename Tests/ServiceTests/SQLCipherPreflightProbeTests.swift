import Foundation
import XCTest
@testable import CypherAir

final class SQLCipherPreflightProbeTests: XCTestCase {
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
