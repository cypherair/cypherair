import CryptoKit
import Foundation
import XCTest
@testable import Sealing

final class SealedSnapshotTests: XCTestCase {
    private let key = SymmetricKey(size: .bits256)

    func test_roundTrip_survivesEncoding() throws {
        let snapshot = try SealedSnapshotCodec.seal(plaintext: Data("contacts".utf8), domain: "contacts", schemaVersion: 1, key: key)
        let encoded = try SealedSnapshotCodec.encode(snapshot)
        let decoded = try SealedSnapshotCodec.decode(encoded, domain: "contacts", schemaVersion: 1)
        XCTAssertEqual(try SealedSnapshotCodec.open(decoded, domain: "contacts", schemaVersion: 1, key: key), Data("contacts".utf8))
    }

    func test_domainAndSchema_areBound() throws {
        let snapshot = try SealedSnapshotCodec.seal(plaintext: Data("x".utf8), domain: "contacts", schemaVersion: 1, key: key)
        XCTAssertThrowsError(try SealedSnapshotCodec.open(snapshot, domain: "settings", schemaVersion: 1, key: key)) {
            XCTAssertEqual($0 as? SealingError, .bindingMismatch)
        }
        XCTAssertThrowsError(try SealedSnapshotCodec.open(snapshot, domain: "contacts", schemaVersion: 2, key: key)) {
            XCTAssertEqual($0 as? SealingError, .bindingMismatch)
        }
        let renamed = SealedSnapshot(magic: snapshot.magic, domain: "settings", schemaVersion: 1, nonce: snapshot.nonce, ciphertext: snapshot.ciphertext, tag: snapshot.tag)
        XCTAssertThrowsError(try SealedSnapshotCodec.open(renamed, domain: "settings", schemaVersion: 1, key: key)) {
            XCTAssertEqual($0 as? SealingError, .authenticationFailed)
        }
    }

    func test_tamperedCiphertext_orWrongKey_isRefused() throws {
        let snapshot = try SealedSnapshotCodec.seal(plaintext: Data("payload".utf8), domain: "d", schemaVersion: 3, key: key)
        var tampered = snapshot.ciphertext; tampered[tampered.startIndex] ^= 0x80
        let variant = SealedSnapshot(magic: snapshot.magic, domain: snapshot.domain, schemaVersion: snapshot.schemaVersion, nonce: snapshot.nonce, ciphertext: tampered, tag: snapshot.tag)
        XCTAssertThrowsError(try SealedSnapshotCodec.open(variant, domain: "d", schemaVersion: 3, key: key)) {
            XCTAssertEqual($0 as? SealingError, .authenticationFailed)
        }
        XCTAssertThrowsError(try SealedSnapshotCodec.open(snapshot, domain: "d", schemaVersion: 3, key: SymmetricKey(size: .bits256))) {
            XCTAssertEqual($0 as? SealingError, .authenticationFailed)
        }
    }

    func test_knownAnswer_pinsAuthenticatedData() throws {
        let fixedKey = SymmetricKey(data: Data(repeating: 0x55, count: 32))
        let snapshot = try SealedSnapshotCodec.seal(plaintext: Data("vector".utf8), domain: "contacts", schemaVersion: 1, key: fixedKey, nonce: Data(repeating: 0x66, count: 12))
        XCTAssertEqual(snapshot.ciphertext.map { String(format: "%02x", $0) }.joined(), KnownAnswers.snapshotCiphertext)
        XCTAssertEqual(snapshot.tag.map { String(format: "%02x", $0) }.joined(), KnownAnswers.snapshotTag)
    }
}
