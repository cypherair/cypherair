import CryptoKit
import Foundation
import Testing
@testable import Sealing

struct SealedSnapshotTests {
    private let key = SymmetricKey(size: .bits256)

    @Test func `Round trip survives encoding`() throws {
        let snapshot = try SealedSnapshotCodec.seal(plaintext: Data("contacts".utf8), domain: "contacts", schemaVersion: 1, key: key)
        let encoded = try SealedSnapshotCodec.encode(snapshot)
        let decoded = try SealedSnapshotCodec.decode(encoded, domain: "contacts", schemaVersion: 1)
        #expect(try SealedSnapshotCodec.open(decoded, domain: "contacts", schemaVersion: 1, key: key) == Data("contacts".utf8))
    }

    @Test func `Domain and schema are bound`() throws {
        let snapshot = try SealedSnapshotCodec.seal(plaintext: Data("x".utf8), domain: "contacts", schemaVersion: 1, key: key)
        #expect(throws: SealingError.bindingMismatch) {
            try SealedSnapshotCodec.open(snapshot, domain: "settings", schemaVersion: 1, key: key)
        }
        #expect(throws: SealingError.otherSchemaVersion) {
            try SealedSnapshotCodec.open(snapshot, domain: "contacts", schemaVersion: 2, key: key)
        }
        let renamed = SealedSnapshot(magic: snapshot.magic, domain: "settings", schemaVersion: 1, nonce: snapshot.nonce, ciphertext: snapshot.ciphertext, tag: snapshot.tag)
        #expect(throws: SealingError.authenticationFailed) {
            try SealedSnapshotCodec.open(renamed, domain: "settings", schemaVersion: 1, key: key)
        }
    }

    @Test func `Tampered ciphertext or wrong key is refused`() throws {
        let snapshot = try SealedSnapshotCodec.seal(plaintext: Data("payload".utf8), domain: "d", schemaVersion: 3, key: key)
        var tampered = snapshot.ciphertext; tampered[tampered.startIndex] ^= 0x80
        let variant = SealedSnapshot(magic: snapshot.magic, domain: snapshot.domain, schemaVersion: snapshot.schemaVersion, nonce: snapshot.nonce, ciphertext: tampered, tag: snapshot.tag)
        #expect(throws: SealingError.authenticationFailed) {
            try SealedSnapshotCodec.open(variant, domain: "d", schemaVersion: 3, key: key)
        }
        #expect(throws: SealingError.authenticationFailed) {
            try SealedSnapshotCodec.open(snapshot, domain: "d", schemaVersion: 3, key: SymmetricKey(size: .bits256))
        }
    }

    @Test func `Known answer pins authenticated data`() throws {
        let fixedKey = SymmetricKey(data: Data(repeating: 0x55, count: 32))
        let snapshot = try SealedSnapshotCodec.seal(plaintext: Data("vector".utf8), domain: "contacts", schemaVersion: 1, key: fixedKey, nonce: Data(repeating: 0x66, count: 12))
        #expect(snapshot.ciphertext.map { String(format: "%02x", $0) }.joined() == KnownAnswers.snapshotCiphertext)
        #expect(snapshot.tag.map { String(format: "%02x", $0) }.joined() == KnownAnswers.snapshotTag)
    }
}
