import CryptoKit
import Foundation

/// One protected-data domain's payload: AES-256-GCM under the domain's derived
/// key, with the domain and schema bound as authenticated data.
public struct SealedSnapshot: Codable, Equatable, Sendable {
    public static let magic = "CAVSNAP1"
    public static let nonceLength = 12
    public static let tagLength = 16

    public let magic: String
    public let domain: String
    public let schemaVersion: Int
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    static let allowedKeys: Set<String> = ["magic", "domain", "schemaVersion", "nonce", "ciphertext", "tag"]

    func validate(expectedDomain: String, expectedSchemaVersion: Int) throws(SealingError) {
        guard magic == Self.magic else { throw .malformed("snapshot magic") }
        guard domain == expectedDomain, schemaVersion == expectedSchemaVersion else { throw .bindingMismatch }
        guard schemaVersion > 0 else { throw .malformed("schema version") }
        guard nonce.count == Self.nonceLength else { throw .malformed("nonce length") }
        guard tag.count == Self.tagLength else { throw .malformed("tag length") }
    }
}

public enum SealedSnapshotCodec {
    public static func seal(plaintext: Data, domain: String, schemaVersion: Int, key: SymmetricKey) throws(SealingError) -> SealedSnapshot {
        try seal(plaintext: plaintext, domain: domain, schemaVersion: schemaVersion, key: key,
                 nonce: try Randomness.bytes(count: SealedSnapshot.nonceLength))
    }

    static func seal(plaintext: Data, domain: String, schemaVersion: Int, key: SymmetricKey, nonce: Data) throws(SealingError) -> SealedSnapshot {
        guard schemaVersion > 0 else { throw .malformed("schema version") }
        guard key.bitCount == 256 else { throw .malformed("key length") }
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: aad(domain: domain, schemaVersion: schemaVersion))
        } catch {
            throw SealingError.internalFailure("AES-GCM seal failed")
        }
        return SealedSnapshot(magic: SealedSnapshot.magic, domain: domain, schemaVersion: schemaVersion, nonce: nonce, ciphertext: sealed.ciphertext, tag: sealed.tag)
    }

    public static func open(_ snapshot: SealedSnapshot, domain: String, schemaVersion: Int, key: SymmetricKey) throws(SealingError) -> Data {
        try snapshot.validate(expectedDomain: domain, expectedSchemaVersion: schemaVersion)
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: snapshot.nonce), ciphertext: snapshot.ciphertext, tag: snapshot.tag)
            return try AES.GCM.open(box, using: key, authenticating: aad(domain: domain, schemaVersion: schemaVersion))
        } catch {
            throw SealingError.authenticationFailed
        }
    }

    public static func encode(_ snapshot: SealedSnapshot) throws(SealingError) -> Data {
        try StrictPropertyList.encode(snapshot)
    }

    public static func decode(_ data: Data, domain: String, schemaVersion: Int) throws(SealingError) -> SealedSnapshot {
        let snapshot = try StrictPropertyList.decode(SealedSnapshot.self, from: data, allowedKeys: SealedSnapshot.allowedKeys)
        try snapshot.validate(expectedDomain: domain, expectedSchemaVersion: schemaVersion)
        return snapshot
    }

    static func aad(domain: String, schemaVersion: Int) -> Data {
        var data = Data("CypherAir snapshot v1 aad".utf8)
        data.appendLengthPrefixed(Data(SealedSnapshot.magic.utf8))
        data.appendLengthPrefixed(Data(domain.utf8))
        data.append(UInt32(schemaVersion).bigEndianData)
        return data
    }
}
