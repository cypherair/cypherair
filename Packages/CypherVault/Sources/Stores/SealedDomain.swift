import CryptoKit
import Foundation
import Sealing

public enum DomainIntegrity: Equatable, Sendable {
    case intact
    case missing
    case damaged
    case otherVersion
}

/// One protected-data domain: a single sealed file, replaced atomically, opened
/// with the key the session derives for it.
public struct SealedDomain<Payload: Codable & Sendable>: Sendable {
    public let domain: String
    public let schemaVersion: Int
    private let files: any DomainFiles

    public init(domain: String, schemaVersion: Int, files: any DomainFiles) {
        self.domain = domain
        self.schemaVersion = schemaVersion
        self.files = files
    }

    public func load(key: SymmetricKey) throws(StoreError) -> Payload {
        guard let data = try files.read(domain) else { throw .missing }
        let padded: Data
        do {
            let snapshot = try SealedSnapshotCodec.decode(data, domain: domain, schemaVersion: schemaVersion)
            padded = try SealedSnapshotCodec.open(snapshot, domain: domain, schemaVersion: schemaVersion, key: key)
        } catch .otherSchemaVersion {
            throw .otherVersion
        } catch {
            throw .damaged
        }
        guard let plaintext = Self.unpad(padded) else { throw .damaged }
        do {
            return try PropertyListDecoder().decode(Payload.self, from: plaintext)
        } catch {
            throw .damaged
        }
    }

    /// Pads the payload, seals it, and replaces the file with it. A crash
    /// leaves either the old file or the new one, never a mix.
    public func save(_ payload: Payload, key: SymmetricKey) throws(StoreError) {
        let plaintext: Data
        do {
            let encoder = PropertyListEncoder()
            encoder.outputFormat = .binary
            plaintext = try encoder.encode(payload)
        } catch {
            throw .internalFailure("payload encoding failed")
        }
        let encoded: Data
        do {
            encoded = try SealedSnapshotCodec.encode(
                try SealedSnapshotCodec.seal(plaintext: Self.pad(plaintext), domain: domain, schemaVersion: schemaVersion, key: key)
            )
        } catch {
            throw .internalFailure("snapshot seal failed")
        }
        try files.replace(domain, with: encoded)
    }

    /// Whether the file is intact, missing, damaged, or from another version,
    /// without returning it.
    public func integrity(key: SymmetricKey) -> DomainIntegrity {
        do {
            _ = try load(key: key)
            return .intact
        } catch .missing {
            return .missing
        } catch .otherVersion {
            return .otherVersion
        } catch {
            return .damaged
        }
    }

    /// Every sealed payload is padded to a multiple of this, so a file's size
    /// does not confirm a guess about what it holds.
    public static var paddingStep: Int { 16 * 1024 }

    /// The payload's length as eight big-endian bytes, the payload, then zeros
    /// up to the next multiple of `paddingStep`.
    static func pad(_ payload: Data) -> Data {
        var padded = Data(count: 8)
        var length = UInt64(payload.count)
        for index in (0..<8).reversed() {
            padded[index] = UInt8(truncatingIfNeeded: length)
            length >>= 8
        }
        padded.append(payload)
        let total = (padded.count + paddingStep - 1) / paddingStep * paddingStep
        padded.append(Data(count: total - padded.count))
        return padded
    }

    static func unpad(_ padded: Data) -> Data? {
        let bytes = [UInt8](padded)
        guard bytes.count >= 8, bytes.count % paddingStep == 0 else { return nil }
        let length = bytes[0..<8].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        guard length <= UInt64(bytes.count - 8) else { return nil }
        let end = 8 + Int(length)
        guard bytes[end...].allSatisfy({ $0 == 0 }) else { return nil }
        return Data(bytes[8..<end])
    }
}
