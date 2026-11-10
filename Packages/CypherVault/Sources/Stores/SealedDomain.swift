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
        let plaintext: Data
        do {
            let snapshot = try SealedSnapshotCodec.decode(data, domain: domain, schemaVersion: schemaVersion)
            plaintext = try SealedSnapshotCodec.open(snapshot, domain: domain, schemaVersion: schemaVersion, key: key)
        } catch .otherSchemaVersion {
            throw .otherVersion
        } catch {
            throw .damaged
        }
        do {
            return try PropertyListDecoder().decode(Payload.self, from: plaintext)
        } catch {
            throw .damaged
        }
    }

    /// Seals the payload and replaces the file with it. A crash leaves either
    /// the old file or the new one, never a mix.
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
                try SealedSnapshotCodec.seal(plaintext: plaintext, domain: domain, schemaVersion: schemaVersion, key: key)
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
}
