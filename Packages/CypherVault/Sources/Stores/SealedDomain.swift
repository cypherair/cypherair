import CryptoKit
import Foundation
import Sealing

public enum DomainIntegrity: Equatable, Sendable {
    case intact
    case missing
    case damaged
}

/// One protected-data domain: a single sealed file, replaced atomically, opened
/// with the key the session derives for it.
public struct SealedDomain<Payload: Codable & Sendable>: Sendable {
    public let domain: String
    public let schemaVersion: Int
    private let directory: ProtectedDataDirectory

    public init(domain: String, schemaVersion: Int, directory: ProtectedDataDirectory) {
        self.domain = domain
        self.schemaVersion = schemaVersion
        self.directory = directory
    }

    public var exists: Bool {
        FileManager.default.fileExists(atPath: directory.fileURL(domain: domain).path)
    }

    public func load(key: SymmetricKey) throws(StoreError) -> Payload {
        let fileURL = directory.fileURL(domain: domain)
        guard let data = FileManager.default.contents(atPath: fileURL.path) else { throw .missing }
        let plaintext: Data
        do {
            let snapshot = try SealedSnapshotCodec.decode(data, domain: domain, schemaVersion: schemaVersion)
            plaintext = try SealedSnapshotCodec.open(snapshot, domain: domain, schemaVersion: schemaVersion, key: key)
        } catch {
            throw .damaged
        }
        do {
            return try PropertyListDecoder().decode(Payload.self, from: plaintext)
        } catch {
            throw .damaged
        }
    }

    /// Writes the new snapshot to a temporary file under complete protection and
    /// renames it over the old one. A crash leaves either the old file or the new
    /// one, never a mix, plus at most a temporary file the sweep removes.
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
        let temporary = directory.temporaryURL(domain: domain)
        do {
            try encoded.write(to: temporary, options: [.atomic, .completeFileProtection])
        } catch {
            throw .io("temporary write failed")
        }
        do {
            try ProtectedDataDirectory.protect(temporary)
            _ = try FileManager.default.replaceItemAt(directory.fileURL(domain: domain), withItemAt: temporary)
            try ProtectedDataDirectory.protect(directory.fileURL(domain: domain))
        } catch let error as StoreError {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw .io("replace failed")
        }
    }

    public func delete() throws(StoreError) {
        let fileURL = directory.fileURL(domain: domain)
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return }
        do { try FileManager.default.removeItem(at: fileURL) } catch { throw .io("delete failed") }
    }

    /// Whether the file is intact, missing, or damaged, without returning it.
    public func integrity(key: SymmetricKey) -> DomainIntegrity {
        do {
            _ = try load(key: key)
            return .intact
        } catch .missing {
            return .missing
        } catch {
            return .damaged
        }
    }
}
