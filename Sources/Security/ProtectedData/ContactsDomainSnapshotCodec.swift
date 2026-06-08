import Foundation

enum ContactsDomainSnapshotCodec {
    private struct SchemaProbe: Decodable {
        let schemaVersion: Int
    }

    static func encodeSnapshot(_ snapshot: ContactsDomainSnapshot) throws -> Data {
        try mapValidationError {
            try snapshot.validateContract()
        }
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        return try encoder.encode(snapshot)
    }

    static func decodeSnapshot(_ data: Data) throws -> ContactsDomainSnapshot {
        let decoder = PropertyListDecoder()
        let schemaVersion = try decoder.decode(SchemaProbe.self, from: data).schemaVersion
        let snapshot: ContactsDomainSnapshot
        switch schemaVersion {
        case ContactsDomainSnapshot.currentSchemaVersion:
            snapshot = try decoder.decode(ContactsDomainSnapshot.self, from: data)
        default:
            throw ProtectedDataError.invalidEnvelope(
                "Contacts payload has an unsupported schema version."
            )
        }
        try mapValidationError {
            try snapshot.validateContract()
        }
        return snapshot
    }

    private static func mapValidationError<T>(_ operation: () throws -> T) throws -> T {
        do {
            return try operation()
        } catch let error as ContactsDomainValidationError {
            throw ProtectedDataError.invalidEnvelope(error.reason)
        }
    }
}
