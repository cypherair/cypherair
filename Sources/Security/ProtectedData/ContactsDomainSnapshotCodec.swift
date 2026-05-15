import Foundation

enum ContactsDomainSnapshotCodec {
    private struct SchemaProbe: Decodable {
        let schemaVersion: Int
    }

    private struct LegacySnapshotV1: Decodable {
        let schemaVersion: Int
        let identities: [ContactIdentity]
        let keyRecords: [ContactKeyRecord]
        let tags: [ContactTag]
        let certificationArtifacts: [ContactCertificationArtifactReference]
        let createdAt: Date
        let updatedAt: Date
    }

    static func encodeSnapshot(_ snapshot: ContactsDomainSnapshot) throws -> Data {
        try mapValidationError {
            try snapshot.validateContract()
        }
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        return try encoder.encode(snapshot)
    }

    static func decodeSnapshot(_ data: Data) throws -> (
        snapshot: ContactsDomainSnapshot,
        sourceSchemaVersion: Int
    ) {
        let decoder = PropertyListDecoder()
        let sourceSchemaVersion = try decoder.decode(SchemaProbe.self, from: data).schemaVersion
        let snapshot: ContactsDomainSnapshot
        switch sourceSchemaVersion {
        case ContactsDomainSnapshot.currentSchemaVersion:
            snapshot = try decoder.decode(ContactsDomainSnapshot.self, from: data)
        case 1:
            snapshot = try migrateLegacyV1Snapshot(
                try decoder.decode(LegacySnapshotV1.self, from: data)
            )
        default:
            throw ProtectedDataError.invalidEnvelope(
                "Contacts payload has an unsupported schema version."
            )
        }
        try mapValidationError {
            try snapshot.validateContract()
        }
        return (snapshot, sourceSchemaVersion)
    }

    private static func migrateLegacyV1Snapshot(_ legacySnapshot: LegacySnapshotV1) throws -> ContactsDomainSnapshot {
        guard legacySnapshot.schemaVersion == 1 else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts v1 migration received an unexpected schema version."
            )
        }

        let migratedSnapshot = ContactsDomainSnapshot(
            schemaVersion: ContactsDomainSnapshot.currentSchemaVersion,
            identities: legacySnapshot.identities,
            keyRecords: legacySnapshot.keyRecords,
            tags: legacySnapshot.tags,
            certificationArtifacts: legacySnapshot.certificationArtifacts,
            createdAt: legacySnapshot.createdAt,
            updatedAt: Date()
        )
        try mapValidationError {
            try migratedSnapshot.validateContract()
        }
        return migratedSnapshot
    }

    private static func mapValidationError<T>(_ operation: () throws -> T) throws -> T {
        do {
            return try operation()
        } catch let error as ContactsDomainValidationError {
            throw ProtectedDataError.invalidEnvelope(error.reason)
        }
    }
}
