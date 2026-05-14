import Foundation

final class ContactsDomainSnapshotCodec: @unchecked Sendable {
    private(set) var lastDecodedSourceSchemaVersion: Int?

    private var serializationScratchBuffer = Data()

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

    func encodeSnapshot(_ snapshot: ContactsDomainSnapshot) throws -> Data {
        try snapshot.validateContract()
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let encoded = try encoder.encode(snapshot)
        serializationScratchBuffer = encoded
        defer {
            serializationScratchBuffer.protectedDataZeroize()
            serializationScratchBuffer = Data()
        }
        return encoded
    }

    func decodeSnapshot(_ data: Data) throws -> ContactsDomainSnapshot {
        serializationScratchBuffer = data
        defer {
            serializationScratchBuffer.protectedDataZeroize()
            serializationScratchBuffer = Data()
        }
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
        try snapshot.validateContract()
        lastDecodedSourceSchemaVersion = sourceSchemaVersion
        return snapshot
    }

    func clearRuntimeState() {
        lastDecodedSourceSchemaVersion = nil
        serializationScratchBuffer.protectedDataZeroize()
        serializationScratchBuffer = Data()
    }

    private func migrateLegacyV1Snapshot(_ legacySnapshot: LegacySnapshotV1) throws -> ContactsDomainSnapshot {
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
        try migratedSnapshot.validateContract()
        return migratedSnapshot
    }
}
