import Foundation

final class ContactsDomainRepository: @unchecked Sendable {
    static let domainID: ProtectedDataDomainID = "contacts"

    private(set) var cachedSnapshot: ContactsDomainSnapshot?
    private(set) var compatibilityProjection: [Contact] = []
    private(set) var lastDecodedSourceSchemaVersion: Int?

    private var serializationScratchBuffer = Data()
    private var searchIndexState: [String: [String]] = [:]
    private var signerRecognitionState: [String: String] = [:]

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
        cachedSnapshot = snapshot
        lastDecodedSourceSchemaVersion = sourceSchemaVersion
        return snapshot
    }

    func makeCompatibilitySnapshot(
        from contacts: [Contact],
        now: Date = Date()
    ) throws -> ContactsDomainSnapshot {
        let sortedContacts = contacts.sorted { $0.fingerprint < $1.fingerprint }
        let identities = sortedContacts.map { contact in
            ContactIdentity(
                contactId: Self.legacyContactID(for: contact.fingerprint),
                displayName: contact.displayName,
                primaryEmail: contact.email,
                tagIds: [],
                notes: nil,
                createdAt: now,
                updatedAt: now
            )
        }
        let keyRecords = sortedContacts.map { contact in
            ContactKeyRecord(
                keyId: Self.legacyKeyID(for: contact.fingerprint),
                contactId: Self.legacyContactID(for: contact.fingerprint),
                fingerprint: contact.fingerprint,
                primaryUserId: contact.userId,
                displayName: contact.displayName,
                email: contact.email,
                keyVersion: contact.keyVersion,
                profile: contact.profile,
                primaryAlgo: contact.primaryAlgo,
                subkeyAlgo: contact.subkeyAlgo,
                hasEncryptionSubkey: contact.hasEncryptionSubkey,
                isRevoked: contact.isRevoked,
                isExpired: contact.isExpired,
                manualVerificationState: contact.verificationState,
                usageState: contact.canEncryptTo ? .preferred : .historical,
                certificationProjection: .empty,
                certificationArtifactIds: [],
                publicKeyData: contact.publicKeyData,
                createdAt: now,
                updatedAt: now
            )
        }

        let snapshot = ContactsDomainSnapshot(
            schemaVersion: ContactsDomainSnapshot.currentSchemaVersion,
            identities: identities,
            keyRecords: keyRecords,
            tags: [],
            certificationArtifacts: [],
            createdAt: now,
            updatedAt: now
        )
        try snapshot.validateContract()
        return snapshot
    }

    func makeCompatibilityContacts(from snapshot: ContactsDomainSnapshot) throws -> [Contact] {
        try snapshot.validateContract()
        let identitiesByID = Dictionary(
            uniqueKeysWithValues: snapshot.identities.map { ($0.contactId, $0) }
        )
        return snapshot.keyRecords
            .sorted { lhs, rhs in
                if lhs.contactId != rhs.contactId {
                    return lhs.contactId < rhs.contactId
                }
                return lhs.fingerprint < rhs.fingerprint
            }
            .map { keyRecord in
                let identity = identitiesByID[keyRecord.contactId]
                return Contact(
                    fingerprint: keyRecord.fingerprint,
                    keyVersion: keyRecord.keyVersion,
                    profile: keyRecord.profile,
                    userId: keyRecord.primaryUserId,
                    contactId: keyRecord.contactId,
                    contactDisplayName: identity?.displayName,
                    usageState: keyRecord.usageState,
                    isRevoked: keyRecord.isRevoked,
                    isExpired: keyRecord.isExpired,
                    hasEncryptionSubkey: keyRecord.hasEncryptionSubkey,
                    verificationState: keyRecord.manualVerificationState,
                    publicKeyData: keyRecord.publicKeyData,
                    primaryAlgo: keyRecord.primaryAlgo,
                    subkeyAlgo: keyRecord.subkeyAlgo
                )
            }
    }

    @discardableResult
    func updateCompatibilityRuntime(from contacts: [Contact]) throws -> ContactsDomainSnapshot {
        let snapshot = try makeCompatibilitySnapshot(from: contacts)
        cachedSnapshot = snapshot
        compatibilityProjection = try makeCompatibilityContacts(from: snapshot)
        return snapshot
    }

    @discardableResult
    func updateProtectedRuntime(from snapshot: ContactsDomainSnapshot) throws -> [Contact] {
        try snapshot.validateContract()
        cachedSnapshot = snapshot
        compatibilityProjection = try makeCompatibilityContacts(from: snapshot)
        return compatibilityProjection
    }

    func seedRuntimeStateForTests() {
        serializationScratchBuffer = Data([0x01, 0x02, 0x03])
        searchIndexState = ["alice": ["legacy-contact-alice"]]
        signerRecognitionState = ["fingerprint": "legacy-contact-alice"]
    }

    var runtimeStateIsClearedForTests: Bool {
        cachedSnapshot == nil &&
        compatibilityProjection.isEmpty &&
        serializationScratchBuffer.isEmpty &&
        searchIndexState.isEmpty &&
        signerRecognitionState.isEmpty
    }

    func clearRuntimeState() {
        cachedSnapshot = nil
        compatibilityProjection = []
        lastDecodedSourceSchemaVersion = nil
        serializationScratchBuffer.protectedDataZeroize()
        serializationScratchBuffer = Data()
        searchIndexState = [:]
        signerRecognitionState = [:]
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

    private static func legacyContactID(for fingerprint: String) -> String {
        "legacy-contact-\(fingerprint)"
    }

    private static func legacyKeyID(for fingerprint: String) -> String {
        "legacy-key-\(fingerprint)"
    }
}
