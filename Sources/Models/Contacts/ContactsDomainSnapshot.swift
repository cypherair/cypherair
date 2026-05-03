import Foundation

struct ContactsDomainSnapshot: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    var schemaVersion: Int
    var identities: [ContactIdentity]
    var keyRecords: [ContactKeyRecord]
    var recipientLists: [RecipientList]
    var tags: [ContactTag]
    var certificationArtifacts: [ContactCertificationArtifactReference]
    var createdAt: Date
    var updatedAt: Date

    static func empty(now: Date = Date()) -> ContactsDomainSnapshot {
        ContactsDomainSnapshot(
            schemaVersion: currentSchemaVersion,
            identities: [],
            keyRecords: [],
            recipientLists: [],
            tags: [],
            certificationArtifacts: [],
            createdAt: now,
            updatedAt: now
        )
    }

    func validateContract() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts payload has an unsupported schema version."
            )
        }

        try Self.validateUnique(
            identities.map(\.contactId),
            label: "contact identifiers"
        )
        try Self.validateUnique(
            keyRecords.map(\.keyId),
            label: "contact key identifiers"
        )
        try Self.validateUnique(
            keyRecords.map { $0.fingerprint.lowercased() },
            label: "contact key fingerprints"
        )
        try Self.validateUnique(
            recipientLists.map(\.recipientListId),
            label: "recipient list identifiers"
        )
        try Self.validateUnique(
            tags.map(\.tagId),
            label: "tag identifiers"
        )
        try Self.validateUnique(
            tags.map { $0.normalizedName.lowercased() },
            label: "normalized tag names"
        )
        try Self.validateUnique(
            certificationArtifacts.map(\.artifactId),
            label: "certification artifact identifiers"
        )

        let contactIds = Set(identities.map(\.contactId))
        let tagIds = Set(tags.map(\.tagId))
        let keyIds = Set(keyRecords.map(\.keyId))
        let artifactIds = Set(certificationArtifacts.map(\.artifactId))

        for identity in identities {
            try Self.validateNonEmpty(identity.contactId, label: "contact identifier")
            try Self.validateUnique(identity.tagIds, label: "tag membership for \(identity.contactId)")
            let missingTagIds = identity.tagIds.filter { !tagIds.contains($0) }
            guard missingTagIds.isEmpty else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts payload contains contact tag memberships without matching tags."
                )
            }
        }

        for keyRecord in keyRecords {
            try Self.validateNonEmpty(keyRecord.keyId, label: "contact key identifier")
            try Self.validateNonEmpty(keyRecord.contactId, label: "contact key contact identifier")
            try Self.validateNonEmpty(keyRecord.fingerprint, label: "contact key fingerprint")
            guard contactIds.contains(keyRecord.contactId) else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts payload contains a key record without a matching contact."
                )
            }
            guard keyRecord.usageState == .historical || keyRecord.canEncryptTo else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts payload contains an active key record that cannot receive encrypted messages."
                )
            }
            try Self.validateUnique(
                keyRecord.certificationArtifactIds,
                label: "certification artifact references for \(keyRecord.keyId)"
            )
            try Self.validateUnique(
                keyRecord.certificationProjection.artifactIds,
                label: "certification projection artifacts for \(keyRecord.keyId)"
            )
            let missingRecordArtifacts = keyRecord.certificationArtifactIds.filter { !artifactIds.contains($0) }
            let missingProjectionArtifacts = keyRecord.certificationProjection.artifactIds.filter { !artifactIds.contains($0) }
            guard missingRecordArtifacts.isEmpty, missingProjectionArtifacts.isEmpty else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts payload contains certification artifact references without matching artifacts."
                )
            }
        }

        for recipientList in recipientLists {
            try Self.validateNonEmpty(recipientList.recipientListId, label: "recipient list identifier")
            try Self.validateUnique(
                recipientList.memberContactIds,
                label: "recipient list members for \(recipientList.recipientListId)"
            )
            let missingMembers = recipientList.memberContactIds.filter { !contactIds.contains($0) }
            guard missingMembers.isEmpty else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts payload contains recipient-list members without matching contacts."
                )
            }
        }

        for tag in tags {
            try Self.validateNonEmpty(tag.tagId, label: "tag identifier")
            try Self.validateNonEmpty(tag.normalizedName, label: "normalized tag name")
            guard tag.normalizedName == ContactTag.normalizedName(for: tag.displayName) else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts payload contains a tag with stale normalized metadata."
                )
            }
        }

        for artifact in certificationArtifacts {
            try Self.validateNonEmpty(artifact.artifactId, label: "certification artifact identifier")
            try Self.validateNonEmpty(artifact.keyId, label: "certification artifact key identifier")
            guard keyIds.contains(artifact.keyId) else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts payload contains a certification artifact without a matching key."
                )
            }
        }

        let preferredCounts = Dictionary(
            grouping: keyRecords.filter { $0.usageState == .preferred },
            by: \.contactId
        ).mapValues(\.count)
        guard preferredCounts.values.allSatisfy({ $0 <= 1 }) else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts payload contains more than one preferred key for a contact."
            )
        }
    }

    private static func validateNonEmpty(_ value: String, label: String) throws {
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts payload contains an empty \(label)."
            )
        }
    }

    private static func validateUnique(_ values: [String], label: String) throws {
        let nonEmptyValues = values.filter { !$0.isEmpty }
        guard Set(nonEmptyValues).count == nonEmptyValues.count else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts payload contains duplicate \(label)."
            )
        }
    }
}
