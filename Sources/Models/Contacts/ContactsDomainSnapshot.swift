import Foundation

struct ContactsDomainSnapshot: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 2

    var schemaVersion: Int
    var identities: [ContactIdentity]
    var keyRecords: [ContactKeyRecord]
    var tags: [ContactTag]
    var certificationArtifacts: [ContactCertificationArtifactReference]
    var createdAt: Date
    var updatedAt: Date

    static func empty(now: Date = Date()) -> ContactsDomainSnapshot {
        ContactsDomainSnapshot(
            schemaVersion: currentSchemaVersion,
            identities: [],
            keyRecords: [],
            tags: [],
            certificationArtifacts: [],
            createdAt: now,
            updatedAt: now
        )
    }

    func validateContract() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw ContactsDomainValidationError.invalidPayload(
                reason: "Contacts payload has an unsupported schema version."
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
        try Self.validateUnique(
            certificationArtifacts.compactMap(\.deduplicationKey),
            label: "certification artifact payloads"
        )

        let contactIds = Set(identities.map(\.contactId))
        let tagIds = Set(tags.map(\.tagId))
        let keyIds = Set(keyRecords.map(\.keyId))
        let artifactsByID = certificationArtifacts.reduce(
            into: [String: ContactCertificationArtifactReference]()
        ) { artifactsByID, artifact in
            artifactsByID[artifact.artifactId] = artifact
        }

        for identity in identities {
            try Self.validateNonEmpty(identity.contactId, label: "contact identifier")
            try Self.validateUnique(identity.tagIds, label: "tag membership for \(identity.contactId)")
            let missingTagIds = identity.tagIds.filter { !tagIds.contains($0) }
            guard missingTagIds.isEmpty else {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains contact tag memberships without matching tags."
                )
            }
        }

        for keyRecord in keyRecords {
            try Self.validateNonEmpty(keyRecord.keyId, label: "contact key identifier")
            try Self.validateNonEmpty(keyRecord.contactId, label: "contact key contact identifier")
            try Self.validateNonEmpty(keyRecord.fingerprint, label: "contact key fingerprint")
            guard contactIds.contains(keyRecord.contactId) else {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains a key record without a matching contact."
                )
            }
            guard keyRecord.usageState == .historical || keyRecord.canEncryptTo else {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains an active key record that cannot receive encrypted messages."
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
            try Self.validateArtifactsBelongToKey(
                keyRecord.certificationArtifactIds,
                keyId: keyRecord.keyId,
                artifactsByID: artifactsByID
            )
            try Self.validateArtifactsBelongToKey(
                keyRecord.certificationProjection.artifactIds,
                keyId: keyRecord.keyId,
                artifactsByID: artifactsByID
            )
        }

        for tag in tags {
            try Self.validateNonEmpty(tag.tagId, label: "tag identifier")
            try Self.validateNonEmpty(tag.normalizedName, label: "normalized tag name")
            guard tag.normalizedName == ContactTag.normalizedName(for: tag.displayName) else {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains a tag with stale normalized metadata."
                )
            }
        }

        for artifact in certificationArtifacts {
            try Self.validateNonEmpty(artifact.artifactId, label: "certification artifact identifier")
            try Self.validateNonEmpty(artifact.keyId, label: "certification artifact key identifier")
            try artifact.validatePayload()
            guard keyIds.contains(artifact.keyId) else {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains a certification artifact without a matching key."
                )
            }
            if let targetKeyFingerprint = artifact.targetKeyFingerprint,
               let keyRecord = keyRecords.first(where: { $0.keyId == artifact.keyId }),
               targetKeyFingerprint.lowercased() != keyRecord.fingerprint.lowercased() {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains a certification artifact with stale target key metadata."
                )
            }
        }

        let preferredCounts = Dictionary(
            grouping: keyRecords.filter { $0.usageState == .preferred },
            by: \.contactId
        ).mapValues(\.count)
        guard preferredCounts.values.allSatisfy({ $0 <= 1 }) else {
            throw ContactsDomainValidationError.invalidPayload(
                reason: "Contacts payload contains more than one preferred key for a contact."
            )
        }
    }

    private static func validateNonEmpty(_ value: String, label: String) throws {
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ContactsDomainValidationError.invalidPayload(
                reason: "Contacts payload contains an empty \(label)."
            )
        }
    }

    private static func validateUnique(_ values: [String], label: String) throws {
        let nonEmptyValues = values.filter { !$0.isEmpty }
        guard Set(nonEmptyValues).count == nonEmptyValues.count else {
            throw ContactsDomainValidationError.invalidPayload(
                reason: "Contacts payload contains duplicate \(label)."
            )
        }
    }

    private static func validateArtifactsBelongToKey(
        _ artifactIDs: [String],
        keyId: String,
        artifactsByID: [String: ContactCertificationArtifactReference]
    ) throws {
        for artifactID in artifactIDs {
            guard let artifact = artifactsByID[artifactID] else {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains certification artifact references without matching artifacts."
                )
            }
            guard artifact.keyId == keyId else {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains certification artifact references for another key."
                )
            }
        }
    }
}
