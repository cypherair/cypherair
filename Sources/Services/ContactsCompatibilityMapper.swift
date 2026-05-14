import Foundation

struct ContactsCompatibilityMapper {
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

    private static func legacyContactID(for fingerprint: String) -> String {
        "legacy-contact-\(fingerprint)"
    }

    private static func legacyKeyID(for fingerprint: String) -> String {
        "legacy-key-\(fingerprint)"
    }
}
