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

    private static func legacyContactID(for fingerprint: String) -> String {
        "legacy-contact-\(fingerprint)"
    }

    private static func legacyKeyID(for fingerprint: String) -> String {
        "legacy-key-\(fingerprint)"
    }
}
