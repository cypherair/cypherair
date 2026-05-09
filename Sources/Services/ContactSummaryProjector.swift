import Foundation

struct ContactSummaryProjector {
    func identitySummaries(
        from snapshot: ContactsDomainSnapshot
    ) -> [ContactIdentitySummary] {
        let keysByContactId = Dictionary(grouping: snapshot.keyRecords, by: \.contactId)
        return snapshot.identities
            .sorted { lhs, rhs in
                let lhsName = lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName)
                if lhsName == .orderedSame {
                    return lhs.contactId < rhs.contactId
                }
                return lhsName == .orderedAscending
            }
            .map { identity in
                let keys = (keysByContactId[identity.contactId] ?? [])
                    .sorted(by: contactKeySort)
                    .map(makeKeySummary)
                return ContactIdentitySummary(
                    contactId: identity.contactId,
                    displayName: identity.displayName,
                    primaryEmail: identity.primaryEmail,
                    tagIds: identity.tagIds,
                    notes: identity.notes,
                    keys: keys
                )
            }
    }

    func recipientSummaries(
        from snapshot: ContactsDomainSnapshot
    ) -> [ContactRecipientSummary] {
        identitySummaries(from: snapshot).compactMap { identity in
            guard let preferredKey = identity.preferredKey,
                  preferredKey.canEncryptTo else {
                return nil
            }
            return ContactRecipientSummary(
                contactId: identity.contactId,
                displayName: identity.displayName,
                primaryEmail: identity.primaryEmail,
                preferredKey: preferredKey
            )
        }
    }

    func identitySummary(
        contactId: String,
        in snapshot: ContactsDomainSnapshot
    ) -> ContactIdentitySummary? {
        identitySummaries(from: snapshot).first { $0.contactId == contactId }
    }

    func keySummary(
        fingerprint: String,
        in snapshot: ContactsDomainSnapshot
    ) -> ContactKeySummary? {
        snapshot.keyRecords
            .first { $0.fingerprint == fingerprint }
            .map(makeKeySummary)
    }

    func keySummary(from keyRecord: ContactKeyRecord) -> ContactKeySummary {
        makeKeySummary(from: keyRecord)
    }

    private func makeKeySummary(from keyRecord: ContactKeyRecord) -> ContactKeySummary {
        ContactKeySummary(
            keyId: keyRecord.keyId,
            contactId: keyRecord.contactId,
            fingerprint: keyRecord.fingerprint,
            primaryUserId: keyRecord.primaryUserId,
            displayName: keyRecord.displayName,
            email: keyRecord.email,
            keyVersion: keyRecord.keyVersion,
            profile: keyRecord.profile,
            primaryAlgo: keyRecord.primaryAlgo,
            subkeyAlgo: keyRecord.subkeyAlgo,
            hasEncryptionSubkey: keyRecord.hasEncryptionSubkey,
            isRevoked: keyRecord.isRevoked,
            isExpired: keyRecord.isExpired,
            manualVerificationState: keyRecord.manualVerificationState,
            usageState: keyRecord.usageState,
            certificationProjection: keyRecord.certificationProjection,
            certificationArtifactIds: keyRecord.certificationArtifactIds
        )
    }

    private func contactKeySort(_ lhs: ContactKeyRecord, _ rhs: ContactKeyRecord) -> Bool {
        let lhsRank = usageSortRank(lhs.usageState)
        let rhsRank = usageSortRank(rhs.usageState)
        if lhsRank != rhsRank {
            return lhsRank < rhsRank
        }
        return lhs.fingerprint < rhs.fingerprint
    }

    private func usageSortRank(_ usageState: ContactKeyUsageState) -> Int {
        switch usageState {
        case .preferred:
            0
        case .additionalActive:
            1
        case .historical:
            2
        }
    }
}
