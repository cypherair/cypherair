import Foundation

/// Turns the stored contacts domain into the summaries the UI reads.
///
/// Every projection derives `ContactKeyTrust` from the snapshot it is handed, so
/// there is no way to obtain a key summary whose trust predates the anchor set
/// it was read against — which is why no projection takes a lone key record.
struct ContactSummaryProjector {
    func identitySummaries(
        from snapshot: ContactsDomainSnapshot
    ) -> [ContactIdentitySummary] {
        let keysByContactId = Dictionary(grouping: snapshot.keyRecords, by: \.contactId)
        let tagSummariesByID = Dictionary(
            uniqueKeysWithValues: tagSummaries(from: snapshot).map { ($0.tagId, $0) }
        )
        let trustWeb = trustWeb(for: snapshot)
        return snapshot.identities
            .map { identity in
                let keys = (keysByContactId[identity.contactId] ?? [])
                    .sorted(by: contactKeySort)
                    .map { makeKeySummary(from: $0, trustWeb: trustWeb) }
                let tags = identity.tagIds.compactMap { tagSummariesByID[$0] }
                return ContactIdentitySummary(
                    contactId: identity.contactId,
                    displayName: identity.displayName,
                    primaryEmail: identity.primaryEmail,
                    tagIds: identity.tagIds,
                    tags: tags,
                    keys: keys
                )
            }
            .sorted(by: identitySummarySort)
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
                tagIds: identity.tagIds,
                preferredKey: preferredKey
            )
        }
    }

    func tagSummaries(
        from snapshot: ContactsDomainSnapshot
    ) -> [ContactTagSummary] {
        let contactCountsByTagId = snapshot.identities.reduce(
            into: [String: Int]()
        ) { counts, identity in
            for tagId in identity.tagIds {
                counts[tagId, default: 0] += 1
            }
        }

        return snapshot.tags
            .map { tag in
                ContactTagSummary(
                    tagId: tag.tagId,
                    displayName: tag.displayName,
                    normalizedName: tag.normalizedName,
                    contactCount: contactCountsByTagId[tag.tagId, default: 0]
                )
            }
            .sorted { lhs, rhs in
                let nameOrder = lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName)
                if nameOrder != .orderedSame {
                    return nameOrder == .orderedAscending
                }
                return lhs.tagId < rhs.tagId
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
        keySummary(in: snapshot) { $0.fingerprint == fingerprint }
    }

    func keySummary(
        keyId: String,
        in snapshot: ContactsDomainSnapshot
    ) -> ContactKeySummary? {
        keySummary(in: snapshot) { $0.keyId == keyId }
    }

    private func keySummary(
        in snapshot: ContactsDomainSnapshot,
        matching isMatch: (ContactKeyRecord) -> Bool
    ) -> ContactKeySummary? {
        snapshot.keyRecords
            .first(where: isMatch)
            .map { makeKeySummary(from: $0, trustWeb: trustWeb(for: snapshot)) }
    }

    private func trustWeb(for snapshot: ContactsDomainSnapshot) -> ContactCertificationTrustWeb {
        ContactCertificationTrustWeb(
            keyRecords: snapshot.keyRecords,
            certificationArtifacts: snapshot.certificationArtifacts
        )
    }

    private func makeKeySummary(
        from keyRecord: ContactKeyRecord,
        trustWeb: ContactCertificationTrustWeb
    ) -> ContactKeySummary {
        ContactKeySummary(
            keyId: keyRecord.keyId,
            contactId: keyRecord.contactId,
            fingerprint: keyRecord.fingerprint,
            primaryUserId: keyRecord.primaryUserId,
            displayName: keyRecord.displayName,
            email: keyRecord.email,
            keyVersion: keyRecord.keyVersion,
            suite: keyRecord.suite,
            primaryAlgo: keyRecord.primaryAlgo,
            subkeyAlgo: keyRecord.subkeyAlgo,
            hasEncryptionSubkey: keyRecord.hasEncryptionSubkey,
            isRevoked: keyRecord.isRevoked,
            isExpired: keyRecord.isExpired,
            manualVerificationState: keyRecord.manualVerificationState,
            usageState: keyRecord.usageState,
            certificationProjection: keyRecord.certificationProjection,
            trust: trustWeb.trust(for: keyRecord)
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

    private func identitySummarySort(_ lhs: ContactIdentitySummary, _ rhs: ContactIdentitySummary) -> Bool {
        let lhsName = lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName)
        if lhsName != .orderedSame {
            return lhsName == .orderedAscending
        }

        let lhsEmail = lhs.primaryEmail ?? ""
        let rhsEmail = rhs.primaryEmail ?? ""
        let emailOrder = lhsEmail.localizedCaseInsensitiveCompare(rhsEmail)
        if emailOrder != .orderedSame {
            return emailOrder == .orderedAscending
        }

        let lhsShortKeyId = lhs.preferredKey?.shortKeyId ?? lhs.keys.first?.shortKeyId ?? ""
        let rhsShortKeyId = rhs.preferredKey?.shortKeyId ?? rhs.keys.first?.shortKeyId ?? ""
        if lhsShortKeyId != rhsShortKeyId {
            return lhsShortKeyId < rhsShortKeyId
        }

        return lhs.contactId < rhs.contactId
    }
}
