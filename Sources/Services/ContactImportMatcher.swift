import Foundation

struct ContactImportMatcher {
    func candidateMatch(
        for validation: PGPValidatedPublicCertificate,
        in snapshot: ContactsDomainSnapshot
    ) -> ContactCandidateMatch? {
        let differentFingerprintContactIds = Set(
            snapshot.keyRecords
                .filter { $0.fingerprint != validation.metadata.fingerprint }
                .map(\.contactId)
        )

        let incomingEmail = normalizedEmail(validation.metadata.userId)
        if let incomingEmail {
            let strongMatches = snapshot.identities.filter {
                differentFingerprintContactIds.contains($0.contactId) &&
                normalizedEmail($0.primaryEmail) == incomingEmail
            }
            if strongMatches.count == 1, let match = strongMatches.first {
                return ContactCandidateMatch(
                    strength: .strong,
                    contactIds: [match.contactId],
                    displayName: match.displayName,
                    primaryEmail: match.primaryEmail
                )
            }
            if strongMatches.count > 1 {
                return ContactCandidateMatch(
                    strength: .ambiguousStrong,
                    contactIds: strongMatches.map(\.contactId),
                    displayName: String(
                        localized: "contacts.candidate.multiple",
                        defaultValue: "Multiple Contacts"
                    ),
                    primaryEmail: incomingEmail
                )
            }
        }

        guard let incomingUserId = validation.metadata.userId else {
            return nil
        }
        if let weakKey = snapshot.keyRecords.first(where: {
            $0.primaryUserId == incomingUserId
                && $0.fingerprint != validation.metadata.fingerprint
        }),
           let identity = snapshot.identities.first(where: { $0.contactId == weakKey.contactId }) {
            return ContactCandidateMatch(
                strength: .weak,
                contactIds: [identity.contactId],
                displayName: identity.displayName,
                primaryEmail: identity.primaryEmail
            )
        }

        return nil
    }

    func conflictingLegacyContact(
        forUserId userId: String?,
        excludingFingerprint fingerprint: String,
        contacts: [Contact]
    ) -> Contact? {
        guard let userId else {
            return nil
        }

        return contacts.first {
            $0.userId == userId && $0.fingerprint != fingerprint
        }
    }

    private func normalizedEmail(_ userIdOrEmail: String?) -> String? {
        let email = IdentityPresentation.email(from: userIdOrEmail) ?? userIdOrEmail
        guard let normalized = email?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased(),
              !normalized.isEmpty,
              normalized.contains("@") else {
            return nil
        }
        return normalized
    }
}
