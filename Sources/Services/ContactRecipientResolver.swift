import Foundation

struct ContactRecipientResolver {
    func publicKeysForRecipientContactIDs(
        _ recipientContactIds: [String],
        in snapshot: ContactsDomainSnapshot
    ) throws -> [Data] {
        var recipientKeys: [Data] = []
        for contactId in recipientContactIds {
            guard let preferredKey = snapshot.keyRecords.first(where: {
                $0.contactId == contactId &&
                $0.usageState == .preferred &&
                $0.canEncryptTo
            }) else {
                throw CypherAirError.invalidKeyData(
                    reason: String(
                        localized: "error.recipientPreferredKeyMissing",
                        defaultValue: "One or more selected contacts do not have a preferred encryption key."
                    )
                )
            }
            recipientKeys.append(preferredKey.publicKeyData)
        }

        return recipientKeys
    }

    func legacyPublicKeysForRecipientFingerprints(
        _ recipientFingerprints: [String],
        contacts: [Contact]
    ) throws -> [Data] {
        let contactsByFingerprint = Dictionary(uniqueKeysWithValues: contacts.map { ($0.fingerprint, $0) })
        let recipientKeys = recipientFingerprints.compactMap { fingerprint in
            contactsByFingerprint[fingerprint]?.publicKeyData
        }

        guard recipientKeys.count == recipientFingerprints.count else {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "error.recipientNotFound",
                    defaultValue: "One or more recipients could not be found in contacts."
                )
            )
        }

        return recipientKeys
    }
}
