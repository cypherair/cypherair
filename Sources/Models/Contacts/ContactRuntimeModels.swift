import Foundation

enum ContactCandidateMatchStrength: String, Equatable, Sendable {
    case strong
    case weak
    case ambiguousStrong
}

struct ContactCandidateMatch: Equatable, Sendable {
    let strength: ContactCandidateMatchStrength
    let contactIds: [String]
    let displayName: String
    let primaryEmail: String?
}

struct ContactKeySummary: Identifiable, Hashable, Sendable {
    var id: String { keyId }

    let keyId: String
    let contactId: String
    let fingerprint: String
    let primaryUserId: String?
    let displayName: String
    let email: String?
    let keyVersion: UInt8
    let profile: KeyProfile
    let primaryAlgo: String
    let subkeyAlgo: String?
    let hasEncryptionSubkey: Bool
    let isRevoked: Bool
    let isExpired: Bool
    let manualVerificationState: ContactVerificationState
    let usageState: ContactKeyUsageState

    var shortKeyId: String {
        IdentityPresentation.shortKeyId(from: fingerprint)
    }

    var canEncryptTo: Bool {
        hasEncryptionSubkey && !isRevoked && !isExpired
    }

    var isVerified: Bool {
        manualVerificationState.isVerified
    }
}

struct ContactIdentitySummary: Identifiable, Hashable, Sendable {
    var id: String { contactId }

    let contactId: String
    let displayName: String
    let primaryEmail: String?
    let tagIds: [String]
    let notes: String?
    let keys: [ContactKeySummary]

    var preferredKey: ContactKeySummary? {
        keys.first { $0.usageState == .preferred }
    }

    var additionalActiveKeys: [ContactKeySummary] {
        keys.filter { $0.usageState == .additionalActive }
    }

    var historicalKeys: [ContactKeySummary] {
        keys.filter { $0.usageState == .historical }
    }

    var canEncryptTo: Bool {
        preferredKey?.canEncryptTo == true
    }

    var hasUnverifiedKeys: Bool {
        keys.contains { !$0.isVerified }
    }

    var keyCountDescription: String {
        String.localizedStringWithFormat(
            String(localized: "contacts.keyCount", defaultValue: "%d keys"),
            keys.count
        )
    }
}

struct ContactMergePreview: Identifiable, Equatable, Sendable {
    var id: String { source.contactId }

    let source: ContactIdentitySummary
    let target: ContactIdentitySummary
}

struct ContactMergeResult: Equatable, Sendable {
    let survivingContact: ContactIdentitySummary
    let removedContactId: String
    let preferredKeyNeedsSelection: Bool
}
