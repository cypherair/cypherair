import Foundation

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
