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
    let profile: PGPKeyProfile
    let primaryAlgo: String
    let subkeyAlgo: String?
    let hasEncryptionSubkey: Bool
    let isRevoked: Bool
    let isExpired: Bool
    let manualVerificationState: ContactVerificationState
    let usageState: ContactKeyUsageState
    let certificationProjection: ContactCertificationProjection
    let certificationArtifactIds: [String]

    var shortKeyId: String {
        IdentityPresentation.shortKeyId(from: fingerprint)
    }

    var canEncryptTo: Bool {
        hasEncryptionSubkey && !isRevoked && !isExpired
    }

    var isVerified: Bool {
        manualVerificationState.isVerified
    }

    var isOpenPGPCertified: Bool {
        certificationProjection.status == .certified
    }
}
