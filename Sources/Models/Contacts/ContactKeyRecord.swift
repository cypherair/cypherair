import Foundation

struct ContactKeyRecord: Codable, Equatable, Identifiable, Sendable {
    var id: String { keyId }

    let keyId: String
    var contactId: String
    var fingerprint: String
    var primaryUserId: String?
    var displayName: String
    var email: String?
    var keyVersion: UInt8
    var profile: PGPKeyProfile
    var primaryAlgo: String
    var subkeyAlgo: String?
    var hasEncryptionSubkey: Bool
    var isRevoked: Bool
    var isExpired: Bool
    var manualVerificationState: ContactVerificationState
    var usageState: ContactKeyUsageState
    var certificationProjection: ContactCertificationProjection
    var certificationArtifactIds: [String]
    var publicKeyData: Data
    var createdAt: Date
    var updatedAt: Date

    var canEncryptTo: Bool {
        hasEncryptionSubkey && !isRevoked && !isExpired
    }
}
