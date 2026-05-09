import Foundation

struct ContactCertificationProjection: Codable, Equatable, Hashable, Sendable {
    enum Status: String, Codable, Equatable, Hashable, Sendable {
        case notCertified
        case certified
        case invalidOrStale
        case revalidationNeeded
    }

    var status: Status
    var artifactIds: [String]
    var lastValidatedAt: Date?
    var reconciliationMetadata: String?

    static var empty: ContactCertificationProjection {
        ContactCertificationProjection(
            status: .notCertified,
            artifactIds: [],
            lastValidatedAt: nil,
            reconciliationMetadata: nil
        )
    }
}
