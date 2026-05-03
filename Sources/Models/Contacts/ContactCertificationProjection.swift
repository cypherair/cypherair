import Foundation

struct ContactCertificationProjection: Codable, Equatable, Sendable {
    enum Status: String, Codable, Equatable, Sendable {
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
