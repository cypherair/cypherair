import Foundation

struct ContactCertificationArtifactReference: Codable, Equatable, Identifiable, Sendable {
    var id: String { artifactId }

    let artifactId: String
    let keyId: String
    var userId: String?
    var createdAt: Date
    var storageHint: String?
}
