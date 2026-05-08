import Foundation

struct ContactCandidateMatch: Equatable, Sendable {
    let strength: ContactCandidateMatchStrength
    let contactIds: [String]
    let displayName: String
    let primaryEmail: String?
}
