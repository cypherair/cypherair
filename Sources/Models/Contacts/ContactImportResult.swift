import Foundation

enum ContactImportResult: Equatable, Sendable {
    case added(contact: ContactIdentitySummary, key: ContactKeySummary)
    case addedWithCandidate(
        contact: ContactIdentitySummary,
        key: ContactKeySummary,
        candidate: ContactCandidateMatch
    )
    case duplicate(contact: ContactIdentitySummary, key: ContactKeySummary)
    case updated(contact: ContactIdentitySummary, key: ContactKeySummary)
}
