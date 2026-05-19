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

    var contact: ContactIdentitySummary {
        switch self {
        case .added(let contact, _),
             .addedWithCandidate(let contact, _, _),
             .duplicate(let contact, _),
             .updated(let contact, _):
            contact
        }
    }

    var key: ContactKeySummary {
        switch self {
        case .added(_, let key),
             .addedWithCandidate(_, let key, _),
             .duplicate(_, let key),
             .updated(_, let key):
            key
        }
    }
}
