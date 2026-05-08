import Foundation

struct ContactMergeResult: Equatable, Sendable {
    let survivingContact: ContactIdentitySummary
    let removedContactId: String
    let preferredKeyNeedsSelection: Bool
}
