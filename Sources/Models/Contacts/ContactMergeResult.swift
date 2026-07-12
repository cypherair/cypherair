import Foundation

struct ContactMergeResult: Equatable, Sendable {
    let survivingContact: ContactIdentitySummary
    let preferredKeyNeedsSelection: Bool
}
