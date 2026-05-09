import Foundation

struct ContactMergePreview: Identifiable, Equatable, Sendable {
    var id: String { source.contactId }

    let source: ContactIdentitySummary
    let target: ContactIdentitySummary
}
