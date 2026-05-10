import Foundation

struct ContactTagSummary: Identifiable, Hashable, Sendable {
    var id: String { tagId }

    let tagId: String
    let displayName: String
    let normalizedName: String
    let contactCount: Int
}
