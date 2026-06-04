import Foundation

struct ContactTagSummary: Identifiable, Hashable, Sendable {
    var id: String { tagId }

    let tagId: String
    let displayName: String
    let normalizedName: String
    let contactCount: Int
}

extension ContactTagSummary {
    /// Returns only the tag ids that still exist among `availableTags`, dropping ids
    /// whose tag has been deleted. Shared by the Contacts and Encrypt tag-filter strips
    /// so a deleted tag silently leaves the active filter on both surfaces rather than
    /// stranding the UI on a dead filter.
    static func prunedTagFilterIds(
        _ tagFilterIds: Set<String>,
        availableTags: [ContactTagSummary]
    ) -> Set<String> {
        guard !tagFilterIds.isEmpty else {
            return []
        }
        let availableTagIds = Set(availableTags.map(\.tagId))
        return tagFilterIds.intersection(availableTagIds)
    }
}
