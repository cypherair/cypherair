import Foundation

/// The multi-select tag-filter selection shared by the Contacts and Encrypt
/// recipient surfaces.
///
/// A value type held as a stored property on each `@Observable` screen model, so
/// mutations flow through the synthesized setter and observation fires correctly.
/// Because a struct can't reach `ContactService`, pruning is caller-driven: every
/// accessor takes the current `availableTags` and delegates to
/// `ContactTagSummary.prunedTagFilterIds` (the single source of truth) so a deleted
/// tag silently leaves the active filter rather than stranding the UI on a dead one.
struct TagFilterState: Equatable, Sendable {
    private(set) var rawSelectedIds: Set<String>

    init(rawSelectedIds: Set<String> = []) {
        self.rawSelectedIds = rawSelectedIds
    }

    /// The active selection pruned to tags that still exist.
    func selectedIds(availableTags: [ContactTagSummary]) -> Set<String> {
        ContactTagSummary.prunedTagFilterIds(rawSelectedIds, availableTags: availableTags)
    }

    func isSelected(_ tagId: String, availableTags: [ContactTagSummary]) -> Bool {
        selectedIds(availableTags: availableTags).contains(tagId)
    }

    /// Toggles a tag in the filter. Adds only tags that currently exist; removing is
    /// always allowed so a stale id cannot be re-added.
    mutating func toggle(_ tagId: String, availableTags: [ContactTagSummary]) {
        let availableTagIds = Set(availableTags.map(\.tagId))
        var selected = ContactTagSummary.prunedTagFilterIds(rawSelectedIds, availableTags: availableTags)
        if selected.contains(tagId) {
            selected.remove(tagId)
        } else if availableTagIds.contains(tagId) {
            selected.insert(tagId)
        }
        rawSelectedIds = selected
    }

    /// Replaces the whole selection (e.g. applying a single search suggestion),
    /// pruned to tags that still exist.
    mutating func replace(with tagIds: Set<String>, availableTags: [ContactTagSummary]) {
        rawSelectedIds = ContactTagSummary.prunedTagFilterIds(tagIds, availableTags: availableTags)
    }

    mutating func clear() {
        rawSelectedIds.removeAll()
    }
}
