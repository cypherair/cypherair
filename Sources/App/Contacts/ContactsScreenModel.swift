import Foundation

@MainActor
@Observable
final class ContactsScreenModel {
    private let contactService: ContactService
    private var rawSelectedTagFilterIds: Set<String> = []

    var searchText = ""
    var selectedTagFilterIds: Set<String> {
        get {
            prunedTagFilterIds(rawSelectedTagFilterIds, availableTags: tagFilters)
        }
        set {
            rawSelectedTagFilterIds = prunedTagFilterIds(newValue, availableTags: tagFilters)
        }
    }
    var deleteError: String?
    var showDeleteError = false

    init(contactService: ContactService) {
        self.contactService = contactService
    }

    var contactsAvailability: ContactsAvailability {
        contactService.contactsAvailability
    }

    var visibleContacts: [ContactIdentitySummary] {
        let filters = tagFilters
        return contactService.contactIdentities(
            matching: searchText,
            tagFilterIds: prunedTagFilterIds(rawSelectedTagFilterIds, availableTags: filters)
        )
    }

    var tagFilters: [ContactTagSummary] {
        guard contactsAvailability.isAvailable else {
            return []
        }
        return contactService.contactTagSummaries()
    }

    var selectedTagFilters: [ContactTagSummary] {
        let filters = tagFilters
        let selectedIds = prunedTagFilterIds(rawSelectedTagFilterIds, availableTags: filters)
        return filters.filter { selectedIds.contains($0.tagId) }
    }

    var tagSuggestions: [ContactTagSummary] {
        contactService.tagSuggestions(matching: searchText)
    }

    var hasActiveSearchOrFilters: Bool {
        !ContactsSearchIndex.normalizedSearchText(searchText).isEmpty ||
            !prunedTagFilterIds(rawSelectedTagFilterIds, availableTags: tagFilters).isEmpty
    }

    func toggleTagFilter(_ tagId: String) {
        let filters = tagFilters
        let availableTagIds = Set(filters.map(\.tagId))
        var selectedIds = prunedTagFilterIds(rawSelectedTagFilterIds, availableTags: filters)

        if selectedIds.contains(tagId) {
            selectedIds.remove(tagId)
        } else if availableTagIds.contains(tagId) {
            selectedIds.insert(tagId)
        }
        rawSelectedTagFilterIds = selectedIds
    }

    func clearTagFilters() {
        rawSelectedTagFilterIds.removeAll()
    }

    func deleteContacts(at indexSet: IndexSet, from contacts: [ContactIdentitySummary]) {
        for index in indexSet {
            let contact = contacts[index]
            do {
                try contactService.removeContactIdentity(contactId: contact.contactId)
            } catch {
                deleteError = error.localizedDescription
                showDeleteError = true
            }
        }
    }

    private func prunedTagFilterIds(
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
