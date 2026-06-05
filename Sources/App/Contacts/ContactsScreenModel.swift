import Foundation

@MainActor
@Observable
final class ContactsScreenModel {
    private let contactService: ContactService
    private var tagFilterState = TagFilterState()

    var searchText = ""
    var selectedTagFilterIds: Set<String> {
        get {
            tagFilterState.selectedIds(availableTags: tagFilters)
        }
        set {
            tagFilterState.replace(with: newValue, availableTags: tagFilters)
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

    var canManageTags: Bool {
        contactsAvailability == .availableProtectedDomain
    }

    var visibleContacts: [ContactIdentitySummary] {
        let filters = tagFilters
        return contactService.contactIdentities(
            matching: searchText,
            tagFilterIds: tagFilterState.selectedIds(availableTags: filters)
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
        let selectedIds = tagFilterState.selectedIds(availableTags: filters)
        return filters.filter { selectedIds.contains($0.tagId) }
    }

    var tagSuggestions: [ContactTagSummary] {
        contactService.tagSuggestions(matching: searchText)
    }

    var hasActiveSearchOrFilters: Bool {
        !ContactsSearchIndex.normalizedSearchText(searchText).isEmpty ||
            !tagFilterState.selectedIds(availableTags: tagFilters).isEmpty
    }

    func toggleTagFilter(_ tagId: String) {
        tagFilterState.toggle(tagId, availableTags: tagFilters)
    }

    func isTagFilterSelected(_ tagId: String) -> Bool {
        tagFilterState.isSelected(tagId, availableTags: tagFilters)
    }

    func applyTagSuggestion(_ tagId: String) {
        let filters = tagFilters
        guard Set(filters.map(\.tagId)).contains(tagId) else {
            return
        }
        tagFilterState.replace(with: [tagId], availableTags: filters)
        searchText = ""
    }

    func clearTagFilters() {
        tagFilterState.clear()
    }

    func clearTransientInput() {
        searchText = ""
        tagFilterState.clear()
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
}
