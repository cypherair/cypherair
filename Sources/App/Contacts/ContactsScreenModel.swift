import Foundation

@MainActor
@Observable
final class ContactsScreenModel {
    private let contactService: ContactService

    var searchText = ""
    var selectedTagFilterIds: Set<String> = []
    var deleteError: String?
    var showDeleteError = false

    init(contactService: ContactService) {
        self.contactService = contactService
    }

    var contactsAvailability: ContactsAvailability {
        contactService.contactsAvailability
    }

    var visibleContacts: [ContactIdentitySummary] {
        contactService.contactIdentities(
            matching: searchText,
            tagFilterIds: selectedTagFilterIds
        )
    }

    var tagFilters: [ContactTagSummary] {
        contactService.contactTagSummaries()
    }

    var selectedTagFilters: [ContactTagSummary] {
        let selectedIds = selectedTagFilterIds
        return tagFilters.filter { selectedIds.contains($0.tagId) }
    }

    var tagSuggestions: [ContactTagSummary] {
        contactService.tagSuggestions(matching: searchText)
    }

    var hasActiveSearchOrFilters: Bool {
        !ContactsSearchIndex.normalizedSearchText(searchText).isEmpty ||
            !selectedTagFilterIds.isEmpty
    }

    func toggleTagFilter(_ tagId: String) {
        if selectedTagFilterIds.contains(tagId) {
            selectedTagFilterIds.remove(tagId)
        } else {
            selectedTagFilterIds.insert(tagId)
        }
    }

    func clearTagFilters() {
        selectedTagFilterIds.removeAll()
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
