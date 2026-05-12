import Foundation

@MainActor
@Observable
final class TagManagementScreenModel {
    private let contactService: ContactService

    var searchText = ""
    var createTagName = ""
    var errorMessage: String?
    var showError = false

    init(contactService: ContactService) {
        self.contactService = contactService
    }

    var contactsAvailability: ContactsAvailability {
        contactService.contactsAvailability
    }

    var canManageTags: Bool {
        contactsAvailability == .availableProtectedDomain
    }

    var allTags: [ContactTagSummary] {
        contactService.contactTagSummaries()
    }

    var visibleTags: [ContactTagSummary] {
        let normalizedSearchText = ContactsSearchIndex.normalizedSearchText(searchText)
        guard !normalizedSearchText.isEmpty else {
            return allTags
        }
        return allTags.filter {
            ContactsSearchIndex.normalizedSearchText($0.displayName).contains(normalizedSearchText)
        }
    }

    func handleAppear() {
    }

    @discardableResult
    func createTag() -> ContactTagSummary? {
        do {
            let tag = try contactService.createTag(named: createTagName)
            createTagName = ""
            return tag
        } catch {
            presentError(error)
            return nil
        }
    }

    @discardableResult
    func createTagIfValid() -> ContactTagSummary? {
        guard !ContactTag.displayName(for: createTagName).isEmpty else {
            return nil
        }
        return createTag()
    }

    func dismissError() {
        errorMessage = nil
        showError = false
    }

    func clearTransientInput() {
        searchText = ""
        createTagName = ""
    }

    private func presentError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }
}
