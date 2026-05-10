import Foundation

@MainActor
@Observable
final class TagManagementScreenModel {
    private let contactService: ContactService

    var searchText = ""
    var createTagName = ""
    var selectedTagId: String?
    var renameText = ""
    var isRenamingSelectedTag = false
    var pendingDeleteTag: ContactTagSummary?
    var membershipDraftContactIds: Set<String> = []
    var errorMessage: String?
    var showError = false

    init(contactService: ContactService) {
        self.contactService = contactService
    }

    var contactsAvailability: ContactsAvailability {
        contactService.contactsAvailability
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

    var contacts: [ContactIdentitySummary] {
        contactService.availableContactIdentities
    }

    var selectedTag: ContactTagSummary? {
        allTags.first { $0.tagId == selectedTagId }
    }

    var selectedTagMemberIds: Set<String> {
        guard let selectedTagId else {
            return []
        }
        return Set(contacts.filter { $0.tagIds.contains(selectedTagId) }.map(\.contactId))
    }

    var hasMembershipDraftChanges: Bool {
        membershipDraftContactIds != selectedTagMemberIds
    }

    func handleAppear() {
        refreshSelectionIfNeeded()
    }

    func selectTag(_ tagId: String) {
        selectedTagId = tagId
        resetMembershipDraft()
    }

    func createTag() {
        do {
            let tag = try contactService.createTag(named: createTagName)
            createTagName = ""
            selectedTagId = tag.tagId
            resetMembershipDraft()
        } catch {
            presentError(error)
        }
    }

    func beginRenameSelectedTag() {
        guard let selectedTag else {
            return
        }
        renameText = selectedTag.displayName
        isRenamingSelectedTag = true
    }

    func commitRenameSelectedTag() {
        guard let currentTagId = selectedTagId else {
            return
        }
        do {
            let tag = try contactService.renameTag(tagId: currentTagId, to: renameText)
            selectedTagId = tag.tagId
            isRenamingSelectedTag = false
            resetMembershipDraft()
        } catch {
            presentError(error)
        }
    }

    func requestDeleteSelectedTag() {
        pendingDeleteTag = selectedTag
    }

    func cancelDeleteTag() {
        pendingDeleteTag = nil
    }

    func confirmDeleteTag() {
        guard let tag = pendingDeleteTag else {
            return
        }
        do {
            try contactService.deleteTag(tagId: tag.tagId)
            if selectedTagId == tag.tagId {
                selectedTagId = nil
            }
            pendingDeleteTag = nil
            refreshSelectionIfNeeded()
        } catch {
            presentError(error)
        }
    }

    func setMembership(contactId: String, isMember: Bool) {
        if isMember {
            membershipDraftContactIds.insert(contactId)
        } else {
            membershipDraftContactIds.remove(contactId)
        }
    }

    func saveMembership() {
        guard let currentTagId = selectedTagId else {
            return
        }
        do {
            try contactService.replaceTagMembership(
                tagId: currentTagId,
                contactIds: membershipDraftContactIds
            )
            resetMembershipDraft()
        } catch {
            presentError(error)
        }
    }

    func resetMembershipDraft() {
        membershipDraftContactIds = selectedTagMemberIds
    }

    func dismissError() {
        errorMessage = nil
        showError = false
    }

    private func refreshSelectionIfNeeded() {
        let tags = allTags
        if let currentTagId = selectedTagId,
           tags.contains(where: { $0.tagId == currentTagId }) {
            resetMembershipDraft()
            return
        }
        selectedTagId = visibleTags.first?.tagId ?? tags.first?.tagId
        resetMembershipDraft()
    }

    private func presentError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }
}
