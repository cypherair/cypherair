import Foundation

@MainActor
@Observable
final class TagManagementScreenModel {
    private let contactService: ContactService

    var searchText = ""
    var createTagName = ""
    var selectedTagId: String?
    var renameTargetTagId: String?
    var renameText = ""
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

    var isRenamingSelectedTag: Bool {
        guard let selectedTagId, let renameTargetTagId else {
            return false
        }
        return selectedTagId == renameTargetTagId
    }

    func handleAppear() {
        refreshSelectionIfNeeded()
    }

    func selectTag(_ tagId: String) {
        if selectedTagId != tagId {
            cancelRename()
        }
        selectedTagId = tagId
        resetMembershipDraft()
    }

    func createTag() {
        do {
            let tag = try contactService.createTag(named: createTagName)
            createTagName = ""
            selectedTagId = tag.tagId
            cancelRename()
            resetMembershipDraft()
        } catch {
            presentError(error)
        }
    }

    func beginRenameSelectedTag() {
        guard let selectedTagId, let selectedTag else {
            return
        }
        renameTargetTagId = selectedTagId
        renameText = selectedTag.displayName
    }

    func commitRenameSelectedTag() {
        guard let currentTagId = renameTargetTagId else {
            return
        }
        do {
            let tag = try contactService.renameTag(tagId: currentTagId, to: renameText)
            selectedTagId = tag.tagId
            cancelRename()
            resetMembershipDraft()
        } catch {
            presentError(error)
        }
    }

    func cancelRename() {
        renameTargetTagId = nil
        renameText = ""
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
            if renameTargetTagId == tag.tagId {
                cancelRename()
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
            if let renameTargetTagId,
               !tags.contains(where: { $0.tagId == renameTargetTagId }) {
                cancelRename()
            }
            resetMembershipDraft()
            return
        }
        cancelRename()
        selectedTagId = visibleTags.first?.tagId ?? tags.first?.tagId
        resetMembershipDraft()
    }

    private func presentError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }
}
