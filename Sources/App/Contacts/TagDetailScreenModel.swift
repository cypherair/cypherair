import Foundation

@MainActor
@Observable
final class TagDetailScreenModel {
    private let contactService: ContactService
    let tagId: String

    var isEditingMembers = false
    var membershipDraftContactIds: Set<String> = []
    var isRenamingTag = false
    var renameText = ""
    var pendingDeleteTag: ContactTagSummary?
    var showDiscardMemberChangesConfirmation = false
    var errorMessage: String?
    var showError = false

    init(tagId: String, contactService: ContactService) {
        self.tagId = tagId
        self.contactService = contactService
        membershipDraftContactIds = selectedTagMemberIds
    }

    var contactsAvailability: ContactsAvailability {
        contactService.contactsAvailability
    }

    var canManageTag: Bool {
        contactsAvailability == .availableProtectedDomain
    }

    var tag: ContactTagSummary? {
        contactService.contactTagSummaries().first { $0.tagId == tagId }
    }

    var contacts: [ContactIdentitySummary] {
        contactService.availableContactIdentities
    }

    var selectedTagMemberIds: Set<String> {
        Set(contacts.filter { $0.tagIds.contains(tagId) }.map(\.contactId))
    }

    var visibleMemberContacts: [ContactIdentitySummary] {
        contacts.filter { $0.tagIds.contains(tagId) }
    }

    var memberCountText: String {
        String.localizedStringWithFormat(
            String(localized: "tagManagement.contactCount", defaultValue: "%d contacts"),
            tag?.contactCount ?? selectedTagMemberIds.count
        )
    }

    var hasMembershipDraftChanges: Bool {
        membershipDraftContactIds != selectedTagMemberIds
    }

    var canSaveMembershipDraft: Bool {
        isEditingMembers && hasMembershipDraftChanges
    }

    var canCommitRename: Bool {
        !ContactTag.displayName(for: renameText).isEmpty
    }

    func handleAppear() {
        if !isEditingMembers {
            resetMembershipDraft()
        }
    }

    func beginMemberEditing() {
        membershipDraftContactIds = selectedTagMemberIds
        isEditingMembers = true
    }

    func requestCancelMemberEditing() {
        if hasMembershipDraftChanges {
            showDiscardMemberChangesConfirmation = true
        } else {
            cancelMemberEditing()
        }
    }

    func cancelMemberEditing() {
        resetMembershipDraft()
        isEditingMembers = false
        showDiscardMemberChangesConfirmation = false
    }

    func toggleDraftMembership(contactId: String) {
        guard isEditingMembers else {
            return
        }
        if membershipDraftContactIds.contains(contactId) {
            membershipDraftContactIds.remove(contactId)
        } else {
            membershipDraftContactIds.insert(contactId)
        }
    }

    func saveMembership() {
        guard canSaveMembershipDraft else {
            return
        }
        do {
            try contactService.replaceTagMembership(
                tagId: tagId,
                contactIds: membershipDraftContactIds
            )
            resetMembershipDraft()
            isEditingMembers = false
        } catch {
            presentError(error)
        }
    }

    func beginRenameTag() {
        guard let tag else {
            return
        }
        renameText = tag.displayName
        isRenamingTag = true
    }

    func cancelRenameTag() {
        renameText = ""
        isRenamingTag = false
    }

    func commitRenameTag() {
        guard canCommitRename else {
            return
        }
        do {
            _ = try contactService.renameTag(tagId: tagId, to: renameText)
            cancelRenameTag()
        } catch {
            presentError(error)
        }
    }

    func requestDeleteTag() {
        pendingDeleteTag = tag
    }

    func cancelDeleteTag() {
        pendingDeleteTag = nil
    }

    func confirmDeleteTag() -> Bool {
        do {
            try contactService.deleteTag(tagId: tagId)
            pendingDeleteTag = nil
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    func dismissError() {
        errorMessage = nil
        showError = false
    }

    func clearTransientInput() {
        cancelRenameTag()
        cancelMemberEditing()
    }

    private func resetMembershipDraft() {
        membershipDraftContactIds = selectedTagMemberIds
    }

    private func presentError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }
}
