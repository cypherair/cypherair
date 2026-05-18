import Foundation

@MainActor
@Observable
final class ContactDetailScreenModel {
    let contactId: String

    private let contactService: ContactService

    var showDeleteConfirmation = false
    var showMergeDialog = false
    var showAddTagSheet = false
    var pendingTagRemoval: ContactTagSummary?
    var detailError: String?
    var showDetailError = false

    init(contactId: String, contactService: ContactService) {
        self.contactId = contactId
        self.contactService = contactService
    }

    var contactsAvailability: ContactsAvailability {
        contactService.contactsAvailability
    }

    var contact: ContactIdentitySummary? {
        contactService.availableContactIdentity(forContactID: contactId)
    }

    var mergeCandidates: [ContactIdentitySummary] {
        contactService.availableContactIdentities.filter { $0.contactId != contactId }
    }

    var availableTags: [ContactTagSummary] {
        contactService.contactTagSummaries()
    }

    var assignedTagIds: Set<String> {
        Set(contact?.tagIds ?? [])
    }

    var allowsProtectedIdentityActions: Bool {
        contactsAvailability == .availableProtectedDomain
    }

    var allowsProtectedCertificationPersistence: Bool {
        contactsAvailability.allowsProtectedCertificationPersistence
    }

    func dismissDetailError() {
        detailError = nil
        showDetailError = false
    }

    @discardableResult
    func removeContactIdentity() -> Bool {
        do {
            try contactService.removeContactIdentity(contactId: contactId)
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    func mergeContact(sourceContactId: String) {
        do {
            _ = try contactService.mergeContact(
                sourceContactId: sourceContactId,
                into: contactId
            )
        } catch {
            presentError(error)
        }
    }

    func addTag(_ name: String) throws {
        try contactService.addTag(named: name, toContactId: contactId)
    }

    func assignExistingTag(_ tagId: String) throws {
        try contactService.assignTag(tagId: tagId, toContactId: contactId)
    }

    func removeTag(_ tagId: String) {
        do {
            try contactService.removeTag(tagId: tagId, fromContactId: contactId)
        } catch {
            presentError(error)
        }
    }

    func markVerified(fingerprint: String) {
        do {
            try contactService.setVerificationState(.verified, for: fingerprint)
        } catch {
            presentError(error)
        }
    }

    func setPreferredKey(fingerprint: String) {
        do {
            try contactService.setPreferredKey(fingerprint: fingerprint, for: contactId)
        } catch {
            presentError(error)
        }
    }

    func setKeyUsage(_ usageState: ContactKeyUsageState, fingerprint: String) {
        do {
            try contactService.setKeyUsageState(usageState, fingerprint: fingerprint)
        } catch {
            presentError(error)
        }
    }

    private func presentError(_ error: Error) {
        detailError = error.localizedDescription
        showDetailError = true
    }
}
