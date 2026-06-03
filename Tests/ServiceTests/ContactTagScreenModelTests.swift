import XCTest
@testable import CypherAir

final class ContactTagScreenModelTests: ContactServiceTestCase {
    @MainActor
    func test_tagManagementModelsCanManageTagsOnlyForProtectedContacts() async throws {
        contactService.resetInMemoryStateAfterLocalDataReset()
        XCTAssertFalse(ContactsScreenModel(contactService: contactService).canManageTags)
        XCTAssertFalse(TagManagementScreenModel(contactService: contactService).canManageTags)

        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsTagManagementAvailability")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }

        XCTAssertTrue(ContactsScreenModel(contactService: opened.service).canManageTags)
        XCTAssertTrue(TagManagementScreenModel(contactService: opened.service).canManageTags)
    }

    @MainActor
    func test_tagManagementScreenModelCreatesTagForNavigation() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsTagManagementModel")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let model = TagManagementScreenModel(contactService: service)

        model.createTagName = "Managed"
        let tag = try XCTUnwrap(model.createTag())

        XCTAssertEqual(tag.displayName, "Managed")
        XCTAssertEqual(model.createTagName, "")
        XCTAssertEqual(model.visibleTags.map(\.tagId), [tag.tagId])
    }

    @MainActor
    func test_tagDetailScreenModelRenamesDeletesAndSavesMembers() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsTagDetailModel")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Managed Member",
            email: "managed-member@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let tag = try service.createTag(named: "Managed")
        let model = TagDetailScreenModel(tagId: tag.tagId, contactService: service)

        XCTAssertEqual(model.tag?.displayName, "Managed")
        XCTAssertEqual(model.membershipDraftContactIds, [])

        model.beginMemberEditing()
        model.toggleDraftMembership(contactId: contactId)
        XCTAssertTrue(model.hasMembershipDraftChanges)
        model.saveMembership()
        XCTAssertFalse(model.isEditingMembers)
        XCTAssertFalse(model.hasMembershipDraftChanges)
        XCTAssertEqual(service.contactTagSummaries().first?.contactCount, 1)

        model.beginRenameTag()
        model.renameText = "Managed Team"
        model.commitRenameTag()
        XCTAssertEqual(model.tag?.displayName, "Managed Team")
        XCTAssertFalse(model.isRenamingTag)

        model.requestDeleteTag()
        XCTAssertEqual(model.pendingDeleteTag?.displayName, "Managed Team")
        XCTAssertTrue(model.confirmDeleteTag())
        XCTAssertTrue(service.contactTagSummaries().isEmpty)
        XCTAssertNil(model.tag)
    }

    @MainActor
    func test_tagDetailScreenModelKeepsSavedGroupingUntilMembershipSave() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsTagDetailSavedGrouping")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let member = try engine.generateKey(
            name: "Alpha Member",
            email: "alpha-member@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let available = try engine.generateKey(
            name: "Bravo Available",
            email: "bravo-available@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: member.publicKeyData)
        _ = try service.importContact(publicKeyData: available.publicKeyData)
        let memberContactId = try XCTUnwrap(service.contactId(forFingerprint: member.fingerprint))
        let availableContactId = try XCTUnwrap(service.contactId(forFingerprint: available.fingerprint))
        let tag = try service.addTag(named: "Stable Grouping", toContactId: memberContactId)
        let model = TagDetailScreenModel(tagId: tag.tagId, contactService: service)

        XCTAssertEqual(model.savedMemberContactIds, [memberContactId])
        XCTAssertEqual(model.savedAvailableContactIds, [availableContactId])

        model.beginMemberEditing()
        model.toggleDraftMembership(contactId: availableContactId)

        XCTAssertTrue(model.membershipDraftContactIds.contains(availableContactId))
        XCTAssertEqual(model.savedMemberContactIds, [memberContactId])
        XCTAssertEqual(model.savedAvailableContactIds, [availableContactId])

        model.toggleDraftMembership(contactId: memberContactId)

        XCTAssertFalse(model.membershipDraftContactIds.contains(memberContactId))
        XCTAssertEqual(model.savedMemberContactIds, [memberContactId])
        XCTAssertEqual(model.savedAvailableContactIds, [availableContactId])

        model.saveMembership()

        XCTAssertFalse(model.isEditingMembers)
        XCTAssertEqual(model.savedMemberContactIds, [availableContactId])
        XCTAssertEqual(model.savedAvailableContactIds, [memberContactId])
        XCTAssertEqual(model.visibleMemberContacts.map(\.contactId), [availableContactId])
    }

    @MainActor
    func test_tagDetailScreenModelCancelMemberEditingConfirmsDiscardWhenDraftChanged() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsTagDetailDiscard")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Discard Member",
            email: "discard-member@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let tag = try service.addTag(named: "Discardable", toContactId: contactId)
        let model = TagDetailScreenModel(tagId: tag.tagId, contactService: service)

        model.beginMemberEditing()
        model.toggleDraftMembership(contactId: contactId)
        XCTAssertTrue(model.hasMembershipDraftChanges)

        model.requestCancelMemberEditing()

        XCTAssertTrue(model.isEditingMembers)
        XCTAssertTrue(model.showDiscardMemberChangesConfirmation)

        model.cancelMemberEditing()

        XCTAssertFalse(model.isEditingMembers)
        XCTAssertFalse(model.showDiscardMemberChangesConfirmation)
        XCTAssertFalse(model.hasMembershipDraftChanges)
        XCTAssertEqual(model.membershipDraftContactIds, Set([contactId]))
    }

    @MainActor
    func test_tagDetailScreenModelClearTransientInput_clearsRenameAndMemberDrafts() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsTagDetailClearInput")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Tagged Member",
            email: "tagged-member@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let tag = try service.createTag(named: "Clearable")
        try service.assignTag(tagId: tag.tagId, toContactId: contactId)
        let model = TagDetailScreenModel(tagId: tag.tagId, contactService: service)

        model.beginMemberEditing()
        model.beginRenameTag()
        model.renameText = "Renamed Draft"
        model.toggleDraftMembership(contactId: contactId)
        XCTAssertTrue(model.hasMembershipDraftChanges)

        model.clearTransientInput()

        XCTAssertFalse(model.isEditingMembers)
        XCTAssertFalse(model.isRenamingTag)
        XCTAssertEqual(model.renameText, "")
        XCTAssertFalse(model.hasMembershipDraftChanges)
        XCTAssertEqual(model.membershipDraftContactIds, Set([contactId]))
    }
}
