import XCTest
@testable import CypherAir

final class ContactsScreenModelTests: ContactServiceTestCase {
    @MainActor
    func test_pr8ContactsScreenModelSearchAndTagFiltersVisibleContacts() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR8ScreenModel")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let work = try engine.generateKey(
            name: "Work Person",
            email: "work-person@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        let personal = try engine.generateKey(
            name: "Personal Person",
            email: "personal-person@example.invalid",
            expirySeconds: nil,
            profile: .advanced
        )

        _ = try service.importContact(publicKeyData: work.publicKeyData)
        _ = try service.importContact(publicKeyData: personal.publicKeyData)
        let workContactId = try XCTUnwrap(service.contactId(forFingerprint: work.fingerprint))
        let personalContactId = try XCTUnwrap(service.contactId(forFingerprint: personal.fingerprint))
        let workTag = try service.addTag(named: "Work", toContactId: workContactId)
        let personalTag = try service.addTag(named: "Personal", toContactId: personalContactId)

        let model = ContactsScreenModel(contactService: service)
        model.searchText = "person"
        XCTAssertEqual(Set(model.visibleContacts.map(\.contactId)), Set([workContactId, personalContactId]))

        model.toggleTagFilter(workTag.tagId)
        XCTAssertEqual(model.visibleContacts.map(\.contactId), [workContactId])

        model.toggleTagFilter(personalTag.tagId)
        XCTAssertEqual(Set(model.visibleContacts.map(\.contactId)), Set([workContactId, personalContactId]))

        model.clearTagFilters()
        model.searchText = "personal"
        XCTAssertEqual(model.visibleContacts.map(\.contactId), [personalContactId])

        model.applyTagSuggestion(workTag.tagId)
        XCTAssertEqual(model.searchText, "")
        XCTAssertEqual(model.visibleContacts.map(\.contactId), [workContactId])
    }

    @MainActor
    func test_contactsScreenModelClearTransientInput_clearsSearchAndTagFilters() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsScreenModelClearInput")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Filter Person",
            email: "filter-person@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let tag = try service.addTag(named: "Filter", toContactId: contactId)
        let model = ContactsScreenModel(contactService: service)
        model.searchText = "filter"
        model.toggleTagFilter(tag.tagId)
        XCTAssertTrue(model.hasActiveSearchOrFilters)

        model.clearTransientInput()

        XCTAssertEqual(model.searchText, "")
        XCTAssertTrue(model.selectedTagFilterIds.isEmpty)
        XCTAssertFalse(model.hasActiveSearchOrFilters)
    }

    @MainActor
    func test_pr8ContactsScreenModelPrunesStaleTagFilterAfterTagDeletion() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR8ScreenModelStaleTag")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Tagged Person",
            email: "tagged-person@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )

        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let tag = try service.addTag(named: "Temporary", toContactId: contactId)

        let model = ContactsScreenModel(contactService: service)
        model.toggleTagFilter(tag.tagId)
        XCTAssertEqual(model.selectedTagFilterIds, Set([tag.tagId]))
        XCTAssertEqual(model.visibleContacts.map(\.contactId), [contactId])

        try service.removeTag(tagId: tag.tagId, fromContactId: contactId)

        XCTAssertEqual(service.contactTagSummaries().map(\.tagId), [tag.tagId])
        XCTAssertEqual(model.selectedTagFilterIds, Set([tag.tagId]))
        XCTAssertTrue(model.visibleContacts.isEmpty)
        XCTAssertTrue(model.hasActiveSearchOrFilters)

        try service.deleteTag(tagId: tag.tagId)

        XCTAssertTrue(service.contactTagSummaries().isEmpty)
        XCTAssertTrue(model.selectedTagFilterIds.isEmpty)
        XCTAssertFalse(model.hasActiveSearchOrFilters)
        XCTAssertEqual(model.visibleContacts.map(\.contactId), [contactId])
    }

    @MainActor
    func test_pr8ContactsScreenModelIgnoresMissingTagFilterIds() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR8ScreenModelMissingTag")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Searchable Person",
            email: "searchable-person@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )

        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))

        let model = ContactsScreenModel(contactService: service)
        model.selectedTagFilterIds = ["missing-tag"]
        XCTAssertTrue(model.selectedTagFilterIds.isEmpty)
        XCTAssertFalse(model.hasActiveSearchOrFilters)

        model.toggleTagFilter("missing-tag")
        XCTAssertTrue(model.selectedTagFilterIds.isEmpty)
        XCTAssertFalse(model.hasActiveSearchOrFilters)

        model.searchText = "searchable"
        XCTAssertTrue(model.hasActiveSearchOrFilters)
        XCTAssertEqual(model.visibleContacts.map(\.contactId), [contactId])
    }
}
