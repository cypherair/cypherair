import XCTest
@testable import CypherAir

final class ContactServiceTagTests: ContactServiceTestCase {
    // MARK: - Tags

    func test_pr8ProtectedTagsNormalizeDedupePersistAndRetainEmptyTags() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR8Tags")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Tagged Contact",
            email: "tagged@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))

        let firstTag = try service.addTag(named: "  Work   Legal  ", toContactId: contactId)
        let duplicateTag = try service.addTag(named: "work legal", toContactId: contactId)

        XCTAssertEqual(firstTag.tagId, duplicateTag.tagId)
        XCTAssertEqual(firstTag.displayName, "Work Legal")
        XCTAssertEqual(service.contactTagSummaries().map(\.displayName), ["Work Legal"])
        XCTAssertEqual(
            service.contactIdentities(matching: "work legal").map(\.contactId),
            [contactId]
        )

        try await service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        let reopenedService = reopened.service
        XCTAssertEqual(reopenedService.contactTagSummaries().map(\.displayName), ["Work Legal"])

        try reopenedService.removeTag(tagId: firstTag.tagId, fromContactId: contactId)
        XCTAssertEqual(reopenedService.contactTagSummaries().map(\.displayName), ["Work Legal"])
        XCTAssertEqual(reopenedService.contactTagSummaries().first?.contactCount, 0)
        XCTAssertTrue(
            try XCTUnwrap(reopenedService.availableContactIdentity(forContactID: contactId))
                .tagIds
                .isEmpty
        )

        try reopenedService.deleteTag(tagId: firstTag.tagId)
        XCTAssertTrue(reopenedService.contactTagSummaries().isEmpty)
    }

    func test_tagManagementCreatesRenamesDeletesAndReplacesMembership() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsTagManagement")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let first = try engine.generateKey(
            name: "Tag Member One",
            email: "tag-member-one@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let second = try engine.generateKey(
            name: "Tag Member Two",
            email: "tag-member-two@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        _ = try service.importContact(publicKeyData: first.publicKeyData)
        _ = try service.importContact(publicKeyData: second.publicKeyData)
        let firstContactId = try XCTUnwrap(service.contactId(forFingerprint: first.fingerprint))
        let secondContactId = try XCTUnwrap(service.contactId(forFingerprint: second.fingerprint))

        let tag = try service.createTag(named: "  Team   Alpha  ")
        XCTAssertEqual(tag.displayName, "Team Alpha")
        XCTAssertEqual(tag.contactCount, 0)
        XCTAssertThrowsError(try service.createTag(named: "team alpha")) { error in
            guard case .invalidKeyData = error as? CypherAirError else {
                return XCTFail("Expected invalidKeyData for duplicate tag, got \(error)")
            }
        }

        let renamed = try service.renameTag(tagId: tag.tagId, to: "Core Team")
        XCTAssertEqual(renamed.displayName, "Core Team")
        _ = try service.createTag(named: "Archive")
        XCTAssertThrowsError(try service.renameTag(tagId: renamed.tagId, to: "archive")) { error in
            guard case .invalidKeyData = error as? CypherAirError else {
                return XCTFail("Expected invalidKeyData for duplicate rename, got \(error)")
            }
        }

        try service.replaceTagMembership(
            tagId: renamed.tagId,
            contactIds: [firstContactId, secondContactId]
        )
        XCTAssertEqual(
            service.contactTagSummaries().first { $0.tagId == renamed.tagId }?.contactCount,
            2
        )
        XCTAssertEqual(
            Set(try XCTUnwrap(service.availableContactIdentity(forContactID: firstContactId)).tagIds),
            Set([renamed.tagId])
        )

        try service.replaceTagMembership(tagId: renamed.tagId, contactIds: [])
        XCTAssertEqual(
            service.contactTagSummaries().first { $0.tagId == renamed.tagId }?.contactCount,
            0
        )
        XCTAssertTrue(try XCTUnwrap(service.availableContactIdentity(forContactID: secondContactId)).tagIds.isEmpty)

        try service.deleteTag(tagId: renamed.tagId)
        XCTAssertNil(service.contactTagSummaries().first { $0.tagId == renamed.tagId })
    }

    func test_tagManagementOperationsRequireProtectedContacts() async throws {
        contactService.resetInMemoryStateAfterLocalDataReset()

        XCTAssertThrowsError(try contactService.createTag(named: "Locked Tag")) { error in
            guard case .contactsUnavailable(.locked) = error as? CypherAirError else {
                return XCTFail("Expected contactsUnavailable(.locked), got \(error)")
            }
        }

        try await contactService.openProtectedContactsForTests()
        XCTAssertNoThrow(try contactService.createTag(named: "Protected Tag"))
    }

    // MARK: - Search

    func test_pr8SearchRanksAndMatchesTagsFingerprintAndShortKeyId() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR8Search")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let exact = try engine.generateKey(
            name: "Alpha",
            email: "alpha@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let prefix = try engine.generateKey(
            name: "Alphabet Soup",
            email: "prefix@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let substring = try engine.generateKey(
            name: "Team Alpha Member",
            email: "substring@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        _ = try service.importContact(publicKeyData: substring.publicKeyData)
        _ = try service.importContact(publicKeyData: prefix.publicKeyData)
        _ = try service.importContact(publicKeyData: exact.publicKeyData)
        let exactContactId = try XCTUnwrap(service.contactId(forFingerprint: exact.fingerprint))
        let prefixContactId = try XCTUnwrap(service.contactId(forFingerprint: prefix.fingerprint))
        let substringContactId = try XCTUnwrap(service.contactId(forFingerprint: substring.fingerprint))

        _ = try service.addTag(named: "Operations", toContactId: substringContactId)

        XCTAssertEqual(
            service.contactIdentities(matching: "Alpha").map(\.contactId),
            [exactContactId, prefixContactId, substringContactId]
        )
        XCTAssertEqual(
            service.contactIdentities(matching: "operations").map(\.contactId),
            [substringContactId]
        )
        XCTAssertEqual(
            service.contactIdentities(matching: prefix.fingerprint).map(\.contactId),
            [prefixContactId]
        )
        XCTAssertEqual(
            service.contactIdentities(
                matching: IdentityPresentation.shortKeyId(from: substring.fingerprint)
            ).map(\.contactId),
            [substringContactId]
        )
        XCTAssertEqual(
            service.contactIdentities(matching: "", tagFilterIds: [try XCTUnwrap(service.contactTagSummaries().first?.tagId)])
                .map(\.contactId),
            [substringContactId]
        )
    }

    func test_pr8RecipientSearchMatchesOnlyPreferredEncryptableKeyIdentifiers() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR8RecipientSearch")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let preferred = try engine.generateKey(
            name: "Recipient Preferred",
            email: "recipient-preferred@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let historical = try engine.generateKey(
            name: "Recipient Historical",
            email: "recipient-historical@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        _ = try service.importContact(publicKeyData: preferred.publicKeyData)
        _ = try service.importContact(publicKeyData: historical.publicKeyData)
        let targetContactId = try XCTUnwrap(service.contactId(forFingerprint: preferred.fingerprint))
        let sourceContactId = try XCTUnwrap(service.contactId(forFingerprint: historical.fingerprint))

        _ = try service.mergeContact(sourceContactId: sourceContactId, into: targetContactId)
        try service.setKeyUsageState(.historical, fingerprint: historical.fingerprint)

        XCTAssertEqual(
            service.contactIdentities(matching: historical.fingerprint).map(\.contactId),
            [targetContactId]
        )
        XCTAssertEqual(
            service.contactIdentities(
                matching: IdentityPresentation.shortKeyId(from: historical.fingerprint)
            ).map(\.contactId),
            [targetContactId]
        )
        XCTAssertTrue(service.recipientContacts(matching: historical.fingerprint).isEmpty)
        XCTAssertTrue(
            service.recipientContacts(
                matching: IdentityPresentation.shortKeyId(from: historical.fingerprint)
            )
            .isEmpty
        )
        XCTAssertEqual(
            service.recipientContacts(matching: preferred.fingerprint).map(\.contactId),
            [targetContactId]
        )
        XCTAssertEqual(
            service.recipientContacts(
                matching: IdentityPresentation.shortKeyId(from: preferred.fingerprint)
            ).map(\.contactId),
            [targetContactId]
        )
    }
}
