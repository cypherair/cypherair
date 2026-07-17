import XCTest
@testable import CypherAir

final class ContactDetailScreenModelTests: ContactServiceTestCase {
    @MainActor
    func test_pr3bContactDetailScreenModelProjectsCurrentDomainState() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR3BDetailProjection")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let alpha = try engine.generateKey(
            name: "Alpha Detail",
            email: "alpha-detail@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let bravo = try engine.generateKey(
            name: "Bravo Detail",
            email: "bravo-detail@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        _ = try service.importContact(publicKeyData: alpha.publicKeyData)
        _ = try service.importContact(publicKeyData: bravo.publicKeyData)
        let alphaContactId = try XCTUnwrap(service.contactId(forFingerprint: alpha.fingerprint))
        let bravoContactId = try XCTUnwrap(service.contactId(forFingerprint: bravo.fingerprint))
        let tag = try service.addTag(named: "Detail Team", toContactId: alphaContactId)

        let model = ContactDetailScreenModel(contactId: alphaContactId, contactService: service)

        XCTAssertEqual(model.contactsAvailability, .availableProtectedDomain)
        XCTAssertTrue(model.allowsProtectedIdentityActions)
        XCTAssertTrue(model.allowsProtectedCertificationPersistence)
        XCTAssertEqual(model.contact?.contactId, alphaContactId)
        XCTAssertEqual(model.contact?.preferredKey?.fingerprint, alpha.fingerprint)
        XCTAssertEqual(model.mergeCandidates.map(\.contactId), [bravoContactId])
        XCTAssertEqual(model.availableTags.map(\.tagId), [tag.tagId])
        XCTAssertEqual(model.assignedTagIds, Set([tag.tagId]))
    }

    @MainActor
    func test_pr3bContactDetailScreenModelDeletesContactAndReportsSuccess() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR3BDetailDelete")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Delete Detail",
            email: "delete-detail@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let model = ContactDetailScreenModel(contactId: contactId, contactService: service)

        XCTAssertTrue(model.removeContactIdentity())
        XCTAssertNil(service.availableContactIdentity(forContactID: contactId))
        XCTAssertFalse(model.showDetailError)
    }

    @MainActor
    func test_pr3bContactDetailScreenModelOwnsMergeTagAndKeyMutations() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR3BDetailMutations")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let first = try engine.generateKey(
            name: "Detail First",
            email: "detail-first@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let second = try engine.generateKey(
            name: "Detail Second",
            email: "detail-second@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        _ = try service.importContact(
            publicKeyData: first.publicKeyData,
            verificationState: .unverified
        )
        _ = try service.importContact(
            publicKeyData: second.publicKeyData,
            verificationState: .unverified
        )
        let targetContactId = try XCTUnwrap(service.contactId(forFingerprint: first.fingerprint))
        let sourceContactId = try XCTUnwrap(service.contactId(forFingerprint: second.fingerprint))
        let model = ContactDetailScreenModel(contactId: targetContactId, contactService: service)

        model.markVerified(fingerprint: first.fingerprint)
        XCTAssertTrue(try XCTUnwrap(model.contact?.preferredKey).isVerified)

        model.mergeContact(sourceContactId: sourceContactId)
        XCTAssertEqual(model.contact?.keys.count, 2)
        XCTAssertNil(service.availableContactIdentity(forContactID: sourceContactId))

        model.setPreferredKey(fingerprint: second.fingerprint)
        XCTAssertEqual(model.contact?.preferredKey?.fingerprint, second.fingerprint)

        model.setKeyUsage(.historical, fingerprint: first.fingerprint)
        XCTAssertEqual(model.contact?.historicalKeys.map(\.fingerprint), [first.fingerprint])

        try model.addTag("Detail Created")
        let createdTag = try XCTUnwrap(model.availableTags.first { $0.displayName == "Detail Created" })
        XCTAssertTrue(model.assignedTagIds.contains(createdTag.tagId))

        model.removeTag(createdTag.tagId)
        XCTAssertFalse(model.assignedTagIds.contains(createdTag.tagId))

        let existingTag = try service.createTag(named: "Detail Existing")
        try model.assignExistingTag(existingTag.tagId)
        XCTAssertTrue(model.assignedTagIds.contains(existingTag.tagId))
    }

    @MainActor
    func test_pr3bContactDetailScreenModelPresentsMutationErrors() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR3BDetailError")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Error Detail",
            email: "error-detail@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let model = ContactDetailScreenModel(contactId: contactId, contactService: service)

        model.setPreferredKey(fingerprint: "missing-fingerprint")

        XCTAssertTrue(model.showDetailError)
        XCTAssertNotNil(model.detailError)

        model.dismissDetailError()

        XCTAssertFalse(model.showDetailError)
        XCTAssertNil(model.detailError)
    }

    // MARK: - Load Contacts
}
