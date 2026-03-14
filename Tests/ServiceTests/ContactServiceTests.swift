import XCTest
@testable import CypherAir

/// Tests for ContactService — public key storage, duplicate detection,
/// key update detection, contact removal, and lookup.
final class ContactServiceTests: XCTestCase {

    private var engine: PgpEngine!
    private var contactService: ContactService!
    private var tempDir: URL!

    override func setUp() {
        super.setUp()
        engine = PgpEngine()
        let result = TestHelpers.makeContactService(engine: engine)
        contactService = result.service
        tempDir = result.tempDir
    }

    override func tearDown() {
        TestHelpers.cleanupTempDir(tempDir)
        contactService = nil
        engine = nil
        tempDir = nil
        super.tearDown()
    }

    // MARK: - Load Contacts

    func test_loadContacts_emptyDirectory_returnsEmpty() throws {
        try contactService.loadContacts()
        XCTAssertTrue(contactService.contacts.isEmpty,
                      "Loading from empty directory should produce no contacts")
    }

    // MARK: - Add Contact

    func test_addContact_validPublicKey_returnsAdded() throws {
        let generated = try engine.generateKey(
            name: "Alice", email: "alice@example.com",
            expirySeconds: nil, profile: .universal
        )

        let result = try contactService.addContact(publicKeyData: generated.publicKeyData)

        if case .added(let contact) = result {
            XCTAssertFalse(contact.fingerprint.isEmpty)
        } else {
            XCTFail("Expected .added, got \(result)")
        }

        XCTAssertEqual(contactService.contacts.count, 1)
    }

    func test_addContact_duplicateFingerprint_returnsDuplicate() throws {
        let generated = try engine.generateKey(
            name: "Bob", email: "bob@example.com",
            expirySeconds: nil, profile: .universal
        )

        // Add once
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)

        // Add again — same fingerprint
        let result = try contactService.addContact(publicKeyData: generated.publicKeyData)

        if case .duplicate = result {
            // Expected
        } else {
            XCTFail("Expected .duplicate, got \(result)")
        }

        XCTAssertEqual(contactService.contacts.count, 1,
                       "Duplicate should not increase contact count")
    }

    func test_addContact_sameUserIdDifferentFingerprint_returnsKeyUpdateDetected() throws {
        // Generate two keys with the same userId but different fingerprints
        let key1 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )
        let key2 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )

        // Add first key
        _ = try contactService.addContact(publicKeyData: key1.publicKeyData)

        // Add second key with same userId
        let result = try contactService.addContact(publicKeyData: key2.publicKeyData)

        if case .keyUpdateDetected(let newContact, let existingContact, _) = result {
            XCTAssertNotEqual(newContact.fingerprint, existingContact.fingerprint,
                              "Key update should have different fingerprints")
        } else {
            XCTFail("Expected .keyUpdateDetected, got \(result)")
        }

        // Count should still be 1 — update not yet confirmed
        XCTAssertEqual(contactService.contacts.count, 1)
    }

    // MARK: - Remove Contact

    func test_removeContact_existingContact_removesFromArray() throws {
        let generated = try engine.generateKey(
            name: "Dave", email: nil,
            expirySeconds: nil, profile: .advanced
        )

        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        XCTAssertEqual(contactService.contacts.count, 1)

        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        try contactService.removeContact(fingerprint: keyInfo.fingerprint)

        XCTAssertEqual(contactService.contacts.count, 0,
                       "Contact should be removed from array")
    }

    // MARK: - Lookup

    func test_contactsMatchingKeyIds_returnsCorrectContacts() throws {
        let key1 = try engine.generateKey(
            name: "Eve", email: nil,
            expirySeconds: nil, profile: .universal
        )
        let key2 = try engine.generateKey(
            name: "Frank", email: nil,
            expirySeconds: nil, profile: .advanced
        )

        _ = try contactService.addContact(publicKeyData: key1.publicKeyData)
        _ = try contactService.addContact(publicKeyData: key2.publicKeyData)
        XCTAssertEqual(contactService.contacts.count, 2)

        let info1 = try engine.parseKeyInfo(keyData: key1.publicKeyData)

        // Lookup by full fingerprint
        let found = contactService.contact(forFingerprint: info1.fingerprint)
        XCTAssertNotNil(found, "Should find contact by full fingerprint")
        XCTAssertEqual(found?.fingerprint, info1.fingerprint)
    }
}
