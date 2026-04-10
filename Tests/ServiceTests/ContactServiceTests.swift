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

    private func loadFixture(_ name: String) throws -> Data {
        try FixtureLoader.loadData(name, ext: "gpg")
    }

    // MARK: - Load Contacts

    func test_loadContacts_emptyDirectory_returnsEmpty() throws {
        try contactService.loadContacts()
        XCTAssertTrue(contactService.contacts.isEmpty,
                      "Loading from empty directory should produce no contacts")
    }

    func test_loadContacts_secretCertificateOnDisk_skipsFileAndPrunesMetadata() throws {
        let valid = try engine.generateKey(
            name: "Stored Valid",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        let secretBearing = try engine.generateKey(
            name: "Stored Secret",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
        )

        try valid.publicKeyData.write(
            to: tempDir.appendingPathComponent("\(valid.fingerprint).gpg"),
            options: .atomic
        )
        try secretBearing.certData.write(
            to: tempDir.appendingPathComponent("\(secretBearing.fingerprint).gpg"),
            options: .atomic
        )

        let metadataURL = tempDir.appendingPathComponent("contact-metadata.json")
        let manifest: [String: Any] = [
            "verificationStates": [
                valid.fingerprint: ContactVerificationState.verified.rawValue,
                secretBearing.fingerprint: ContactVerificationState.verified.rawValue,
            ]
        ]
        let metadata = try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
        try metadata.write(to: metadataURL, options: .atomic)

        try contactService.loadContacts()

        XCTAssertEqual(contactService.contacts.count, 1)
        XCTAssertEqual(contactService.contacts.first?.fingerprint, valid.fingerprint)

        let storedMetadata = try Data(contentsOf: metadataURL)
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: storedMetadata) as? [String: Any]
        )
        let verificationStates = try XCTUnwrap(json["verificationStates"] as? [String: String])
        XCTAssertEqual(verificationStates.count, 1)
        XCTAssertEqual(verificationStates[valid.fingerprint], ContactVerificationState.verified.rawValue)
        XCTAssertNil(verificationStates[secretBearing.fingerprint])
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

    func test_addContact_secretCertificateRejectedWithoutPersisting() throws {
        let generated = try engine.generateKey(
            name: "Secret Contact Reject",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        XCTAssertThrowsError(try contactService.addContact(publicKeyData: generated.certData)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .contactImportRequiresPublicCertificate = cypherError else {
                return XCTFail("Expected .contactImportRequiresPublicCertificate, got \(cypherError)")
            }
        }

        XCTAssertTrue(contactService.contacts.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("\(generated.fingerprint).gpg").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("contact-metadata.json").path))
    }

    func test_addContact_armoredSecretCertificateRejectedWithoutPersisting() throws {
        let generated = try engine.generateKey(
            name: "Armored Secret Contact Reject",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
        )
        let armoredSecret = try engine.armor(data: generated.certData, kind: .secretKey)

        XCTAssertThrowsError(try contactService.addContact(publicKeyData: armoredSecret)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .contactImportRequiresPublicCertificate = cypherError else {
                return XCTFail("Expected .contactImportRequiresPublicCertificate, got \(cypherError)")
            }
        }

        XCTAssertTrue(contactService.contacts.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("\(generated.fingerprint).gpg").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("contact-metadata.json").path))
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

    func test_addContact_sameFingerprintMaterialUpdate_returnsUpdated() throws {
        let generated = try engine.generateKey(
            name: "Update", email: "update@example.com",
            expirySeconds: nil, profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        let result = try contactService.addContact(publicKeyData: refreshed.publicKeyData)

        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertEqual(contactService.contacts.count, 1)
        XCTAssertEqual(updatedContact.fingerprint, generated.fingerprint)
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: updatedContact.publicKeyData).expiryTimestamp,
            refreshed.keyInfo.expiryTimestamp
        )

        let storedFile = tempDir.appendingPathComponent("\(generated.fingerprint).gpg")
        let storedData = try Data(contentsOf: storedFile)
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: storedData).expiryTimestamp,
            refreshed.keyInfo.expiryTimestamp,
            "Stored contact file should be updated in place"
        )

        let restarted = ContactService(engine: engine, contactsDirectory: tempDir)
        try restarted.loadContacts()
        XCTAssertEqual(restarted.contacts.count, 1)
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: restarted.contacts[0].publicKeyData).expiryTimestamp,
            refreshed.keyInfo.expiryTimestamp
        )
    }

    func test_addContact_sameFingerprintMaterialUpdate_preservesUnverifiedState() throws {
        let generated = try engine.generateKey(
            name: "Update Unverified", email: "update-unverified@example.com",
            expirySeconds: nil, profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        let result = try contactService.addContact(
            publicKeyData: refreshed.publicKeyData,
            verificationState: .unverified
        )
        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertFalse(updatedContact.isVerified)

        let restarted = ContactService(engine: engine, contactsDirectory: tempDir)
        try restarted.loadContacts()
        XCTAssertFalse(restarted.contacts[0].isVerified)
    }

    func test_addContact_sameFingerprintMaterialUpdate_verifiedImportPromotesExistingUnverifiedContact() throws {
        let generated = try engine.generateKey(
            name: "Update Promote", email: "update-promote@example.com",
            expirySeconds: nil, profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        let result = try contactService.addContact(
            publicKeyData: refreshed.publicKeyData,
            verificationState: .verified
        )
        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.isVerified)
        XCTAssertTrue(contactService.contact(forFingerprint: updatedContact.fingerprint)?.isVerified == true)
    }

    func test_addContact_sameFingerprintPrimaryUserIdUpdate_returnsUpdatedAndRefreshesDisplayIdentity() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")

        let baseInfo = try engine.parseKeyInfo(keyData: base)
        XCTAssertEqual(baseInfo.userId, "aaaaa")

        _ = try contactService.addContact(publicKeyData: base)
        let result = try contactService.addContact(publicKeyData: update)

        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertEqual(updatedContact.fingerprint, baseInfo.fingerprint)
        XCTAssertEqual(updatedContact.userId, "bbbbb")
        XCTAssertEqual(updatedContact.displayName, "bbbbb")
        XCTAssertEqual(contactService.contacts.count, 1)

        let storedData = try Data(contentsOf: tempDir.appendingPathComponent("\(baseInfo.fingerprint).gpg"))
        XCTAssertEqual(try engine.parseKeyInfo(keyData: storedData).userId, "bbbbb")
    }

    func test_addContact_sameFingerprintPrimaryUserIdCollision_returnsKeyUpdateDetectedWithoutPersistingMerge() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")
        let conflictingKey = try engine.generateKey(
            name: "bbbbb",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let originalInfo = try engine.parseKeyInfo(keyData: base)

        _ = try contactService.addContact(publicKeyData: base)
        _ = try contactService.addContact(publicKeyData: conflictingKey.publicKeyData)

        let result = try contactService.addContact(publicKeyData: update)
        guard case .keyUpdateDetected(let newContact, let existingContact, let keyData) = result else {
            return XCTFail("Expected .keyUpdateDetected, got \(result)")
        }

        XCTAssertEqual(newContact.fingerprint, originalInfo.fingerprint)
        XCTAssertEqual(newContact.userId, "bbbbb")
        XCTAssertEqual(existingContact.fingerprint, conflictingKey.fingerprint)
        XCTAssertEqual(contactService.contacts.count, 2)
        XCTAssertEqual(contactService.contact(forFingerprint: originalInfo.fingerprint)?.userId, "aaaaa")
        XCTAssertEqual(try engine.parseKeyInfo(keyData: keyData).userId, "bbbbb")

        let storedData = try Data(contentsOf: tempDir.appendingPathComponent("\(originalInfo.fingerprint).gpg"))
        XCTAssertEqual(try engine.parseKeyInfo(keyData: storedData).userId, "aaaaa")
    }

    func test_confirmKeyUpdate_sameFingerprintMergeCollisionRemovesConflictingContact() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")
        let conflictingKey = try engine.generateKey(
            name: "bbbbb",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let originalInfo = try engine.parseKeyInfo(keyData: base)

        _ = try contactService.addContact(publicKeyData: base)
        _ = try contactService.addContact(publicKeyData: conflictingKey.publicKeyData)

        let result = try contactService.addContact(publicKeyData: update)
        guard case .keyUpdateDetected(_, let existingContact, let keyData) = result else {
            return XCTFail("Expected .keyUpdateDetected, got \(result)")
        }

        try contactService.confirmKeyUpdate(
            existingFingerprint: existingContact.fingerprint,
            keyData: keyData
        )

        XCTAssertEqual(contactService.contacts.count, 1)
        let survivingContact = try XCTUnwrap(contactService.contact(forFingerprint: originalInfo.fingerprint))
        XCTAssertEqual(survivingContact.userId, "bbbbb")
        XCTAssertTrue(survivingContact.isVerified)
        XCTAssertFalse(contactService.contacts.contains { $0.fingerprint == existingContact.fingerprint })

        let survivingFile = tempDir.appendingPathComponent("\(originalInfo.fingerprint).gpg")
        XCTAssertTrue(FileManager.default.fileExists(atPath: survivingFile.path))
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: Data(contentsOf: survivingFile)).userId,
            "bbbbb"
        )

        let removedFile = tempDir.appendingPathComponent("\(existingContact.fingerprint).gpg")
        XCTAssertFalse(FileManager.default.fileExists(atPath: removedFile.path))
    }

    func test_addContact_sameFingerprintRevocationUpdate_profileA_refreshesRevocationState() throws {
        let base = try loadFixture("merge_revocation_profile_a_base")
        let update = try loadFixture("merge_revocation_profile_a_update")

        _ = try contactService.addContact(publicKeyData: base)
        let result = try contactService.addContact(publicKeyData: update)

        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.isRevoked)
        XCTAssertFalse(updatedContact.canEncryptTo)

        let restarted = ContactService(engine: engine, contactsDirectory: tempDir)
        try restarted.loadContacts()
        XCTAssertTrue(restarted.contacts[0].isRevoked)
    }

    func test_addContact_sameFingerprintRevocationUpdate_profileB_refreshesRevocationState() throws {
        let base = try loadFixture("merge_revocation_profile_b_base")
        let update = try loadFixture("merge_revocation_profile_b_update")

        _ = try contactService.addContact(publicKeyData: base)
        let result = try contactService.addContact(publicKeyData: update)

        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.isRevoked)
        XCTAssertFalse(updatedContact.canEncryptTo)
        XCTAssertEqual(updatedContact.profile, .advanced)
    }

    func test_addContact_sameFingerprintEncryptionSubkeyUpdate_profileA_refreshesEncryptionCapability() throws {
        let base = try loadFixture("merge_add_encryption_subkey_profile_a_base")
        let update = try loadFixture("merge_add_encryption_subkey_profile_a_update")

        let added = try contactService.addContact(publicKeyData: base)
        guard case .added(let baseContact) = added else {
            return XCTFail("Expected .added, got \(added)")
        }
        XCTAssertFalse(baseContact.hasEncryptionSubkey)
        XCTAssertFalse(baseContact.canEncryptTo)

        let result = try contactService.addContact(publicKeyData: update)
        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.hasEncryptionSubkey)
        XCTAssertTrue(updatedContact.canEncryptTo)
    }

    func test_addContact_sameFingerprintEncryptionSubkeyUpdate_profileB_refreshesEncryptionCapability() throws {
        let base = try loadFixture("merge_add_encryption_subkey_profile_b_base")
        let update = try loadFixture("merge_add_encryption_subkey_profile_b_update")

        let added = try contactService.addContact(publicKeyData: base)
        guard case .added(let baseContact) = added else {
            return XCTFail("Expected .added, got \(added)")
        }
        XCTAssertFalse(baseContact.hasEncryptionSubkey)
        XCTAssertFalse(baseContact.canEncryptTo)

        let result = try contactService.addContact(publicKeyData: update)
        guard case .updated(let updatedContact) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedContact.hasEncryptionSubkey)
        XCTAssertTrue(updatedContact.canEncryptTo)
        XCTAssertEqual(updatedContact.profile, .advanced)
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

    // MARK: - Confirm Key Update

    func test_confirmKeyUpdate_replacesOldContact() throws {
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
        XCTAssertEqual(contactService.contacts.count, 1)
        let oldFingerprint = contactService.contacts[0].fingerprint

        // Detect update
        let result = try contactService.addContact(publicKeyData: key2.publicKeyData)
        guard case .keyUpdateDetected(let newContact, _, let keyData) = result else {
            return XCTFail("Expected .keyUpdateDetected")
        }

        // Confirm update
        let confirmedContact = try contactService.confirmKeyUpdate(
            existingFingerprint: oldFingerprint,
            keyData: keyData
        )

        // Verify: old contact replaced, new contact present
        XCTAssertEqual(contactService.contacts.count, 1)
        XCTAssertEqual(contactService.contacts[0].fingerprint, newContact.fingerprint)
        XCTAssertNotEqual(contactService.contacts[0].fingerprint, oldFingerprint)
        XCTAssertEqual(confirmedContact.fingerprint, newContact.fingerprint)

        // Verify: new file exists on disk
        let newFile = tempDir.appendingPathComponent("\(newContact.fingerprint).gpg")
        XCTAssertTrue(FileManager.default.fileExists(atPath: newFile.path),
                      "New key file should exist after confirmKeyUpdate")

        // Verify: old file removed
        let oldFile = tempDir.appendingPathComponent("\(oldFingerprint).gpg")
        XCTAssertFalse(FileManager.default.fileExists(atPath: oldFile.path),
                       "Old key file should be removed after confirmKeyUpdate")
    }

    func test_confirmKeyUpdate_secretKeyDataRejectedWithoutReplacingExistingContact() throws {
        let key1 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )
        let key2 = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )

        _ = try contactService.addContact(publicKeyData: key1.publicKeyData)
        let oldFingerprint = contactService.contacts[0].fingerprint

        let result = try contactService.addContact(publicKeyData: key2.publicKeyData)
        guard case .keyUpdateDetected = result else {
            return XCTFail("Expected .keyUpdateDetected")
        }

        XCTAssertThrowsError(
            try contactService.confirmKeyUpdate(
                existingFingerprint: oldFingerprint,
                keyData: key2.certData
            )
        ) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .contactImportRequiresPublicCertificate = cypherError else {
                return XCTFail("Expected .contactImportRequiresPublicCertificate, got \(cypherError)")
            }
        }

        XCTAssertEqual(contactService.contacts.count, 1)
        XCTAssertEqual(contactService.contacts[0].fingerprint, oldFingerprint)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("\(oldFingerprint).gpg").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.appendingPathComponent("\(key2.fingerprint).gpg").path))
    }

    // MARK: - Binary Key Import

    func test_addContact_binaryPublicKey_profileA_returnsAdded() throws {
        // generateKey returns publicKeyData in binary OpenPGP format (not armored).
        // This confirms the service accepts raw binary Data — the same format
        // the views should pass after the binary import fix.
        let generated = try engine.generateKey(
            name: "BinaryA", email: nil,
            expirySeconds: nil, profile: .universal
        )

        // Verify the data is actually binary (not ASCII armor)
        let firstByte = generated.publicKeyData.first
        XCTAssertNotEqual(firstByte, UInt8(ascii: "-"),
                          "publicKeyData should be binary, not armored")

        let result = try contactService.addContact(publicKeyData: generated.publicKeyData)
        if case .added(let contact) = result {
            XCTAssertFalse(contact.fingerprint.isEmpty)
        } else {
            XCTFail("Expected .added for binary Profile A key, got \(result)")
        }
    }

    func test_addContact_binaryPublicKey_profileB_returnsAdded() throws {
        let generated = try engine.generateKey(
            name: "BinaryB", email: nil,
            expirySeconds: nil, profile: .advanced
        )

        let firstByte = generated.publicKeyData.first
        XCTAssertNotEqual(firstByte, UInt8(ascii: "-"),
                          "publicKeyData should be binary, not armored")

        let result = try contactService.addContact(publicKeyData: generated.publicKeyData)
        if case .added(let contact) = result {
            XCTAssertFalse(contact.fingerprint.isEmpty)
        } else {
            XCTFail("Expected .added for binary Profile B key, got \(result)")
        }
    }

    func test_addContact_armoredPublicKey_profileA_returnsAdded() throws {
        // Verify armored format also works (regression guard)
        let generated = try engine.generateKey(
            name: "ArmoredA", email: nil,
            expirySeconds: nil, profile: .universal
        )

        let armoredData = try engine.armorPublicKey(certData: generated.publicKeyData)
        let firstChar = String(data: armoredData.prefix(5), encoding: .utf8)
        XCTAssertTrue(firstChar?.hasPrefix("-----") == true,
                      "Armored data should start with PGP header")

        let result = try contactService.addContact(publicKeyData: armoredData)
        if case .added(let contact) = result {
            XCTAssertFalse(contact.fingerprint.isEmpty)
        } else {
            XCTFail("Expected .added for armored Profile A key, got \(result)")
        }
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

    // MARK: - M5: Contact Persistence Across Restart

    func test_contactPersistence_survivesServiceRestart() throws {
        let generated = try engine.generateKey(
            name: "Persist Test", email: "persist@example.com",
            expirySeconds: nil, profile: .universal
        )

        // Add contact to first service instance
        let addResult = try contactService.addContact(publicKeyData: generated.publicKeyData)
        guard case .added(let contact) = addResult else {
            XCTFail("Expected .added"); return
        }
        let originalFingerprint = contact.fingerprint

        // Create a NEW service instance pointing to the same temp directory
        let newService = ContactService(engine: engine, contactsDirectory: tempDir)
        try newService.loadContacts()

        XCTAssertEqual(newService.contacts.count, 1, "Contact should survive service restart")
        XCTAssertEqual(newService.contacts.first?.fingerprint, originalFingerprint,
                       "Fingerprint should match after restart")
    }

    func test_addContact_unverified_persistsAcrossRestart() throws {
        let generated = try engine.generateKey(
            name: "Unverified Persist", email: "pending@example.com",
            expirySeconds: nil, profile: .universal
        )

        let addResult = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        guard case .added(let contact) = addResult else {
            XCTFail("Expected .added"); return
        }
        XCTAssertFalse(contact.isVerified)

        let newService = ContactService(engine: engine, contactsDirectory: tempDir)
        try newService.loadContacts()

        XCTAssertEqual(newService.contacts.count, 1)
        XCTAssertEqual(newService.contacts.first?.fingerprint, contact.fingerprint)
        XCTAssertFalse(newService.contacts.first?.isVerified ?? true)
    }

    func test_setVerificationState_promotesContactToVerified_andPersists() throws {
        let generated = try engine.generateKey(
            name: "Manual Verify", email: "manual@example.com",
            expirySeconds: nil, profile: .universal
        )

        let addResult = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        guard case .added(let contact) = addResult else {
            XCTFail("Expected .added"); return
        }

        try contactService.setVerificationState(.verified, for: contact.fingerprint)
        XCTAssertTrue(contactService.contact(forFingerprint: contact.fingerprint)?.isVerified == true)

        let newService = ContactService(engine: engine, contactsDirectory: tempDir)
        try newService.loadContacts()
        XCTAssertTrue(newService.contact(forFingerprint: contact.fingerprint)?.isVerified == true)
    }

    func test_addContact_duplicateVerifiedImport_upgradesExistingUnverifiedContact() throws {
        let generated = try engine.generateKey(
            name: "Duplicate Upgrade", email: "upgrade@example.com",
            expirySeconds: nil, profile: .universal
        )

        _ = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        let duplicateResult = try contactService.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .verified
        )
        guard case .duplicate(let upgradedContact) = duplicateResult else {
            XCTFail("Expected .duplicate"); return
        }

        XCTAssertTrue(upgradedContact.isVerified)
        XCTAssertTrue(contactService.contact(forFingerprint: upgradedContact.fingerprint)?.isVerified == true)
    }
}
