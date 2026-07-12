import XCTest
@testable import CypherAir

final class ContactServiceTests: ContactServiceTestCase {
    // MARK: - Protected Contact Lookup

    func test_contactIdForFingerprint_requiresExistingProtectedContact() throws {
        XCTAssertNil(contactService.contactId(forFingerprint: "stale-fingerprint"))

        let generated = try engine.generateKey(
            name: "Protected Lookup",
            email: "protected-lookup@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )

        _ = try contactService.importContact(publicKeyData: generated.publicKeyData)
        let record = try XCTUnwrap(contactService.availableContactKeyRecord(fingerprint: generated.fingerprint))

        XCTAssertEqual(
            contactService.contactId(forFingerprint: generated.fingerprint),
            record.contactId
        )
        XCTAssertFalse(record.contactId.hasPrefix("legacy-contact-"))
        XCTAssertNil(contactService.contactId(forFingerprint: "missing-\(generated.fingerprint)"))
    }

    // MARK: - Load Contacts

    func test_loadContacts_emptyDirectory_returnsEmpty() async throws {
        try await contactService.openProtectedContactsForTests()
        XCTAssertTrue(contactService.testContactKeyRecords.isEmpty,
                      "Loading from empty directory should produce no contacts")
    }

    // MARK: - Add Contact

    func test_addContact_validPublicKey_returnsAdded() throws {
        let generated = try engine.generateKey(
            name: "Alice", email: "alice@example.com",
            expirySeconds: nil, profile: .universal
        )

        let result = try contactService.importContact(publicKeyData: generated.publicKeyData)

        if case .added(_, let key) = result {
            XCTAssertFalse(key.fingerprint.isEmpty)
        } else {
            XCTFail("Expected .added, got \(result)")
        }

        XCTAssertEqual(contactService.testContactKeyRecords.count, 1)
    }

    func test_requireContactPublicKeyData_returnsPublicCertificateBytesForFingerprintAndKeyID() throws {
        let generated = try engine.generateKey(
            name: "Public Key Lookup",
            email: "lookup@example.com",
            expirySeconds: nil,
            profile: .universal
        )

        let result = try contactService.importContact(publicKeyData: generated.publicKeyData)
        guard case .added(_, let key) = result else {
            return XCTFail("Expected .added, got \(result)")
        }

        XCTAssertEqual(
            try contactService.requireContactPublicKeyData(fingerprint: key.fingerprint),
            generated.publicKeyData
        )
        XCTAssertEqual(
            try contactService.requireContactPublicKeyData(keyId: key.keyId),
            generated.publicKeyData
        )
    }

    func test_requireContactPublicKeyData_missingContactThrowsNotFound() throws {
        XCTAssertThrowsError(
            try contactService.requireContactPublicKeyData(fingerprint: String(repeating: "a", count: 40))
        ) { error in
            guard case .internalError(let reason) = error as? CypherAirError else {
                return XCTFail("Expected internalError, got \(error)")
            }
            XCTAssertEqual(reason, "The selected contact could not be found.")
        }

        XCTAssertThrowsError(
            try contactService.requireContactPublicKeyData(keyId: "legacy-key-missing")
        ) { error in
            guard case .internalError(let reason) = error as? CypherAirError else {
                return XCTFail("Expected internalError, got \(error)")
            }
            XCTAssertEqual(reason, "The selected contact could not be found.")
        }
    }

    func test_addContact_secretCertificateRejectedWithoutPersisting() throws {
        let generated = try engine.generateKey(
            name: "Secret Contact Reject",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        XCTAssertThrowsError(try contactService.importContact(publicKeyData: generated.certData)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .contactImportRequiresPublicCertificate = cypherError else {
                return XCTFail("Expected .contactImportRequiresPublicCertificate, got \(cypherError)")
            }
        }

        XCTAssertTrue(contactService.testContactKeyRecords.isEmpty)
    }

    func test_addContact_armoredSecretCertificateRejectedWithoutPersisting() throws {
        let generated = try engine.generateKey(
            name: "Armored Secret Contact Reject",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
        )
        let armoredSecret = try engine.armor(data: generated.certData, kind: .secretKey)

        XCTAssertThrowsError(try contactService.importContact(publicKeyData: armoredSecret)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .contactImportRequiresPublicCertificate = cypherError else {
                return XCTFail("Expected .contactImportRequiresPublicCertificate, got \(cypherError)")
            }
        }

        XCTAssertTrue(contactService.testContactKeyRecords.isEmpty)
    }

    func test_addContact_duplicateFingerprint_returnsDuplicate() throws {
        let generated = try engine.generateKey(
            name: "Bob", email: "bob@example.com",
            expirySeconds: nil, profile: .universal
        )

        // Add once
        _ = try contactService.importContact(publicKeyData: generated.publicKeyData)

        // Add again — same fingerprint
        let result = try contactService.importContact(publicKeyData: generated.publicKeyData)

        if case .duplicate = result {
            // Expected
        } else {
            XCTFail("Expected .duplicate, got \(result)")
        }

        XCTAssertEqual(contactService.testContactKeyRecords.count, 1,
                       "Duplicate should not increase contact count")
    }

    func test_addContact_sameFingerprintMaterialUpdate_returnsUpdated() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactMaterialUpdate")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let generated = try engine.generateKey(
            name: "Update", email: "update@example.com",
            expirySeconds: nil, profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try opened.service.importContact(publicKeyData: generated.publicKeyData)
        let result = try opened.service.importContact(publicKeyData: refreshed.publicKeyData)

        guard case .updated(_, let updatedKey) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertEqual(opened.service.testContactKeyRecords.count, 1)
        XCTAssertEqual(updatedKey.fingerprint, generated.fingerprint)
        let updatedRecord = try XCTUnwrap(opened.service.availableContactKeyRecord(fingerprint: updatedKey.fingerprint))
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: updatedRecord.publicKeyData).expiryTimestamp,
            refreshed.keyInfo.expiryTimestamp
        )

        try await opened.service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        XCTAssertEqual(reopened.service.testContactKeyRecords.count, 1)
        XCTAssertEqual(
            try engine.parseKeyInfo(keyData: reopened.service.testContactKeyRecords[0].publicKeyData).expiryTimestamp,
            refreshed.keyInfo.expiryTimestamp
        )
    }

    func test_addContact_sameFingerprintMaterialUpdate_preservesUnverifiedState() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactMaterialUpdateUnverified")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let generated = try engine.generateKey(
            name: "Update Unverified", email: "update-unverified@example.com",
            expirySeconds: nil, profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try opened.service.importContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        let result = try opened.service.importContact(
            publicKeyData: refreshed.publicKeyData,
            verificationState: .unverified
        )
        guard case .updated(_, let updatedKey) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertFalse(updatedKey.isVerified)

        try await opened.service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        XCTAssertFalse(reopened.service.testContactKeyRecords[0].manualVerificationState == .verified)
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

        _ = try contactService.importContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        let result = try contactService.importContact(
            publicKeyData: refreshed.publicKeyData,
            verificationState: .verified
        )
        guard case .updated(_, let updatedKey) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedKey.isVerified)
        XCTAssertEqual(
            contactService.availableContactKeyRecord(fingerprint: updatedKey.fingerprint)?.manualVerificationState,
            .verified
        )
    }

    func test_addContact_sameFingerprintPrimaryUserIdUpdate_returnsUpdatedAndRefreshesDisplayIdentity() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")

        let baseInfo = try engine.parseKeyInfo(keyData: base)
        XCTAssertEqual(baseInfo.userId, "aaaaa")

        _ = try contactService.importContact(publicKeyData: base)
        let result = try contactService.importContact(publicKeyData: update)

        guard case .updated(_, let updatedKey) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertEqual(updatedKey.fingerprint, baseInfo.fingerprint)
        XCTAssertEqual(updatedKey.primaryUserId, "bbbbb")
        XCTAssertEqual(updatedKey.displayName, "bbbbb")
        XCTAssertEqual(contactService.testContactKeyRecords.count, 1)

        let updatedRecord = try XCTUnwrap(contactService.availableContactKeyRecord(fingerprint: baseInfo.fingerprint))
        XCTAssertEqual(try engine.parseKeyInfo(keyData: updatedRecord.publicKeyData).userId, "bbbbb")
    }

    func test_importContact_sameFingerprintPrimaryUserIdCollisionUpdatesWithoutReplacementPrompt() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")
        let conflictingKey = try engine.generateKey(
            name: "bbbbb",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let originalInfo = try engine.parseKeyInfo(keyData: base)

        _ = try contactService.importContact(publicKeyData: base)
        _ = try contactService.importContact(publicKeyData: conflictingKey.publicKeyData)

        let result = try contactService.importContact(publicKeyData: update)
        guard case .updated(_, let updatedKey) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertEqual(updatedKey.fingerprint, originalInfo.fingerprint)
        XCTAssertEqual(updatedKey.primaryUserId, "bbbbb")
        XCTAssertEqual(contactService.testContactKeyRecords.count, 2)
        XCTAssertEqual(contactService.availableContactKeyRecord(fingerprint: originalInfo.fingerprint)?.primaryUserId, "bbbbb")
        XCTAssertNotNil(contactService.availableContactKeyRecord(fingerprint: conflictingKey.fingerprint))
    }

    func test_addContact_sameFingerprintRevocationUpdate_profileA_refreshesRevocationState() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactRevocationUpdateProfileA")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let base = try loadFixture("merge_revocation_profile_a_base")
        let update = try loadFixture("merge_revocation_profile_a_update")

        _ = try opened.service.importContact(publicKeyData: base)
        let result = try opened.service.importContact(publicKeyData: update)

        guard case .updated(_, let updatedKey) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedKey.isRevoked)
        XCTAssertFalse(updatedKey.canEncryptTo)

        try await opened.service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        XCTAssertTrue(reopened.service.testContactKeyRecords[0].isRevoked)
    }

    func test_addContact_sameFingerprintRevocationUpdate_profileB_refreshesRevocationState() throws {
        let base = try loadFixture("merge_revocation_profile_b_base")
        let update = try loadFixture("merge_revocation_profile_b_update")

        _ = try contactService.importContact(publicKeyData: base)
        let result = try contactService.importContact(publicKeyData: update)

        guard case .updated(_, let updatedKey) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedKey.isRevoked)
        XCTAssertFalse(updatedKey.canEncryptTo)
        XCTAssertEqual(updatedKey.profile, .advanced)
    }

    func test_addContact_sameFingerprintEncryptionSubkeyUpdate_profileA_refreshesEncryptionCapability() throws {
        let base = try loadFixture("merge_add_encryption_subkey_profile_a_base")
        let update = try loadFixture("merge_add_encryption_subkey_profile_a_update")

        let added = try contactService.importContact(publicKeyData: base)
        guard case .added(_, let baseKey) = added else {
            return XCTFail("Expected .added, got \(added)")
        }
        XCTAssertFalse(baseKey.hasEncryptionSubkey)
        XCTAssertFalse(baseKey.canEncryptTo)

        let result = try contactService.importContact(publicKeyData: update)
        guard case .updated(_, let updatedKey) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedKey.hasEncryptionSubkey)
        XCTAssertTrue(updatedKey.canEncryptTo)
    }

    func test_addContact_sameFingerprintEncryptionSubkeyUpdate_profileB_refreshesEncryptionCapability() throws {
        let base = try loadFixture("merge_add_encryption_subkey_profile_b_base")
        let update = try loadFixture("merge_add_encryption_subkey_profile_b_update")

        let added = try contactService.importContact(publicKeyData: base)
        guard case .added(_, let baseKey) = added else {
            return XCTFail("Expected .added, got \(added)")
        }
        XCTAssertFalse(baseKey.hasEncryptionSubkey)
        XCTAssertFalse(baseKey.canEncryptTo)

        let result = try contactService.importContact(publicKeyData: update)
        guard case .updated(_, let updatedKey) = result else {
            return XCTFail("Expected .updated, got \(result)")
        }

        XCTAssertTrue(updatedKey.hasEncryptionSubkey)
        XCTAssertTrue(updatedKey.canEncryptTo)
        XCTAssertEqual(updatedKey.profile, .advanced)
    }

    func test_importContact_sameUserIdDifferentFingerprint_returnsCandidateContact() throws {
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
        _ = try contactService.importContact(publicKeyData: key1.publicKeyData)

        // Add second key with same userId
        let result = try contactService.importContact(publicKeyData: key2.publicKeyData)

        if case .addedWithCandidate(_, let importedKey, let candidate) = result {
            XCTAssertEqual(importedKey.fingerprint, key2.fingerprint)
            XCTAssertEqual(candidate.strength, .strong)
        } else {
            XCTFail("Expected .addedWithCandidate, got \(result)")
        }

        XCTAssertEqual(contactService.testContactKeyRecords.count, 2)
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

        let result = try contactService.importContact(publicKeyData: generated.publicKeyData)
        if case .added(_, let key) = result {
            XCTAssertFalse(key.fingerprint.isEmpty)
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

        let result = try contactService.importContact(publicKeyData: generated.publicKeyData)
        if case .added(_, let key) = result {
            XCTAssertFalse(key.fingerprint.isEmpty)
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

        let result = try contactService.importContact(publicKeyData: armoredData)
        if case .added(_, let key) = result {
            XCTAssertFalse(key.fingerprint.isEmpty)
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

        _ = try contactService.importContact(publicKeyData: key1.publicKeyData)
        _ = try contactService.importContact(publicKeyData: key2.publicKeyData)
        XCTAssertEqual(contactService.testContactKeyRecords.count, 2)

        let info1 = try engine.parseKeyInfo(keyData: key1.publicKeyData)

        // Lookup by full fingerprint
        let found = contactService.availableContactKeyRecord(fingerprint: info1.fingerprint)
        XCTAssertNotNil(found, "Should find contact by full fingerprint")
        XCTAssertEqual(found?.fingerprint, info1.fingerprint)
    }

    // MARK: - M5: Contact Mutation Persistence Across Reopen

    func test_setVerificationState_promotesContactToVerified_andPersists() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactVerificationPersist")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let generated = try engine.generateKey(
            name: "Manual Verify", email: "manual@example.com",
            expirySeconds: nil, profile: .universal
        )

        let addResult = try opened.service.importContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        guard case .added(_, let key) = addResult else {
            XCTFail("Expected .added"); return
        }

        try opened.service.setVerificationState(.verified, for: key.fingerprint)
        XCTAssertEqual(
            opened.service.availableContactKeyRecord(fingerprint: key.fingerprint)?.manualVerificationState,
            .verified
        )

        try await opened.service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        XCTAssertEqual(
            reopened.service.availableContactKeyRecord(fingerprint: key.fingerprint)?.manualVerificationState,
            .verified
        )
    }

    func test_addContact_duplicateVerifiedImport_upgradesExistingUnverifiedContact() throws {
        let generated = try engine.generateKey(
            name: "Duplicate Upgrade", email: "upgrade@example.com",
            expirySeconds: nil, profile: .universal
        )

        _ = try contactService.importContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )

        let duplicateResult = try contactService.importContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .verified
        )
        guard case .duplicate(_, let upgradedKey) = duplicateResult else {
            XCTFail("Expected .duplicate"); return
        }

        XCTAssertTrue(upgradedKey.isVerified)
        XCTAssertEqual(
            contactService.availableContactKeyRecord(fingerprint: upgradedKey.fingerprint)?.manualVerificationState,
            .verified
        )
    }

    func test_contactsDomainSnapshot_usesProtectedRuntimeIdsForImports() throws {
        let generated = try engine.generateKey(
            name: "Projection", email: "projection@example.com",
            expirySeconds: nil, profile: .universal
        )
        let addResult = try contactService.importContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        guard case .added(_, let key) = addResult else {
            return XCTFail("Expected .added")
        }

        let snapshot = try contactService.currentContactsDomainSnapshot()
        XCTAssertEqual(snapshot.schemaVersion, ContactsDomainSnapshot.currentSchemaVersion)
        XCTAssertEqual(snapshot.identities.map(\.contactId), [key.contactId])
        XCTAssertFalse(key.contactId.hasPrefix("legacy-contact-"))
        XCTAssertEqual(snapshot.keyRecords.map(\.keyId), [key.keyId])
        XCTAssertFalse(key.keyId.hasPrefix("legacy-key-"))
        XCTAssertEqual(snapshot.keyRecords.first?.usageState, .preferred)

        let record = try XCTUnwrap(contactService.availableContactKeyRecord(fingerprint: key.fingerprint))
        XCTAssertEqual(record.publicKeyData, generated.publicKeyData)
        XCTAssertEqual(record.profile, key.profile)
        XCTAssertEqual(record.primaryUserId, key.primaryUserId)
        XCTAssertEqual(record.manualVerificationState, .unverified)
    }
}
