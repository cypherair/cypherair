import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    // MARK: - C5.2B Certificate Merge / Update

    func test_certificateMergeUpdate_profileA_expiryRefreshReturnsUpdated() throws {
        let generated = try engine.generateKey(
            name: "Merge A",
            email: "merge-a@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        let result = try engine.mergePublicCertificateUpdate(
            existingCert: generated.publicKeyData,
            incomingCertOrUpdate: refreshed.publicKeyData
        )

        XCTAssertEqual(result.outcome, .updated)
        let info = try engine.parseKeyInfo(keyData: result.mergedCertData)
        XCTAssertEqual(info.fingerprint, generated.fingerprint)
        XCTAssertEqual(info.expiryTimestamp, refreshed.keyInfo.expiryTimestamp)
    }

    func test_certificateMergeUpdate_profileB_expiryRefreshReturnsUpdated() throws {
        let generated = try engine.generateKey(
            name: "Merge B",
            email: "merge-b@example.com",
            expirySeconds: nil,
            profile: .advanced
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        let result = try engine.mergePublicCertificateUpdate(
            existingCert: generated.publicKeyData,
            incomingCertOrUpdate: refreshed.publicKeyData
        )

        XCTAssertEqual(result.outcome, .updated)
        let info = try engine.parseKeyInfo(keyData: result.mergedCertData)
        XCTAssertEqual(info.fingerprint, generated.fingerprint)
        XCTAssertEqual(info.profile, .advanced)
        XCTAssertEqual(info.expiryTimestamp, refreshed.keyInfo.expiryTimestamp)
    }

    func test_certificateMergeUpdate_duplicateReturnsNoOp() throws {
        let generated = try engine.generateKey(
            name: "Merge Duplicate",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let result = try engine.mergePublicCertificateUpdate(
            existingCert: generated.publicKeyData,
            incomingCertOrUpdate: generated.publicKeyData
        )

        XCTAssertEqual(result.outcome, .noOp)
        let info = try engine.parseKeyInfo(keyData: result.mergedCertData)
        XCTAssertEqual(info.fingerprint, generated.fingerprint)
    }

    func test_certificateMergeUpdate_primaryUserIdSwitchUsesPrimaryIdentity() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")

        let baseInfo = try engine.parseKeyInfo(keyData: base)
        XCTAssertEqual(baseInfo.userId, "aaaaa")

        let result = try engine.mergePublicCertificateUpdate(
            existingCert: base,
            incomingCertOrUpdate: update
        )

        XCTAssertEqual(result.outcome, .updated)
        let mergedInfo = try engine.parseKeyInfo(keyData: result.mergedCertData)
        XCTAssertEqual(mergedInfo.userId, "bbbbb")
    }

    func test_certificateMergeUpdate_profileA_revocationFixtureReturnsUpdated() throws {
        let base = try loadFixture("merge_revocation_profile_a_base")
        let update = try loadFixture("merge_revocation_profile_a_update")

        let result = try engine.mergePublicCertificateUpdate(
            existingCert: base,
            incomingCertOrUpdate: update
        )

        XCTAssertEqual(result.outcome, .updated)
        let info = try engine.parseKeyInfo(keyData: result.mergedCertData)
        XCTAssertTrue(info.isRevoked)
        XCTAssertEqual(info.profile, .universal)
    }

    func test_certificateMergeUpdate_profileB_revocationFixtureReturnsUpdated() throws {
        let base = try loadFixture("merge_revocation_profile_b_base")
        let update = try loadFixture("merge_revocation_profile_b_update")

        let result = try engine.mergePublicCertificateUpdate(
            existingCert: base,
            incomingCertOrUpdate: update
        )

        XCTAssertEqual(result.outcome, .updated)
        let info = try engine.parseKeyInfo(keyData: result.mergedCertData)
        XCTAssertTrue(info.isRevoked)
        XCTAssertEqual(info.profile, .advanced)
    }

    func test_certificateMergeUpdate_profileA_encryptionSubkeyFixtureReturnsUpdated() throws {
        let base = try loadFixture("merge_add_encryption_subkey_profile_a_base")
        let update = try loadFixture("merge_add_encryption_subkey_profile_a_update")

        XCTAssertFalse(try engine.parseKeyInfo(keyData: base).hasEncryptionSubkey)

        let result = try engine.mergePublicCertificateUpdate(
            existingCert: base,
            incomingCertOrUpdate: update
        )

        XCTAssertEqual(result.outcome, .updated)
        let info = try engine.parseKeyInfo(keyData: result.mergedCertData)
        XCTAssertTrue(info.hasEncryptionSubkey)
        XCTAssertEqual(info.profile, .universal)
    }

    func test_certificateMergeUpdate_profileB_encryptionSubkeyFixtureReturnsUpdated() throws {
        let base = try loadFixture("merge_add_encryption_subkey_profile_b_base")
        let update = try loadFixture("merge_add_encryption_subkey_profile_b_update")

        XCTAssertFalse(try engine.parseKeyInfo(keyData: base).hasEncryptionSubkey)

        let result = try engine.mergePublicCertificateUpdate(
            existingCert: base,
            incomingCertOrUpdate: update
        )

        XCTAssertEqual(result.outcome, .updated)
        let info = try engine.parseKeyInfo(keyData: result.mergedCertData)
        XCTAssertTrue(info.hasEncryptionSubkey)
        XCTAssertEqual(info.profile, .advanced)
    }

    func test_validatePublicCertificate_returnsNormalizedPublicCertAndMetadata() throws {
        let generated = try engine.generateKey(
            name: "Validate Public",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let result = try engine.validatePublicCertificate(certData: generated.publicKeyData)

        XCTAssertEqual(result.publicCertData, generated.publicKeyData)
        XCTAssertEqual(result.keyInfo.fingerprint, generated.fingerprint)
        XCTAssertEqual(result.profile, .universal)
    }

    // MARK: - C5.2C Selector Discovery

    func test_discoverCertificateSelectors_gpgPublicAndSecretFixtures_matchAcrossFFI() throws {
        let publicCert = try loadArmoredFixtureAsBinary("gpg_pubkey")
        let secretCert = try loadArmoredFixtureAsBinary("gpg_secretkey")

        let fromPublic = try engine.discoverCertificateSelectors(certData: publicCert)
        let fromSecret = try engine.discoverCertificateSelectors(certData: secretCert)

        XCTAssertEqual(fromPublic, fromSecret)
        XCTAssertFalse(fromPublic.subkeys.isEmpty)
        XCTAssertFalse(fromPublic.userIds.isEmpty)
    }

    func test_discoverCertificateSelectors_generatedProfiles_driveSelectiveRevocationAcrossFFI() throws {
        for profile in [KeyProfile.universal, .advanced] {
            let generated = try engine.generateKey(
                name: "Selector \(profile)",
                email: "selector-\(profile)-ffi@example.com",
                expirySeconds: nil,
                profile: profile
            )

            let discovered = try engine.discoverCertificateSelectors(certData: generated.publicKeyData)

            XCTAssertEqual(discovered.certificateFingerprint, generated.fingerprint)
            XCTAssertFalse(discovered.subkeys.isEmpty)
            XCTAssertEqual(discovered.userIds.count, 1)
            XCTAssertEqual(
                discovered.subkeys[0].fingerprint,
                discovered.subkeys[0].fingerprint.lowercased(),
                "FFI-discovered subkey selector must be lowercase hex"
            )
            XCTAssertTrue(
                discovered.subkeys.contains(where: \.isCurrentlyTransportEncryptionCapable),
                "Generated key should expose at least one currently transport-capable discovered subkey"
            )

            let subkeyRevocation = try engine.generateSubkeyRevocation(
                secretCert: generated.certData,
                subkeyFingerprint: discovered.subkeys[0].fingerprint
            )
            let userIdRevocation = try engine.generateUserIdRevocationBySelector(
                secretCert: generated.certData,
                userIdSelector: selectorInput(
                    userIdData: discovered.userIds[0].userIdData,
                    occurrenceIndex: discovered.userIds[0].occurrenceIndex
                )
            )

            XCTAssertFalse(subkeyRevocation.isEmpty)
            XCTAssertFalse(userIdRevocation.isEmpty)
        }
    }

    func test_discoverCertificateSelectors_primaryUserIdMergeFixture_preservesListOrderAndOccurrenceIndexAcrossFFI() throws {
        let base = try loadFixture("merge_primary_uid_base")
        let update = try loadFixture("merge_primary_uid_update")
        let merged = try engine.mergePublicCertificateUpdate(
            existingCert: base,
            incomingCertOrUpdate: update
        )

        let discovered = try engine.discoverCertificateSelectors(certData: merged.mergedCertData)

        XCTAssertEqual(discovered.userIds.count, 2)
        XCTAssertEqual(discovered.userIds[0].occurrenceIndex, 0)
        XCTAssertEqual(discovered.userIds[1].occurrenceIndex, 1)
        XCTAssertEqual(discovered.userIds.map(\.displayText), ["aaaaa", "bbbbb"])
        XCTAssertEqual(
            discovered.userIds.map(\.userIdData),
            [Data("aaaaa".utf8), Data("bbbbb".utf8)]
        )
    }

    func test_discoverCertificateSelectors_binaryOnlyArmoredInput_throwsInvalidKeyDataAcrossFFI() throws {
        let armoredPublicCert = try loadArmoredFixture("gpg_pubkey")

        XCTAssertThrowsError(
            try engine.discoverCertificateSelectors(certData: armoredPublicCert)
        ) { error in
            guard case .InvalidKeyData = error as? PgpError else {
                return XCTFail("Expected InvalidKeyData, got \(error)")
            }
        }
    }

    func test_discoverCertificateSelectors_duplicateSameBytesFixture_preservesPerOccurrenceStateAcrossFFI()
        throws
    {
        let secretCert = try loadFixture("selector_duplicate_userid_second_revoked_secret")

        let discovered = try engine.discoverCertificateSelectors(certData: secretCert)

        XCTAssertEqual(discovered.userIds.count, 2)
        XCTAssertEqual(discovered.userIds[0].occurrenceIndex, 0)
        XCTAssertEqual(discovered.userIds[1].occurrenceIndex, 1)
        XCTAssertEqual(discovered.userIds[0].userIdData, discovered.userIds[1].userIdData)
        XCTAssertTrue(discovered.userIds[0].isCurrentlyPrimary)
        XCTAssertFalse(discovered.userIds[1].isCurrentlyPrimary)
        XCTAssertFalse(discovered.userIds[0].isCurrentlyRevoked)
        XCTAssertTrue(discovered.userIds[1].isCurrentlyRevoked)
    }

    func test_validatePublicCertificate_secretBearingInput_throwsInvalidKeyDataWithStableToken() throws {
        let generated = try engine.generateKey(
            name: "Validate Secret",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
        )

        XCTAssertThrowsError(
            try engine.validatePublicCertificate(certData: generated.certData)
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .InvalidKeyData(let reason):
                XCTAssertEqual(reason, PGPContactImportAdapter.publicOnlyReasonToken)
            default:
                XCTFail("Expected InvalidKeyData, got \(pgpError)")
            }
        }
    }
}
