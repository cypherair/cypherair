import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceRevocationSelectionTests: KeyManagementServiceTestCase {

    private static let armoredSignatureHeader = "-----BEGIN PGP SIGNATURE-----"

    private func assertArmoredSignature(_ armored: Data, file: StaticString = #filePath, line: UInt = #line) throws {
        let prefix = String(data: armored.prefix(Self.armoredSignatureHeader.utf8.count), encoding: .utf8)
        XCTAssertEqual(prefix, Self.armoredSignatureHeader,
                       "Selective revocation output must be ASCII-armored as a PGP SIGNATURE",
                       file: file, line: line)

        let binary = try engine.dearmor(armored: armored)
        XCTAssertFalse(binary.isEmpty,
                       "Dearmored selective revocation must be non-empty binary bytes",
                       file: file, line: line)
    }

    private func snapshotCatalogAndKeychain(
        for targetService: KeyManagementService? = nil
    ) -> (keys: [PGPKeyIdentity], saveCount: Int, deleteCount: Int) {
        let targetService = targetService ?? service!
        return (targetService.keys, mockKC.saveCallCount, mockKC.deleteCallCount)
    }

    private func assertNoCatalogOrKeychainMutation(
        for targetService: KeyManagementService? = nil,
        before: (keys: [PGPKeyIdentity], saveCount: Int, deleteCount: Int),
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let targetService = targetService ?? service!
        XCTAssertEqual(targetService.keys.count, before.keys.count, "Catalog key count must not change",
                       file: file, line: line)
        for (beforeKey, afterKey) in zip(before.keys, targetService.keys) {
            XCTAssertEqual(beforeKey.fingerprint, afterKey.fingerprint, file: file, line: line)
            XCTAssertEqual(beforeKey.revocationCert, afterKey.revocationCert,
                           "PGPKeyIdentity.revocationCert must not be mutated by selective revocation",
                           file: file, line: line)
            XCTAssertEqual(beforeKey.isBackedUp, afterKey.isBackedUp, file: file, line: line)
        }
        XCTAssertEqual(mockKC.saveCallCount, before.saveCount,
                       "Selective revocation must not write to Keychain", file: file, line: line)
        XCTAssertEqual(mockKC.deleteCallCount, before.deleteCount,
                       "Selective revocation must not delete Keychain items", file: file, line: line)
    }

    func test_selectionCatalog_existingStoredKey_returnsSelectorsWithoutUnwrapOrMetadataRewrite() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Selector Catalog")
        let unwrapCountBefore = mockSE.unwrapCallCount
        let saveCountBefore = mockKC.saveCallCount

        let catalog = try service.selectionCatalog(fingerprint: identity.fingerprint)

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore, "Selector discovery must not unwrap private key material")
        XCTAssertEqual(mockKC.saveCallCount, saveCountBefore, "Selector discovery must not rewrite metadata")
        XCTAssertEqual(catalog.certificateFingerprint, identity.fingerprint)
        XCTAssertFalse(catalog.subkeys.isEmpty)
        XCTAssertEqual(catalog.userIds.count, 1)
        XCTAssertEqual(catalog.userIds[0].occurrenceIndex, 0)
        XCTAssertEqual(catalog.userIds[0].userIdData, Data((identity.userId ?? "").utf8))
        XCTAssertTrue(catalog.subkeys.contains(where: \.isCurrentlyTransportEncryptionCapable))
    }

    func test_selectionCatalog_missingFingerprint_throwsNoMatchingKey() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: service, name: "Selector Missing")

        XCTAssertThrowsError(
            try service.selectionCatalog(fingerprint: "missing-fingerprint")
        ) { error in
            guard case .noMatchingKey = error as? CypherAirError else {
                return XCTFail("Expected noMatchingKey, got \(error)")
            }
        }
    }

    func test_selectionCatalog_metadataFingerprintMismatch_throwsInvalidKeyDataWithoutUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Selector Mismatch A")
        let otherIdentity = try await TestHelpers.generateProfileBKey(service: service, name: "Selector Mismatch B")

        var corruptedIdentity = try loadStoredIdentity(fingerprint: identity.fingerprint)
        corruptedIdentity.publicKeyData = otherIdentity.publicKeyData
        try overwriteStoredIdentity(corruptedIdentity)

        let freshService = makeFreshService()
        try freshService.loadKeys()

        let unwrapCountBefore = mockSE.unwrapCallCount
        let saveCountBefore = mockKC.saveCallCount

        XCTAssertThrowsError(
            try freshService.selectionCatalog(fingerprint: identity.fingerprint)
        ) { error in
            guard case .invalidKeyData = error as? CypherAirError else {
                return XCTFail("Expected invalidKeyData, got \(error)")
            }
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore, "Fingerprint mismatch must not unwrap private keys")
        XCTAssertEqual(mockKC.saveCallCount, saveCountBefore, "Fingerprint mismatch must not rewrite metadata")
    }

    func test_selectionCatalog_duplicateSameBytesFixture_preservesPerOccurrenceState() throws {
        let fixture = try FixtureLoader.loadData(
            "selector_duplicate_userid_second_revoked_secret",
            ext: "gpg"
        )
        let info = try engine.parseKeyInfo(keyData: fixture)
        let metadata = PGPKeyMetadataAdapter.metadata(from: info)
        let identity = PGPKeyIdentity(
            fingerprint: metadata.fingerprint,
            keyVersion: metadata.keyVersion,
            profile: metadata.profile,
            userId: metadata.userId,
            hasEncryptionSubkey: metadata.hasEncryptionSubkey,
            isRevoked: metadata.isRevoked,
            isExpired: metadata.isExpired,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: fixture,
            revocationCert: Data(),
            primaryAlgo: metadata.primaryAlgo,
            subkeyAlgo: metadata.subkeyAlgo,
            expiryDate: metadata.expiryDate,
            openPGPConfigurationIdentity: metadata.profile.openPGPConfiguration.identity,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
        try storeIdentity(identity)

        let freshService = makeFreshService()
        try freshService.loadKeys()
        let unwrapCountBefore = mockSE.unwrapCallCount
        let saveCountBefore = mockKC.saveCallCount

        let catalog = try freshService.selectionCatalog(fingerprint: info.fingerprint)

        XCTAssertEqual(catalog.userIds.count, 2)
        XCTAssertEqual(catalog.userIds[0].userIdData, catalog.userIds[1].userIdData)
        XCTAssertTrue(catalog.userIds[0].isCurrentlyPrimary)
        XCTAssertFalse(catalog.userIds[1].isCurrentlyPrimary)
        XCTAssertFalse(catalog.userIds[0].isCurrentlyRevoked)
        XCTAssertTrue(catalog.userIds[1].isCurrentlyRevoked)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore, "Duplicate selector discovery must not unwrap private key material")
        XCTAssertEqual(mockKC.saveCallCount, saveCountBefore, "Duplicate selector discovery must not rewrite metadata")
    }

    func test_loadSelectionCatalog_existingStoredKey_matchesSynchronousSelectorsWithoutUnwrapOrMetadataRewrite() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Async Selector Catalog")
        let unwrapCountBefore = mockSE.unwrapCallCount
        let saveCountBefore = mockKC.saveCallCount

        let synchronousCatalog = try service.selectionCatalog(fingerprint: identity.fingerprint)
        let asyncCatalog = try await service.loadSelectionCatalog(fingerprint: identity.fingerprint)

        XCTAssertEqual(asyncCatalog, synchronousCatalog)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore, "Async selector discovery must not unwrap private key material")
        XCTAssertEqual(mockKC.saveCallCount, saveCountBefore, "Async selector discovery must not rewrite metadata")
    }

    func test_loadSelectionCatalog_missingFingerprint_throwsNoMatchingKey() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: service, name: "Async Selector Missing")

        do {
            _ = try await service.loadSelectionCatalog(fingerprint: "missing-fingerprint")
            XCTFail("Expected noMatchingKey")
        } catch CypherAirError.noMatchingKey {
            // Expected.
        } catch {
            XCTFail("Expected noMatchingKey, got \(error)")
        }
    }

    func test_loadSelectionCatalog_metadataFingerprintMismatch_throwsInvalidKeyDataWithoutUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Async Selector Mismatch A")
        let otherIdentity = try await TestHelpers.generateProfileBKey(service: service, name: "Async Selector Mismatch B")

        var corruptedIdentity = try loadStoredIdentity(fingerprint: identity.fingerprint)
        corruptedIdentity.publicKeyData = otherIdentity.publicKeyData
        try overwriteStoredIdentity(corruptedIdentity)

        let freshService = makeFreshService()
        try freshService.loadKeys()

        let unwrapCountBefore = mockSE.unwrapCallCount
        let saveCountBefore = mockKC.saveCallCount

        do {
            _ = try await freshService.loadSelectionCatalog(fingerprint: identity.fingerprint)
            XCTFail("Expected invalidKeyData")
        } catch CypherAirError.invalidKeyData {
            // Expected.
        } catch {
            XCTFail("Expected invalidKeyData, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore, "Async fingerprint mismatch must not unwrap private keys")
        XCTAssertEqual(mockKC.saveCallCount, saveCountBefore, "Async fingerprint mismatch must not rewrite metadata")
    }

    func test_exportRevocationCertificate_existingGeneratedKey_doesNotUnwrapAndReturnsArmoredSignature() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Generated Revocation Export")
        let unwrapCountBefore = mockSE.unwrapCallCount

        let armored = try await service.exportRevocationCertificate(fingerprint: identity.fingerprint)

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore, "Existing revocation should export without SE unwrap")
        XCTAssertTrue(String(data: armored.prefix(27), encoding: .utf8)?.contains("BEGIN PGP SIGNATURE") == true)

        let binary = try engine.dearmor(armored: armored)
        XCTAssertEqual(binary, identity.revocationCert)
    }

    func test_exportRevocationCertificate_existingImportedKey_doesNotUnwrapOrRewriteMetadata() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service, name: "Imported Revocation Source")
        let passphrase = "imported-revocation-pass"
        let exportedBackup = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        try service.deleteKey(fingerprint: identity.fingerprint)

        let imported = try await service.importKey(
            armoredData: exportedBackup,
            passphrase: passphrase
        )

        let metadataSavesBefore = mockKC.saveCallCount
        let unwrapCountBefore = mockSE.unwrapCallCount

        let armored = try await service.exportRevocationCertificate(fingerprint: imported.fingerprint)

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore, "Stored imported revocation should not trigger unwrap")
        XCTAssertEqual(mockKC.saveCallCount, metadataSavesBefore, "Stored imported revocation should not rewrite metadata")

        let binary = try engine.dearmor(armored: armored)
        XCTAssertEqual(binary, imported.revocationCert)
    }

    func test_exportRevocationCertificate_missingArtifact_failsClosedWithoutUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Missing Revocation Artifact")
        var stored = try loadStoredIdentity(fingerprint: identity.fingerprint)
        stored.revocationCert = Data()
        try overwriteStoredIdentity(stored)

        let strictService = makeFreshService()
        try strictService.loadKeys()
        XCTAssertTrue(try XCTUnwrap(strictService.keys.first).revocationCert.isEmpty)

        let unwrapCountBefore = mockSE.unwrapCallCount
        let updateCountBefore = metadataPersistence.updateCallCount

        do {
            _ = try await strictService.exportRevocationCertificate(fingerprint: identity.fingerprint)
            XCTFail("Expected missing revocation artifact to fail closed")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .revocationArtifactUnavailable)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore, "Missing artifact must not trigger private-key unwrap")
        XCTAssertEqual(metadataPersistence.updateCallCount, updateCountBefore, "Missing artifact must not rewrite metadata")
        XCTAssertTrue(try loadStoredIdentity(fingerprint: identity.fingerprint).revocationCert.isEmpty)
    }

    func test_generateKey_profileA_revocationCertIsValidOpenPGP() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        XCTAssertFalse(identity.revocationCert.isEmpty, "Revocation cert should not be empty")
        XCTAssertFalse(identity.publicKeyData.isEmpty, "Public key data should not be empty")

        // engine.parseRevocationCert performs:
        // 1. Parse as OpenPGP signature packet
        // 2. Verify signature type is KeyRevocation
        // 3. Cryptographically verify signature against the key
        let result = try engine.parseRevocationCert(
            revData: identity.revocationCert,
            certData: identity.publicKeyData
        )
        XCTAssertTrue(result.lowercased().contains(identity.fingerprint.lowercased()),
                      "Validation result should contain the key's fingerprint")
    }

    func test_generateKey_profileB_revocationCertIsValidOpenPGP() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)

        XCTAssertFalse(identity.revocationCert.isEmpty)
        XCTAssertFalse(identity.publicKeyData.isEmpty)

        let result = try engine.parseRevocationCert(
            revData: identity.revocationCert,
            certData: identity.publicKeyData
        )
        XCTAssertTrue(result.lowercased().contains(identity.fingerprint.lowercased()),
                      "Validation result should contain the key's fingerprint")
    }

    func test_exportSubkeyRevocationCertificate_profileA_returnsArmoredSignatureAndUnwrapsOnce() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Subkey Rev A")
        let catalog = try service.selectionCatalog(fingerprint: identity.fingerprint)
        let subkey = try XCTUnwrap(catalog.subkeys.first,
                                   "Profile A key should expose at least one subkey selector")

        let unwrapBefore = mockSE.unwrapCallCount
        let snapshot = snapshotCatalogAndKeychain()

        let armored = try await service.exportSubkeyRevocationCertificate(
            fingerprint: identity.fingerprint,
            subkeySelection: subkey
        )

        try assertArmoredSignature(armored)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore + 1,
                       "Subkey revocation export must unwrap exactly once on the happy path")
        assertNoCatalogOrKeychainMutation(before: snapshot)
    }

    func test_exportSubkeyRevocationCertificate_profileB_returnsArmoredSignatureAndUnwrapsOnce() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service, name: "Subkey Rev B")
        let catalog = try service.selectionCatalog(fingerprint: identity.fingerprint)
        let subkey = try XCTUnwrap(catalog.subkeys.first,
                                   "Profile B key should expose at least one subkey selector")

        let unwrapBefore = mockSE.unwrapCallCount
        let snapshot = snapshotCatalogAndKeychain()

        let armored = try await service.exportSubkeyRevocationCertificate(
            fingerprint: identity.fingerprint,
            subkeySelection: subkey
        )

        try assertArmoredSignature(armored)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore + 1)
        assertNoCatalogOrKeychainMutation(before: snapshot)
    }

    func test_exportSubkeyRevocationCertificate_unknownFingerprint_throwsNoMatchingKeyBeforeUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Subkey Rev Missing")
        let catalog = try service.selectionCatalog(fingerprint: identity.fingerprint)
        let subkey = try XCTUnwrap(catalog.subkeys.first)

        let unwrapBefore = mockSE.unwrapCallCount

        do {
            _ = try await service.exportSubkeyRevocationCertificate(
                fingerprint: "0000000000000000000000000000000000000000",
                subkeySelection: subkey
            )
            XCTFail("Expected noMatchingKey")
        } catch CypherAirError.noMatchingKey {
            // Expected.
        } catch {
            XCTFail("Expected noMatchingKey, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore,
                       "Unknown fingerprint must never reach SE unwrap")
    }

    func test_exportSubkeyRevocationCertificate_selectorMissInCert_throwsInvalidKeyDataBeforeUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Subkey Rev Bogus")

        let bogusSelection = SubkeySelectionOption(
            fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            algorithmDisplay: "x25519",
            isCurrentlyTransportEncryptionCapable: true,
            isCurrentlyRevoked: false,
            isCurrentlyExpired: false
        )

        let unwrapBefore = mockSE.unwrapCallCount

        do {
            _ = try await service.exportSubkeyRevocationCertificate(
                fingerprint: identity.fingerprint,
                subkeySelection: bogusSelection
            )
            XCTFail("Expected invalidKeyData")
        } catch CypherAirError.invalidKeyData {
            // Expected.
        } catch {
            XCTFail("Expected invalidKeyData, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore,
                       "Selector-miss must fail before any SE unwrap")
    }

    func test_exportSubkeyRevocationCertificate_metadataFingerprintMismatch_throwsInvalidKeyDataBeforeUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Subkey Rev Metadata A")
        let otherIdentity = try await TestHelpers.generateProfileBKey(service: service, name: "Subkey Rev Metadata B")
        let otherCatalog = try service.selectionCatalog(fingerprint: otherIdentity.fingerprint)
        let otherSubkey = try XCTUnwrap(otherCatalog.subkeys.first)

        var corruptedIdentity = try loadStoredIdentity(fingerprint: identity.fingerprint)
        corruptedIdentity.publicKeyData = otherIdentity.publicKeyData
        try overwriteStoredIdentity(corruptedIdentity)

        let freshService = makeFreshService()
        try freshService.loadKeys()

        let unwrapBefore = mockSE.unwrapCallCount
        let snapshot = snapshotCatalogAndKeychain(for: freshService)

        do {
            _ = try await freshService.exportSubkeyRevocationCertificate(
                fingerprint: identity.fingerprint,
                subkeySelection: otherSubkey
            )
            XCTFail("Expected invalidKeyData")
        } catch CypherAirError.invalidKeyData {
            // Expected.
        } catch {
            XCTFail("Expected invalidKeyData, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore,
                       "Metadata fingerprint mismatch must fail before any SE unwrap")
        assertNoCatalogOrKeychainMutation(for: freshService, before: snapshot)
    }

    func test_exportUserIdRevocationCertificate_profileA_returnsArmoredSignatureAndUnwrapsOnce() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "UserId Rev A")
        let catalog = try service.selectionCatalog(fingerprint: identity.fingerprint)
        let userIdOption = try XCTUnwrap(catalog.userIds.first,
                                         "Profile A key should expose its User ID selector")

        let unwrapBefore = mockSE.unwrapCallCount
        let snapshot = snapshotCatalogAndKeychain()

        let armored = try await service.exportUserIdRevocationCertificate(
            fingerprint: identity.fingerprint,
            userIdSelection: userIdOption
        )

        try assertArmoredSignature(armored)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore + 1)
        assertNoCatalogOrKeychainMutation(before: snapshot)
    }

    func test_exportUserIdRevocationCertificate_profileB_returnsArmoredSignatureAndUnwrapsOnce() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service, name: "UserId Rev B")
        let catalog = try service.selectionCatalog(fingerprint: identity.fingerprint)
        let userIdOption = try XCTUnwrap(catalog.userIds.first)

        let unwrapBefore = mockSE.unwrapCallCount
        let snapshot = snapshotCatalogAndKeychain()

        let armored = try await service.exportUserIdRevocationCertificate(
            fingerprint: identity.fingerprint,
            userIdSelection: userIdOption
        )

        try assertArmoredSignature(armored)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore + 1)
        assertNoCatalogOrKeychainMutation(before: snapshot)
    }

    func test_exportUserIdRevocationCertificate_outOfRangeOccurrenceIndex_throwsInvalidKeyDataBeforeUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "UserId Rev OOB")
        let catalog = try service.selectionCatalog(fingerprint: identity.fingerprint)
        let baseOption = try XCTUnwrap(catalog.userIds.first)

        let outOfRange = UserIdSelectionOption(
            occurrenceIndex: baseOption.occurrenceIndex + 1,
            userIdData: baseOption.userIdData,
            displayText: baseOption.displayText,
            isCurrentlyPrimary: baseOption.isCurrentlyPrimary,
            isCurrentlyRevoked: baseOption.isCurrentlyRevoked
        )

        let unwrapBefore = mockSE.unwrapCallCount

        do {
            _ = try await service.exportUserIdRevocationCertificate(
                fingerprint: identity.fingerprint,
                userIdSelection: outOfRange
            )
            XCTFail("Expected invalidKeyData")
        } catch CypherAirError.invalidKeyData {
            // Expected.
        } catch {
            XCTFail("Expected invalidKeyData, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore,
                       "Out-of-range occurrence index must fail before any SE unwrap")
    }

    func test_exportUserIdRevocationCertificate_userIdDataBytesMismatch_throwsInvalidKeyDataBeforeUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "UserId Rev Bytes")
        let catalog = try service.selectionCatalog(fingerprint: identity.fingerprint)
        let baseOption = try XCTUnwrap(catalog.userIds.first)

        let tamperedBytes = Data("Mallory <mallory@example.com>".utf8)
        XCTAssertNotEqual(tamperedBytes, baseOption.userIdData,
                          "Tampered bytes must differ from the genuine selector bytes")

        let mismatched = UserIdSelectionOption(
            occurrenceIndex: baseOption.occurrenceIndex,
            userIdData: tamperedBytes,
            displayText: baseOption.displayText,
            isCurrentlyPrimary: baseOption.isCurrentlyPrimary,
            isCurrentlyRevoked: baseOption.isCurrentlyRevoked
        )

        let unwrapBefore = mockSE.unwrapCallCount

        do {
            _ = try await service.exportUserIdRevocationCertificate(
                fingerprint: identity.fingerprint,
                userIdSelection: mismatched
            )
            XCTFail("Expected invalidKeyData")
        } catch CypherAirError.invalidKeyData {
            // Expected.
        } catch {
            XCTFail("Expected invalidKeyData, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore,
                       "User ID bytes mismatch must fail before any SE unwrap")
    }

    func test_exportUserIdRevocationCertificate_selectorBuiltFromDifferentCertificate_throwsInvalidKeyDataBeforeUnwrap() async throws {
        let victimIdentity = try await TestHelpers.generateProfileAKey(service: service, name: "Victim Cert")
        let foreignIdentity = try await TestHelpers.generateProfileAKey(
            service: service,
            name: "Foreign Cert",
            email: "foreign@example.com"
        )

        let foreignCatalog = try service.selectionCatalog(fingerprint: foreignIdentity.fingerprint)
        let foreignOption = try XCTUnwrap(foreignCatalog.userIds.first)

        let victimCatalog = try service.selectionCatalog(fingerprint: victimIdentity.fingerprint)
        let victimOption = try XCTUnwrap(victimCatalog.userIds.first)
        XCTAssertNotEqual(foreignOption.userIdData, victimOption.userIdData)

        let unwrapBefore = mockSE.unwrapCallCount

        do {
            _ = try await service.exportUserIdRevocationCertificate(
                fingerprint: victimIdentity.fingerprint,
                userIdSelection: foreignOption
            )
            XCTFail("Expected invalidKeyData")
        } catch CypherAirError.invalidKeyData {
            // Expected.
        } catch {
            XCTFail("Expected invalidKeyData, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore,
                       "Cross-certificate selector must fail before any SE unwrap")
    }

    func test_exportUserIdRevocationCertificate_metadataFingerprintMismatch_throwsInvalidKeyDataBeforeUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "UserId Rev Metadata A")
        let otherIdentity = try await TestHelpers.generateProfileBKey(
            service: service,
            name: "UserId Rev Metadata B",
            email: "metadata-b@example.com"
        )
        let otherCatalog = try service.selectionCatalog(fingerprint: otherIdentity.fingerprint)
        let otherUserId = try XCTUnwrap(otherCatalog.userIds.first)

        var corruptedIdentity = try loadStoredIdentity(fingerprint: identity.fingerprint)
        corruptedIdentity.publicKeyData = otherIdentity.publicKeyData
        try overwriteStoredIdentity(corruptedIdentity)

        let freshService = makeFreshService()
        try freshService.loadKeys()

        let unwrapBefore = mockSE.unwrapCallCount
        let snapshot = snapshotCatalogAndKeychain(for: freshService)

        do {
            _ = try await freshService.exportUserIdRevocationCertificate(
                fingerprint: identity.fingerprint,
                userIdSelection: otherUserId
            )
            XCTFail("Expected invalidKeyData")
        } catch CypherAirError.invalidKeyData {
            // Expected.
        } catch {
            XCTFail("Expected invalidKeyData, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore,
                       "Metadata fingerprint mismatch must fail before any SE unwrap")
        assertNoCatalogOrKeychainMutation(for: freshService, before: snapshot)
    }

    /// Exercises the service's end-to-end dispatch for the duplicate-occurrence path.
    ///
    /// This uses a fixture-backed identity path instead of the normal import flow so the
    /// stored metadata preserves the duplicate-occurrence structure exactly as encoded in the
    /// source fixture. The duplicate-occurrence cryptographic semantics themselves remain
    /// covered at the Rust/FFI layer by selector-based User ID revocation tests in
    /// `FFIIntegrationTests` and `pgp-mobile/tests/revocation_construction_tests.rs`.
    func test_exportUserIdRevocationCertificate_duplicateOccurrence_secondIndexRoutesThroughService() async throws {
        let fixture = try FixtureLoader.loadData(
            "selector_duplicate_userid_second_revoked_secret",
            ext: "gpg"
        )
        let identity = try provisionFixtureBackedIdentity(secretCertData: fixture)
        let freshService = makeFreshService()
        try freshService.loadKeys()

        let catalog = try freshService.selectionCatalog(fingerprint: identity.fingerprint)
        XCTAssertEqual(catalog.userIds.count, 2, "Fixture is expected to expose two User ID occurrences")
        let secondOccurrence = catalog.userIds[1]
        XCTAssertEqual(secondOccurrence.occurrenceIndex, 1)

        let unwrapBefore = mockSE.unwrapCallCount
        let snapshot = snapshotCatalogAndKeychain(for: freshService)

        let armored = try await freshService.exportUserIdRevocationCertificate(
            fingerprint: identity.fingerprint,
            userIdSelection: secondOccurrence
        )

        try assertArmoredSignature(armored)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapBefore + 1)
        assertNoCatalogOrKeychainMutation(for: freshService, before: snapshot)
    }

}
