import XCTest
@testable import CypherAir

/// Tests for KeyManagementService — full key lifecycle with mock SE/Keychain/Auth.
final class KeyManagementServiceTests: XCTestCase {

    private var engine: PgpEngine!
    private var service: KeyManagementService!
    private var mockSE: MockSecureEnclave!
    private var mockKC: MockKeychain!
    private var mockAuth: MockAuthenticator!

    override func setUp() {
        super.setUp()
        engine = PgpEngine()
        let result = TestHelpers.makeKeyManagement(engine: engine)
        service = result.service
        mockSE = result.mockSE
        mockKC = result.mockKC
        mockAuth = result.mockAuth
    }

    override func tearDown() {
        // Clean up crash recovery flags that tests may have set
        UserDefaults.standard.removeObject(forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)

        service = nil
        mockSE = nil
        mockKC = nil
        mockAuth = nil
        engine = nil
        super.tearDown()
    }

    // MARK: - Key Generation: Profile A

    func test_generateKey_profileA_storesKeychainItems() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        // Should store 4 Keychain items: SE key, salt, sealed box, metadata
        XCTAssertEqual(mockKC.saveCallCount, 4,
                       "Profile A key gen should store 4 Keychain items")

        // Verify items exist
        let fp = identity.fingerprint
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.seKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.saltService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.sealedKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.metadataService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
    }

    func test_generateKey_profileA_returnsCorrectIdentity() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        XCTAssertEqual(identity.keyVersion, 4, "Profile A should produce v4 key")
        XCTAssertEqual(identity.profile, .universal)
        XCTAssertFalse(identity.fingerprint.isEmpty)
        XCTAssertTrue(identity.hasEncryptionSubkey, "Generated key should have encryption subkey")
        XCTAssertFalse(identity.isRevoked)
        XCTAssertFalse(identity.isExpired)
        XCTAssertFalse(identity.isBackedUp)
        XCTAssertFalse(identity.publicKeyData.isEmpty)
        XCTAssertFalse(identity.revocationCert.isEmpty)
    }

    // MARK: - Key Generation: Profile B

    func test_generateKey_profileB_storesKeychainItems() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)

        XCTAssertEqual(mockKC.saveCallCount, 4)

        let fp = identity.fingerprint
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.seKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
    }

    func test_generateKey_profileB_returnsCorrectIdentity() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)

        XCTAssertEqual(identity.keyVersion, 6, "Profile B should produce v6 key")
        XCTAssertEqual(identity.profile, .advanced)
        XCTAssertTrue(identity.hasEncryptionSubkey)
    }

    // MARK: - Key Generation: Default Key Logic

    func test_generateKey_firstKey_isDefault() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        XCTAssertTrue(identity.isDefault, "First key should be default")
    }

    func test_generateKey_secondKey_isNotDefault() async throws {
        try await TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Second")
        XCTAssertFalse(second.isDefault, "Second key should not be default")
    }

    // MARK: - Key Generation: SE Interaction

    func test_generateKey_seWrapCalled() async throws {
        try await TestHelpers.generateProfileAKey(service: service)

        XCTAssertEqual(mockSE.generateCallCount, 1, "SE should generate one wrapping key")
        XCTAssertEqual(mockSE.wrapCallCount, 1, "SE should wrap once")
    }

    func test_generateKey_profileB_seWrapCalled() async throws {
        try await TestHelpers.generateProfileBKey(service: service)

        XCTAssertEqual(mockSE.generateCallCount, 1)
        XCTAssertEqual(mockSE.wrapCallCount, 1)
    }

    // MARK: - Key Loading

    func test_loadKeys_emptyKeychain_returnsEmpty() async throws {
        try service.loadKeys()
        XCTAssertTrue(service.keys.isEmpty)
    }

    func test_loadKeys_withStoredMetadata_loadsKeys() async throws {
        // Generate a key (stores metadata in mock Keychain)
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        // Create a new service instance pointing at the same Keychain
        let newService = KeyManagementService(
            engine: engine,
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth
        )

        try newService.loadKeys()
        XCTAssertEqual(newService.keys.count, 1)
        XCTAssertEqual(newService.keys.first?.fingerprint, identity.fingerprint)
    }

    func test_loadKeys_corruptMetadata_skipsCorruptEntry() async throws {
        // Store valid metadata
        try await TestHelpers.generateProfileAKey(service: service)

        // Store corrupt metadata under a fake fingerprint
        let corruptData = Data("not-valid-json".utf8)
        try mockKC.save(
            corruptData,
            service: KeychainConstants.metadataService(fingerprint: "deadbeef"),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        // Load should succeed, skipping the corrupt entry
        let newService = KeyManagementService(
            engine: engine,
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth
        )
        try newService.loadKeys()

        // Should load only the valid key, not the corrupt one
        XCTAssertEqual(newService.keys.count, 1)
    }

    // MARK: - Key Export

    func test_exportKey_profileA_returnsArmoredData() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        let exported = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: "test-pass-123")

        XCTAssertFalse(exported.isEmpty, "Exported data should not be empty")
        // Check it starts with PGP armor header
        let armorHeader = String(data: exported.prefix(27), encoding: .utf8)
        XCTAssertTrue(armorHeader?.hasPrefix("-----BEGIN PGP") == true,
                      "Exported data should be ASCII-armored")
    }

    func test_exportKey_marksKeyAsBackedUp() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        XCTAssertFalse(identity.isBackedUp)

        _ = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: "backup-pass")

        XCTAssertTrue(service.keys.first?.isBackedUp == true,
                      "Key should be marked as backed up after export")
    }

    func test_exportKey_nonexistentFingerprint_throwsError() async {
        do {
            _ = try await service.exportKey(fingerprint: "nonexistent", passphrase: "pass")
            XCTFail("Expected error for nonexistent fingerprint")
        } catch {
            // Should fail — no key with this fingerprint exists in Keychain
        }
    }

    func test_exportKey_profileB_returnsArmoredData() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)

        let exported = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: "test-pass-456")
        XCTAssertFalse(exported.isEmpty)
    }

    // MARK: - Key Deletion

    func test_deleteKey_removesKeychainItems() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let fp = identity.fingerprint

        try service.deleteKey(fingerprint: fp)

        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.seKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
    }

    func test_deleteKey_removesFromKeysArray() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        XCTAssertEqual(service.keys.count, 1)

        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertEqual(service.keys.count, 0)
    }

    func test_deleteKey_reassignsDefaultIfNeeded() async throws {
        let first = try await TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Second")

        XCTAssertTrue(first.isDefault)
        XCTAssertFalse(second.isDefault)

        // Delete the default key
        try service.deleteKey(fingerprint: first.fingerprint)

        // The remaining key should become default
        XCTAssertTrue(service.keys.first?.isDefault == true,
                      "Remaining key should become default after default deleted")
    }

    // MARK: - Unwrap Private Key

    func test_unwrapPrivateKey_validFingerprint_returnsData() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        let privateKeyData = try service.unwrapPrivateKey(fingerprint: identity.fingerprint)
        XCTAssertFalse(privateKeyData.isEmpty, "Unwrapped private key should not be empty")

        // Verify SE unwrap was called
        XCTAssertEqual(mockSE.unwrapCallCount, 1)
    }

    func test_unwrapPrivateKey_unknownFingerprint_throwsError() {
        XCTAssertThrowsError(try service.unwrapPrivateKey(fingerprint: "unknown-fp")) { _ in
            // Expected: Keychain load fails for unknown fingerprint
        }
    }

    func test_unwrapPrivateKey_profileB_returnsData() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)

        let privateKeyData = try service.unwrapPrivateKey(fingerprint: identity.fingerprint)
        XCTAssertFalse(privateKeyData.isEmpty)
    }

    // MARK: - Key Import/Restore

    func test_importKey_profileA_exportThenImport_fingerprintMatches() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Export Test A")
        let passphrase = "test-passphrase-123"

        // Export the key
        let exportedData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        XCTAssertFalse(exportedData.isEmpty)

        // Delete the original key
        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        // Import the exported key
        let imported = try await service.importKey(
            armoredData: exportedData,
            passphrase: passphrase,
            authMode: .standard
        )

        // Verify fingerprint and profile match
        XCTAssertEqual(imported.fingerprint, identity.fingerprint,
                       "Imported key fingerprint should match original")
        XCTAssertEqual(imported.profile, .universal,
                       "Imported key should retain Profile A (universal)")
        XCTAssertEqual(imported.keyVersion, 4)
    }

    func test_importKey_profileB_exportThenImport_fingerprintMatches() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service, name: "Export Test B")
        let passphrase = "test-passphrase-456"

        let exportedData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        XCTAssertFalse(exportedData.isEmpty)

        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        let imported = try await service.importKey(
            armoredData: exportedData,
            passphrase: passphrase,
            authMode: .standard
        )

        XCTAssertEqual(imported.fingerprint, identity.fingerprint,
                       "Imported key fingerprint should match original")
        XCTAssertEqual(imported.profile, .advanced,
                       "Imported key should retain Profile B (advanced)")
        XCTAssertEqual(imported.keyVersion, 6)
    }

    // MARK: - Default Key

    func test_setDefaultKey_switchesDefault() async throws {
        let first = try await TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Second")

        XCTAssertTrue(service.keys.first(where: { $0.fingerprint == first.fingerprint })!.isDefault)
        XCTAssertFalse(service.keys.first(where: { $0.fingerprint == second.fingerprint })!.isDefault)

        try service.setDefaultKey(fingerprint: second.fingerprint)

        XCTAssertFalse(service.keys.first(where: { $0.fingerprint == first.fingerprint })!.isDefault)
        XCTAssertTrue(service.keys.first(where: { $0.fingerprint == second.fingerprint })!.isDefault)
    }

    func test_defaultKey_returnsFirstDefault() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        XCTAssertEqual(service.defaultKey?.fingerprint, identity.fingerprint)
    }

    func test_defaultKey_noKeys_returnsNil() {
        XCTAssertNil(service.defaultKey)
    }

    func test_setDefaultKey_persistsAcrossReload() async throws {
        let first = try await TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Second")

        // Switch default from first to second
        try service.setDefaultKey(fingerprint: second.fingerprint)

        // Create a fresh service with the same mock Keychain — simulates cold restart
        let freshService = KeyManagementService(
            engine: engine,
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth
        )
        try freshService.loadKeys()

        // Verify the persisted default survived the "restart"
        let reloadedFirst = freshService.keys.first(where: { $0.fingerprint == first.fingerprint })
        let reloadedSecond = freshService.keys.first(where: { $0.fingerprint == second.fingerprint })
        XCTAssertEqual(reloadedFirst?.isDefault, false,
                       "First key should not be default after reload")
        XCTAssertEqual(reloadedSecond?.isDefault, true,
                       "Second key should remain default after reload")
    }

    // MARK: - Duplicate Key Import Guard

    func test_importKey_duplicateFingerprint_throwsDuplicateKeyError() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Original A")
        let passphrase = "test-pass-dup-a"

        // Export the key (to get armored data for re-import)
        let exportedData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)

        // Attempt to import without deleting — should throw duplicateKey
        do {
            _ = try await service.importKey(armoredData: exportedData, passphrase: passphrase, authMode: .standard)
            XCTFail("Expected CypherAirError.duplicateKey")
        } catch {
            guard let cypherError = error as? CypherAirError,
                  case .duplicateKey = cypherError else {
                return XCTFail("Expected CypherAirError.duplicateKey, got \(error)")
            }
        }

        // Verify no extra SE key was generated (guard fired before SE wrapping)
        // 1 generate for original key + 0 for the rejected import = 1 total
        XCTAssertEqual(mockSE.generateCallCount, 1,
                       "SE key should not be generated for duplicate import")
    }

    func test_importKey_duplicateFingerprint_profileB_throwsDuplicateKeyError() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service, name: "Original B")
        let passphrase = "test-pass-dup-b"

        let exportedData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)

        do {
            _ = try await service.importKey(armoredData: exportedData, passphrase: passphrase, authMode: .standard)
            XCTFail("Expected CypherAirError.duplicateKey")
        } catch {
            guard let cypherError = error as? CypherAirError,
                  case .duplicateKey = cypherError else {
                return XCTFail("Expected CypherAirError.duplicateKey, got \(error)")
            }
        }

        XCTAssertEqual(mockSE.generateCallCount, 1,
                       "SE key should not be generated for duplicate Profile B import")
    }

    // MARK: - Modify Expiry

    func test_modifyExpiry_profileA_updatesExpiryDate() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Expiry A")

        // Modify expiry to 1 year (31536000 seconds)
        let updated = try await service.modifyExpiry(
            fingerprint: identity.fingerprint,
            newExpirySeconds: 31_536_000,
            authMode: .standard
        )

        XCTAssertNotNil(updated.expiryDate, "Updated key should have an expiry date")
        XCTAssertFalse(updated.isExpired, "Key should not be expired immediately after modification")
        XCTAssertEqual(updated.fingerprint, identity.fingerprint,
                       "Fingerprint should not change after expiry modification")
    }

    func test_modifyExpiry_profileB_updatesExpiryDate() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service, name: "Expiry B")

        let updated = try await service.modifyExpiry(
            fingerprint: identity.fingerprint,
            newExpirySeconds: 31_536_000,
            authMode: .standard
        )

        XCTAssertNotNil(updated.expiryDate)
        XCTAssertFalse(updated.isExpired)
        XCTAssertEqual(updated.fingerprint, identity.fingerprint)
    }

    func test_modifyExpiry_setsAndClearsCrashRecoveryFlag() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Flag Test")

        // Verify flags are not set before operation
        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))

        _ = try await service.modifyExpiry(
            fingerprint: identity.fingerprint,
            newExpirySeconds: 31_536_000,
            authMode: .standard
        )

        // After successful completion, flags should be cleared
        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.modifyExpiryInProgressKey),
                       "In-progress flag should be cleared after successful modifyExpiry")
        XCTAssertNil(UserDefaults.standard.string(forKey: AuthPreferences.modifyExpiryFingerprintKey),
                     "Fingerprint flag should be cleared after successful modifyExpiry")
    }

    // MARK: - Modify Expiry Crash Recovery

    func test_modifyExpiryCrashRecovery_oldAndPendingExist_deletesPending() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Recovery Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        // Simulate interrupted modifyExpiry: set flags and store pending items
        // while old permanent items still exist.
        UserDefaults.standard.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.set(fp, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        let dummyData = Data("pending-data".utf8)
        try mockKC.save(dummyData, service: KeychainConstants.pendingSeKeyService(fingerprint: fp),
                        account: account, accessControl: nil)
        try mockKC.save(dummyData, service: KeychainConstants.pendingSaltService(fingerprint: fp),
                        account: account, accessControl: nil)
        try mockKC.save(dummyData, service: KeychainConstants.pendingSealedKeyService(fingerprint: fp),
                        account: account, accessControl: nil)

        // Run recovery
        service.checkAndRecoverFromInterruptedModifyExpiry()

        // Verify: flags cleared
        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.modifyExpiryInProgressKey),
                       "In-progress flag should be cleared after recovery")
        XCTAssertNil(UserDefaults.standard.string(forKey: AuthPreferences.modifyExpiryFingerprintKey),
                     "Fingerprint flag should be cleared after recovery")

        // Verify: pending items deleted
        XCTAssertFalse(mockKC.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fp),
                                     account: account),
                       "Pending SE key should be deleted")
        XCTAssertFalse(mockKC.exists(service: KeychainConstants.pendingSaltService(fingerprint: fp),
                                     account: account),
                       "Pending salt should be deleted")
        XCTAssertFalse(mockKC.exists(service: KeychainConstants.pendingSealedKeyService(fingerprint: fp),
                                     account: account),
                       "Pending sealed key should be deleted")

        // Verify: original permanent items still intact
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.seKeyService(fingerprint: fp),
                                    account: account),
                      "Original SE key should remain intact")
    }

    func test_modifyExpiryCrashRecovery_onlyPendingExists_promotesToPermanent() async throws {
        // Generate a key, export its fingerprint, then manually delete permanent items
        // to simulate a crash after deletion but before promotion.
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Promote Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        // Copy current permanent data to pending names (simulating what modifyExpiry does)
        let seKeyData = try mockKC.load(
            service: KeychainConstants.seKeyService(fingerprint: fp), account: account)
        let saltData = try mockKC.load(
            service: KeychainConstants.saltService(fingerprint: fp), account: account)
        let sealedData = try mockKC.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fp), account: account)

        try mockKC.save(seKeyData, service: KeychainConstants.pendingSeKeyService(fingerprint: fp),
                        account: account, accessControl: nil)
        try mockKC.save(saltData, service: KeychainConstants.pendingSaltService(fingerprint: fp),
                        account: account, accessControl: nil)
        try mockKC.save(sealedData, service: KeychainConstants.pendingSealedKeyService(fingerprint: fp),
                        account: account, accessControl: nil)

        // Delete the permanent items (simulating the crash point)
        try mockKC.delete(service: KeychainConstants.seKeyService(fingerprint: fp), account: account)
        try mockKC.delete(service: KeychainConstants.saltService(fingerprint: fp), account: account)
        try mockKC.delete(service: KeychainConstants.sealedKeyService(fingerprint: fp), account: account)

        // Set crash recovery flags
        UserDefaults.standard.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.set(fp, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        // Run recovery
        service.checkAndRecoverFromInterruptedModifyExpiry()

        // Verify: flags cleared
        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))

        // Verify: permanent items restored from pending
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.seKeyService(fingerprint: fp),
                                    account: account),
                      "SE key should be promoted to permanent")
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.saltService(fingerprint: fp),
                                    account: account),
                      "Salt should be promoted to permanent")
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.sealedKeyService(fingerprint: fp),
                                    account: account),
                      "Sealed key should be promoted to permanent")
    }

    func test_modifyExpiryCrashRecovery_noFlag_doesNothing() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "No Flag Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        // Ensure no crash recovery flag is set
        UserDefaults.standard.set(false, forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)

        let saveCountBefore = mockKC.saveCallCount
        let deleteCountBefore = mockKC.deleteCallCount

        // Run recovery — should be a no-op
        service.checkAndRecoverFromInterruptedModifyExpiry()

        // Verify: no Keychain operations performed
        XCTAssertEqual(mockKC.saveCallCount, saveCountBefore,
                       "No Keychain saves should occur when flag is not set")
        XCTAssertEqual(mockKC.deleteCallCount, deleteCountBefore,
                       "No Keychain deletes should occur when flag is not set")

        // Verify: original key still intact
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.seKeyService(fingerprint: fp),
                                    account: account))
    }

    // MARK: - Delete Key Default Persistence

    func test_deleteKey_reassignsDefault_persistsAcrossReload() async throws {
        let first = try await TestHelpers.generateProfileAKey(service: service, name: "Default")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Other")

        XCTAssertTrue(first.isDefault)
        XCTAssertFalse(second.isDefault)

        // Delete the default key — second should become default
        try service.deleteKey(fingerprint: first.fingerprint)
        XCTAssertTrue(service.keys.first?.isDefault == true)

        // Create a fresh service to simulate cold restart
        let freshService = KeyManagementService(
            engine: engine,
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth
        )
        try freshService.loadKeys()

        // Verify the promoted default persisted through reload
        XCTAssertEqual(freshService.keys.count, 1)
        XCTAssertTrue(freshService.keys.first?.isDefault == true,
                      "Promoted default should persist across reload")
        XCTAssertEqual(freshService.keys.first?.fingerprint, second.fingerprint)
    }

    // MARK: - Binary Format Key Import

    func test_importKey_binaryFormat_profileA_fingerprintMatches() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Binary Import A")
        let passphrase = "binary-test-pass-a"

        // Export produces ASCII armor
        let armoredData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        XCTAssertTrue(String(data: armoredData.prefix(5), encoding: .utf8)?.hasPrefix("-----") == true)

        // Convert to binary OpenPGP format
        let binaryData = try engine.dearmor(armored: armoredData)
        XCTAssertNotEqual(binaryData.first, UInt8(ascii: "-"),
                          "Dearmored data should not start with ASCII armor header")

        // Delete the original
        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        // Import using binary format — this is the same path that views now use
        let imported = try await service.importKey(
            armoredData: binaryData,
            passphrase: passphrase,
            authMode: .standard
        )

        XCTAssertEqual(imported.fingerprint, identity.fingerprint,
                       "Binary import should produce same fingerprint as original")
        XCTAssertEqual(imported.profile, .universal)
        XCTAssertEqual(imported.keyVersion, 4)
    }

    func test_importKey_binaryFormat_profileB_fingerprintMatches() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service, name: "Binary Import B")
        let passphrase = "binary-test-pass-b"

        let armoredData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        let binaryData = try engine.dearmor(armored: armoredData)

        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        let imported = try await service.importKey(
            armoredData: binaryData,
            passphrase: passphrase,
            authMode: .standard
        )

        XCTAssertEqual(imported.fingerprint, identity.fingerprint,
                       "Binary import should produce same fingerprint as original")
        XCTAssertEqual(imported.profile, .advanced)
        XCTAssertEqual(imported.keyVersion, 6)
    }

    // MARK: - Fingerprint Validation (M-1)

    func test_hkdfInfo_validV4Fingerprint_succeeds() async throws {
        let v4 = String(repeating: "a1b2c3d4", count: 5) // 40 hex chars
        let data = try SEConstants.hkdfInfo(fingerprint: v4)
        XCTAssertTrue(data.count > 0)
    }

    func test_hkdfInfo_validV6Fingerprint_succeeds() async throws {
        let v6 = String(repeating: "a1b2c3d4", count: 8) // 64 hex chars
        let data = try SEConstants.hkdfInfo(fingerprint: v6)
        XCTAssertTrue(data.count > 0)
    }

    func test_hkdfInfo_emptyFingerprint_throwsInvalidFingerprint() {
        XCTAssertThrowsError(try SEConstants.hkdfInfo(fingerprint: "")) { error in
            XCTAssertEqual(error as? SecureEnclaveError, .invalidFingerprint)
        }
    }

    func test_hkdfInfo_nonHexFingerprint_throwsInvalidFingerprint() {
        XCTAssertThrowsError(try SEConstants.hkdfInfo(fingerprint: "xyz!@#")) { error in
            XCTAssertEqual(error as? SecureEnclaveError, .invalidFingerprint)
        }
    }

    func test_hkdfInfo_mixedCaseFingerprint_normalizedToLowercase() async throws {
        let upper = "AABBCCDD"
        let lower = "aabbccdd"
        let dataUpper = try SEConstants.hkdfInfo(fingerprint: upper)
        let dataLower = try SEConstants.hkdfInfo(fingerprint: lower)
        XCTAssertEqual(dataUpper, dataLower, "Mixed case should normalize to same info data")
    }

}
