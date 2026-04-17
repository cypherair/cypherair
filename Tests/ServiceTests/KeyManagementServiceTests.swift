import Foundation
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
        UserDefaults.standard.removeObject(forKey: AuthPreferences.rewrapInProgressKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.rewrapTargetModeKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.authModeKey)

        service = nil
        mockSE = nil
        mockKC = nil
        mockAuth = nil
        engine = nil
        super.tearDown()
    }

    private func copyPermanentBundleToPending(fingerprint: String) throws {
        let account = KeychainConstants.defaultAccount
        let seKeyData = try mockKC.load(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account
        )
        let saltData = try mockKC.load(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account
        )
        let sealedData = try mockKC.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account
        )

        try mockKC.save(
            seKeyData,
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try mockKC.save(
            saltData,
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try mockKC.save(
            sealedData,
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
    }

    private func makeFreshService() -> KeyManagementService {
        KeyManagementService(
            engine: engine,
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth
        )
    }

    private func loadStoredIdentity(fingerprint: String) throws -> PGPKeyIdentity {
        let metadata = try mockKC.load(
            service: KeychainConstants.metadataService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
        return try JSONDecoder().decode(PGPKeyIdentity.self, from: metadata)
    }

    private func overwriteStoredIdentity(_ identity: PGPKeyIdentity) throws {
        let serviceName = KeychainConstants.metadataService(fingerprint: identity.fingerprint)
        try mockKC.delete(
            service: serviceName,
            account: KeychainConstants.defaultAccount
        )
        let data = try JSONEncoder().encode(identity)
        try mockKC.save(
            data,
            service: serviceName,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
    }

    private func storeIdentity(_ identity: PGPKeyIdentity) throws {
        let data = try JSONEncoder().encode(identity)
        try mockKC.save(
            data,
            service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
    }

    private func provisionFixtureBackedIdentity(secretCertData: Data) throws -> PGPKeyIdentity {
        let info = try engine.parseKeyInfo(keyData: secretCertData)
        let handle = try mockSE.generateWrappingKey(accessControl: nil)
        let bundle = try mockSE.wrap(
            privateKey: secretCertData,
            using: handle,
            fingerprint: info.fingerprint
        )
        let bundleStore = KeyBundleStore(keychain: mockKC)
        try bundleStore.saveBundle(bundle, fingerprint: info.fingerprint)

        // Test-only fixture path: retain the exact fixture bytes on the identity so
        // selector discovery sees the same duplicate-occurrence structure already
        // exercised by `test_selectionCatalog_duplicateSameBytesFixture_preservesPerOccurrenceState`.
        let identity = PGPKeyIdentity(
            fingerprint: info.fingerprint,
            keyVersion: info.keyVersion,
            profile: info.profile,
            userId: info.userId,
            hasEncryptionSubkey: info.hasEncryptionSubkey,
            isRevoked: info.isRevoked,
            isExpired: info.isExpired,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: secretCertData,
            revocationCert: Data(),
            primaryAlgo: info.primaryAlgo,
            subkeyAlgo: info.subkeyAlgo,
            expiryDate: info.expiryTimestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        )
        try storeIdentity(identity)
        return identity
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

    func test_exportKey_metadataUpdateFailure_keepsSessionBackedUp_butFreshServiceSeesOldState() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        mockKC.deleteError = MockKeychainError.deleteFailed

        _ = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "backup-pass"
        )

        XCTAssertTrue(try XCTUnwrap(service.keys.first).isBackedUp)

        let freshService = makeFreshService()
        try freshService.loadKeys()

        XCTAssertEqual(freshService.keys.count, 1)
        XCTAssertFalse(try XCTUnwrap(freshService.keys.first).isBackedUp)
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

    func test_deleteKey_removesPendingKeychainItems() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let fp = identity.fingerprint

        try copyPermanentBundleToPending(fingerprint: fp)

        try service.deleteKey(fingerprint: fp)

        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.pendingSaltService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
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

    func test_deleteKey_partialFailure_stillSyncsCurrentSessionState() async throws {
        let first = try await TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Second")

        mockKC.deleteError = MockKeychainError.deleteFailed

        XCTAssertThrowsError(try service.deleteKey(fingerprint: first.fingerprint)) { error in
            guard case .keychainError(let message) = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError.keychainError, got \(error)")
            }
            XCTAssertTrue(message.contains("Partial key deletion"))
        }

        XCTAssertEqual(service.keys.map(\.fingerprint), [second.fingerprint])
        XCTAssertEqual(service.defaultKey?.fingerprint, second.fingerprint)
        XCTAssertTrue(try XCTUnwrap(service.keys.first).isDefault)
    }

    func test_deleteKey_interruptedModifyExpiry_clearsRecoveryStateAndBlocksRestore() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let fp = identity.fingerprint

        try copyPermanentBundleToPending(fingerprint: fp)
        UserDefaults.standard.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.set(fp, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        try service.deleteKey(fingerprint: fp)

        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))
        XCTAssertNil(UserDefaults.standard.string(forKey: AuthPreferences.modifyExpiryFingerprintKey))
        XCTAssertNil(service.checkAndRecoverFromInterruptedModifyExpiry())
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.seKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
    }

    func test_deleteKey_interruptedRewrap_lastKeyClearsGlobalRecoveryState() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        try copyPermanentBundleToPending(fingerprint: identity.fingerprint)
        UserDefaults.standard.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        UserDefaults.standard.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)

        try service.deleteKey(fingerprint: identity.fingerprint)

        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.rewrapInProgressKey))
        XCTAssertNil(UserDefaults.standard.string(forKey: AuthPreferences.rewrapTargetModeKey))
    }

    func test_deleteKey_interruptedRewrap_withOtherKeysPreservesGlobalRecoveryState() async throws {
        let first = try await TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Second")

        try copyPermanentBundleToPending(fingerprint: first.fingerprint)
        UserDefaults.standard.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        UserDefaults.standard.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)

        try service.deleteKey(fingerprint: first.fingerprint)

        XCTAssertTrue(UserDefaults.standard.bool(forKey: AuthPreferences.rewrapInProgressKey))
        XCTAssertEqual(
            UserDefaults.standard.string(forKey: AuthPreferences.rewrapTargetModeKey),
            AuthenticationMode.highSecurity.rawValue
        )
        XCTAssertEqual(service.keys.map(\.fingerprint), [second.fingerprint])
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: first.fingerprint),
            account: KeychainConstants.defaultAccount))
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

    func test_setDefaultKey_metadataSaveFailure_stillSyncsCurrentSessionState() async throws {
        let first = try await TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Second")

        mockKC.saveError = MockKeychainError.saveFailed

        XCTAssertThrowsError(try service.setDefaultKey(fingerprint: second.fingerprint)) { error in
            guard let keychainError = error as? MockKeychainError,
                  case .saveFailed = keychainError else {
                return XCTFail("Expected MockKeychainError.saveFailed, got \(error)")
            }
        }

        XCTAssertFalse(try XCTUnwrap(service.keys.first(where: { $0.fingerprint == first.fingerprint })).isDefault)
        XCTAssertTrue(try XCTUnwrap(service.keys.first(where: { $0.fingerprint == second.fingerprint })).isDefault)
        XCTAssertEqual(service.defaultKey?.fingerprint, second.fingerprint)
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
        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        // Verify: flags cleared
        XCTAssertEqual(outcome, .cleanedPendingSafe)
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
        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        // Verify: flags cleared
        XCTAssertEqual(outcome, .promotedPendingSafe)
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
        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        // Verify: no Keychain operations performed
        XCTAssertNil(outcome)
        XCTAssertEqual(mockKC.saveCallCount, saveCountBefore,
                       "No Keychain saves should occur when flag is not set")
        XCTAssertEqual(mockKC.deleteCallCount, deleteCountBefore,
                       "No Keychain deletes should occur when flag is not set")

        // Verify: original key still intact
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.seKeyService(fingerprint: fp),
                                    account: account))
    }

    func test_modifyExpiryCrashRecovery_partialPermanentAndCompletePending_replacesPermanent() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Partial Promote Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

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

        try mockKC.delete(service: KeychainConstants.saltService(fingerprint: fp), account: account)
        try mockKC.delete(service: KeychainConstants.sealedKeyService(fingerprint: fp), account: account)

        UserDefaults.standard.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.set(fp, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .promotedPendingSafe)
        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.seKeyService(fingerprint: fp), account: account))
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.saltService(fingerprint: fp), account: account))
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.sealedKeyService(fingerprint: fp), account: account))
        XCTAssertFalse(mockKC.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fp), account: account))
    }

    func test_modifyExpiryCrashRecovery_retryableFailure_keepsFlags() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Retry Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        try mockKC.save(Data([0xAA]), service: KeychainConstants.pendingSeKeyService(fingerprint: fp),
                        account: account, accessControl: nil)
        try mockKC.save(Data([0xBB]), service: KeychainConstants.pendingSaltService(fingerprint: fp),
                        account: account, accessControl: nil)
        try mockKC.save(Data([0xCC]), service: KeychainConstants.pendingSealedKeyService(fingerprint: fp),
                        account: account, accessControl: nil)

        try mockKC.delete(service: KeychainConstants.seKeyService(fingerprint: fp), account: account)
        mockKC.failOnSaveNumber = mockKC.saveCallCount + 1

        UserDefaults.standard.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.set(fp, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .retryableFailure)
        XCTAssertTrue(UserDefaults.standard.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))
        XCTAssertEqual(
            UserDefaults.standard.string(forKey: AuthPreferences.modifyExpiryFingerprintKey),
            fp
        )
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fp), account: account))
    }

    func test_modifyExpiryCrashRecovery_unrecoverable_clearsFlags() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Unrecoverable Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        try mockKC.delete(service: KeychainConstants.saltService(fingerprint: fp), account: account)
        try mockKC.save(Data([0xAA]), service: KeychainConstants.pendingSeKeyService(fingerprint: fp),
                        account: account, accessControl: nil)

        UserDefaults.standard.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.set(fp, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .unrecoverable)
        XCTAssertFalse(UserDefaults.standard.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))
        XCTAssertNil(UserDefaults.standard.string(forKey: AuthPreferences.modifyExpiryFingerprintKey))
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
        XCTAssertFalse(imported.revocationCert.isEmpty, "Imported key should immediately store a revocation signature")

        let revocationValidation = try engine.parseRevocationCert(
            revData: imported.revocationCert,
            certData: imported.publicKeyData
        )
        XCTAssertTrue(revocationValidation.lowercased().contains(imported.fingerprint.lowercased()))
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
        XCTAssertFalse(imported.revocationCert.isEmpty)

        let revocationValidation = try engine.parseRevocationCert(
            revData: imported.revocationCert,
            certData: imported.publicKeyData
        )
        XCTAssertTrue(revocationValidation.lowercased().contains(imported.fingerprint.lowercased()))
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

    // MARK: - H1: High Security Biometrics Blocking

    func test_exportKey_highSecurity_biometricsUnavailable_throwsAuthError() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        mockSE.simulatedAuthMode = .highSecurity
        mockSE.biometricsAvailable = false

        do {
            _ = try await service.exportKey(
                fingerprint: identity.fingerprint,
                passphrase: "backup-pass"
            )
            XCTFail("Expected error when biometrics unavailable in High Security mode")
        } catch {
            // Auth error from SE reconstructKey during unwrapPrivateKey
        }
    }

    // MARK: - M2: Wrong Passphrase

    func test_importKey_profileA_wrongPassphrase_throwsError() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "correct-passphrase"
        )

        // Attempt import with wrong passphrase
        do {
            _ = try await service.importKey(
                armoredData: exported,
                passphrase: "wrong-passphrase",
                authMode: .standard
            )
            XCTFail("Expected error for wrong passphrase")
        } catch let error as CypherAirError {
            // Accept .wrongPassphrase or .s2kError — both indicate passphrase failure
            switch error {
            case .wrongPassphrase, .s2kError:
                break // Expected
            default:
                XCTFail("Expected wrong passphrase error, got \(error)")
            }
        }
    }

    func test_importKey_profileB_wrongPassphrase_throwsError() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "correct-passphrase"
        )

        do {
            _ = try await service.importKey(
                armoredData: exported,
                passphrase: "wrong-passphrase",
                authMode: .standard
            )
            XCTFail("Expected error for wrong passphrase")
        } catch let error as CypherAirError {
            switch error {
            case .wrongPassphrase, .s2kError:
                break // Expected
            default:
                XCTFail("Expected wrong passphrase error, got \(error)")
            }
        }
    }

    // MARK: - M3: Argon2id Memory Guard Integration

    func test_importKey_profileB_lowMemory_throwsArgon2idExceeded() async throws {
        // Service with full memory for key generation + export
        let identity = try await TestHelpers.generateProfileBKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "test-pass"
        )

        // Create a separate service with low memory (500 MB)
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 500_000_000
        let (lowMemService, _, _, _) = TestHelpers.makeKeyManagement(memoryInfo: mockMemory)

        // Profile B uses Argon2id with 512 MB; 512 MB > 75% of 500 MB (375 MB) → rejected
        do {
            _ = try await lowMemService.importKey(
                armoredData: exported,
                passphrase: "test-pass",
                authMode: .standard
            )
            XCTFail("Expected argon2idMemoryExceeded for low-memory import")
        } catch let error as CypherAirError {
            if case .argon2idMemoryExceeded = error {
                // Expected
            } else {
                XCTFail("Expected .argon2idMemoryExceeded, got \(error)")
            }
        }
    }

    func test_importKey_profileA_lowMemory_succeeds() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "test-pass"
        )

        // Create a service with low memory
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 500_000_000
        let (lowMemService, _, _, _) = TestHelpers.makeKeyManagement(memoryInfo: mockMemory)

        // Profile A uses Iterated+Salted S2K (no Argon2id) — guard is no-op
        let imported = try await lowMemService.importKey(
            armoredData: exported,
            passphrase: "test-pass",
            authMode: .standard
        )
        XCTAssertEqual(imported.profile, .universal)
    }

    // MARK: - Selector Discovery

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
        let identity = PGPKeyIdentity(
            fingerprint: info.fingerprint,
            keyVersion: info.keyVersion,
            profile: info.profile,
            userId: info.userId,
            hasEncryptionSubkey: info.hasEncryptionSubkey,
            isRevoked: info.isRevoked,
            isExpired: info.isExpired,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: fixture,
            revocationCert: Data(),
            primaryAlgo: info.primaryAlgo,
            subkeyAlgo: info.subkeyAlgo,
            expiryDate: info.expiryTimestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) }
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

    // MARK: - M4: Revocation Certificate Validity

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
            passphrase: passphrase,
            authMode: .standard
        )

        let metadataSavesBefore = mockKC.saveCallCount
        let unwrapCountBefore = mockSE.unwrapCallCount

        let armored = try await service.exportRevocationCertificate(fingerprint: imported.fingerprint)

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore, "Stored imported revocation should not trigger unwrap")
        XCTAssertEqual(mockKC.saveCallCount, metadataSavesBefore, "Stored imported revocation should not rewrite metadata")

        let binary = try engine.dearmor(armored: armored)
        XCTAssertEqual(binary, imported.revocationCert)
    }

    func test_exportRevocationCertificate_legacyMissingRevocation_backfillsAndSecondExportSkipsUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Legacy Revocation")
        let passphrase = "legacy-revocation-pass"
        let exportedBackup = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        try service.deleteKey(fingerprint: identity.fingerprint)

        let imported = try await service.importKey(
            armoredData: exportedBackup,
            passphrase: passphrase,
            authMode: .standard
        )

        var legacyIdentity = try loadStoredIdentity(fingerprint: imported.fingerprint)
        legacyIdentity.revocationCert = Data()
        try overwriteStoredIdentity(legacyIdentity)

        let legacyService = makeFreshService()
        try legacyService.loadKeys()
        XCTAssertTrue(try XCTUnwrap(legacyService.keys.first).revocationCert.isEmpty)

        let unwrapCountBeforeFirstExport = mockSE.unwrapCallCount
        let firstArmored = try await legacyService.exportRevocationCertificate(fingerprint: imported.fingerprint)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBeforeFirstExport + 1, "Legacy backfill should unwrap once")

        let firstBinary = try engine.dearmor(armored: firstArmored)
        let persisted = try loadStoredIdentity(fingerprint: imported.fingerprint)
        XCTAssertEqual(firstBinary, persisted.revocationCert, "Backfilled revocation should persist to metadata")
        XCTAssertFalse(persisted.revocationCert.isEmpty)

        let unwrapCountBeforeSecondExport = mockSE.unwrapCallCount
        let secondArmored = try await legacyService.exportRevocationCertificate(fingerprint: imported.fingerprint)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBeforeSecondExport, "Persisted revocation should skip unwrap on later exports")
        XCTAssertEqual(secondArmored, firstArmored)
    }

    func test_exportRevocationCertificate_legacyMissingRevocation_metadataUpdateFailure_stillExportsAndKeepsSessionBackfilled() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Legacy Revocation Save Failure")
        let passphrase = "legacy-revocation-save-failure-pass"
        let exportedBackup = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        try service.deleteKey(fingerprint: identity.fingerprint)

        let imported = try await service.importKey(
            armoredData: exportedBackup,
            passphrase: passphrase,
            authMode: .standard
        )

        var legacyIdentity = try loadStoredIdentity(fingerprint: imported.fingerprint)
        legacyIdentity.revocationCert = Data()
        try overwriteStoredIdentity(legacyIdentity)

        let legacyService = makeFreshService()
        try legacyService.loadKeys()
        XCTAssertTrue(try XCTUnwrap(legacyService.keys.first).revocationCert.isEmpty)

        mockKC.saveError = MockKeychainError.saveFailed

        let unwrapCountBeforeFirstExport = mockSE.unwrapCallCount
        let firstArmored = try await legacyService.exportRevocationCertificate(fingerprint: imported.fingerprint)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBeforeFirstExport + 1, "Legacy backfill should unwrap once even when metadata persistence fails")

        let firstBinary = try engine.dearmor(armored: firstArmored)
        XCTAssertEqual(try XCTUnwrap(legacyService.keys.first).revocationCert, firstBinary, "Current session should keep the generated revocation even if metadata persistence fails")

        let persisted = try loadStoredIdentity(fingerprint: imported.fingerprint)
        XCTAssertTrue(persisted.revocationCert.isEmpty, "Failed metadata update should restore the previous persisted metadata")

        let unwrapCountBeforeSecondExport = mockSE.unwrapCallCount
        let secondArmored = try await legacyService.exportRevocationCertificate(fingerprint: imported.fingerprint)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBeforeSecondExport, "Current session should not re-unwrap after an in-memory backfill")
        XCTAssertEqual(secondArmored, firstArmored)

        let freshService = makeFreshService()
        try freshService.loadKeys()
        XCTAssertTrue(try XCTUnwrap(freshService.keys.first).revocationCert.isEmpty, "Fresh service should still observe the legacy persisted state")

        let unwrapCountBeforeFreshExport = mockSE.unwrapCallCount
        let freshArmored = try await freshService.exportRevocationCertificate(fingerprint: imported.fingerprint)
        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBeforeFreshExport + 1, "Fresh service should backfill again because persisted metadata was unchanged")

        let freshBinary = try engine.dearmor(armored: freshArmored)
        let freshSessionIdentity = try XCTUnwrap(freshService.keys.first)
        XCTAssertEqual(freshSessionIdentity.revocationCert, freshBinary)
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

    // MARK: - Selective Revocation: Subkey

    /// Armor header used to verify the service returns ASCII-armored signature bytes.
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

    // MARK: - Selective Revocation: User ID

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
    /// covered at the Rust/FFI layer by `FFIIntegrationTests.test_generateUserIdRevocation_*`
    /// and by `pgp-mobile/tests/revocation_construction_tests.rs`.
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
