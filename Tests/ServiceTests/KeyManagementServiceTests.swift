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
        service = nil
        mockSE = nil
        mockKC = nil
        mockAuth = nil
        engine = nil
        super.tearDown()
    }

    // MARK: - Key Generation: Profile A

    func test_generateKey_profileA_storesKeychainItems() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service)

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

    func test_generateKey_profileA_returnsCorrectIdentity() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service)

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

    func test_generateKey_profileB_storesKeychainItems() throws {
        let identity = try TestHelpers.generateProfileBKey(service: service)

        XCTAssertEqual(mockKC.saveCallCount, 4)

        let fp = identity.fingerprint
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.seKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
    }

    func test_generateKey_profileB_returnsCorrectIdentity() throws {
        let identity = try TestHelpers.generateProfileBKey(service: service)

        XCTAssertEqual(identity.keyVersion, 6, "Profile B should produce v6 key")
        XCTAssertEqual(identity.profile, .advanced)
        XCTAssertTrue(identity.hasEncryptionSubkey)
    }

    // MARK: - Key Generation: Default Key Logic

    func test_generateKey_firstKey_isDefault() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service)
        XCTAssertTrue(identity.isDefault, "First key should be default")
    }

    func test_generateKey_secondKey_isNotDefault() throws {
        try TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try TestHelpers.generateProfileBKey(service: service, name: "Second")
        XCTAssertFalse(second.isDefault, "Second key should not be default")
    }

    // MARK: - Key Generation: SE Interaction

    func test_generateKey_seWrapCalled() throws {
        try TestHelpers.generateProfileAKey(service: service)

        XCTAssertEqual(mockSE.generateCallCount, 1, "SE should generate one wrapping key")
        XCTAssertEqual(mockSE.wrapCallCount, 1, "SE should wrap once")
    }

    func test_generateKey_profileB_seWrapCalled() throws {
        try TestHelpers.generateProfileBKey(service: service)

        XCTAssertEqual(mockSE.generateCallCount, 1)
        XCTAssertEqual(mockSE.wrapCallCount, 1)
    }

    // MARK: - Key Loading

    func test_loadKeys_emptyKeychain_returnsEmpty() throws {
        try service.loadKeys()
        XCTAssertTrue(service.keys.isEmpty)
    }

    func test_loadKeys_withStoredMetadata_loadsKeys() throws {
        // Generate a key (stores metadata in mock Keychain)
        let identity = try TestHelpers.generateProfileAKey(service: service)

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

    func test_loadKeys_corruptMetadata_skipsCorruptEntry() throws {
        // Store valid metadata
        try TestHelpers.generateProfileAKey(service: service)

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

    func test_exportKey_profileA_returnsArmoredData() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service)

        let exported = try service.exportKey(fingerprint: identity.fingerprint, passphrase: "test-pass-123")

        XCTAssertFalse(exported.isEmpty, "Exported data should not be empty")
        // Check it starts with PGP armor header
        let armorHeader = String(data: exported.prefix(27), encoding: .utf8)
        XCTAssertTrue(armorHeader?.hasPrefix("-----BEGIN PGP") == true,
                      "Exported data should be ASCII-armored")
    }

    func test_exportKey_marksKeyAsBackedUp() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service)
        XCTAssertFalse(identity.isBackedUp)

        _ = try service.exportKey(fingerprint: identity.fingerprint, passphrase: "backup-pass")

        XCTAssertTrue(service.keys.first?.isBackedUp == true,
                      "Key should be marked as backed up after export")
    }

    func test_exportKey_nonexistentFingerprint_throwsError() {
        XCTAssertThrowsError(try service.exportKey(fingerprint: "nonexistent", passphrase: "pass")) { error in
            // Should fail — no key with this fingerprint exists in Keychain
        }
    }

    func test_exportKey_profileB_returnsArmoredData() throws {
        let identity = try TestHelpers.generateProfileBKey(service: service)

        let exported = try service.exportKey(fingerprint: identity.fingerprint, passphrase: "test-pass-456")
        XCTAssertFalse(exported.isEmpty)
    }

    // MARK: - Key Deletion

    func test_deleteKey_removesKeychainItems() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service)
        let fp = identity.fingerprint

        try service.deleteKey(fingerprint: fp)

        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.seKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
    }

    func test_deleteKey_removesFromKeysArray() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service)
        XCTAssertEqual(service.keys.count, 1)

        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertEqual(service.keys.count, 0)
    }

    func test_deleteKey_reassignsDefaultIfNeeded() throws {
        let first = try TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try TestHelpers.generateProfileBKey(service: service, name: "Second")

        XCTAssertTrue(first.isDefault)
        XCTAssertFalse(second.isDefault)

        // Delete the default key
        try service.deleteKey(fingerprint: first.fingerprint)

        // The remaining key should become default
        XCTAssertTrue(service.keys.first?.isDefault == true,
                      "Remaining key should become default after default deleted")
    }

    // MARK: - Unwrap Private Key

    func test_unwrapPrivateKey_validFingerprint_returnsData() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service)

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

    func test_unwrapPrivateKey_profileB_returnsData() throws {
        let identity = try TestHelpers.generateProfileBKey(service: service)

        let privateKeyData = try service.unwrapPrivateKey(fingerprint: identity.fingerprint)
        XCTAssertFalse(privateKeyData.isEmpty)
    }

    // MARK: - Key Import/Restore

    func test_importKey_profileA_exportThenImport_fingerprintMatches() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service, name: "Export Test A")
        let passphrase = "test-passphrase-123"

        // Export the key
        let exportedData = try service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        XCTAssertFalse(exportedData.isEmpty)

        // Delete the original key
        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        // Import the exported key
        let imported = try service.importKey(
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

    func test_importKey_profileB_exportThenImport_fingerprintMatches() throws {
        let identity = try TestHelpers.generateProfileBKey(service: service, name: "Export Test B")
        let passphrase = "test-passphrase-456"

        let exportedData = try service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        XCTAssertFalse(exportedData.isEmpty)

        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        let imported = try service.importKey(
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

    func test_setDefaultKey_switchesDefault() throws {
        let first = try TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try TestHelpers.generateProfileBKey(service: service, name: "Second")

        XCTAssertTrue(service.keys.first(where: { $0.fingerprint == first.fingerprint })!.isDefault)
        XCTAssertFalse(service.keys.first(where: { $0.fingerprint == second.fingerprint })!.isDefault)

        service.setDefaultKey(fingerprint: second.fingerprint)

        XCTAssertFalse(service.keys.first(where: { $0.fingerprint == first.fingerprint })!.isDefault)
        XCTAssertTrue(service.keys.first(where: { $0.fingerprint == second.fingerprint })!.isDefault)
    }

    func test_defaultKey_returnsFirstDefault() throws {
        let identity = try TestHelpers.generateProfileAKey(service: service)
        XCTAssertEqual(service.defaultKey?.fingerprint, identity.fingerprint)
    }

    func test_defaultKey_noKeys_returnsNil() {
        XCTAssertNil(service.defaultKey)
    }
}
