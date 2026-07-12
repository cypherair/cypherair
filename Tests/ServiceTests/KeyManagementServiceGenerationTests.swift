import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceGenerationTests: KeyManagementServiceTestCase {

    func test_generateKey_profileA_storesKeychainItems() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        // Should store a single Keychain item: the private-key envelope row.
        // Metadata persists through the injected metadata persistence, not the Keychain.
        XCTAssertEqual(mockKC.saveCallCount, 1,
                       "Profile A key gen should store one private-key envelope item")

        // Verify the envelope row exists
        let fp = identity.fingerprint
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
        XCTAssertEqual(metadataPersistence.identities.map(\.fingerprint), [fp])
    }

    func test_generateKey_profileA_returnsCorrectIdentity() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        XCTAssertEqual(identity.keyVersion, 4, "Profile A should produce v4 key")
        XCTAssertEqual(identity.softwareProfile, .universal)
        XCTAssertFalse(identity.fingerprint.isEmpty)
        XCTAssertTrue(identity.hasEncryptionSubkey, "Generated key should have encryption subkey")
        XCTAssertFalse(identity.isRevoked)
        XCTAssertFalse(identity.isExpired)
        XCTAssertFalse(identity.isBackedUp)
        XCTAssertFalse(identity.publicKeyData.isEmpty)
        XCTAssertFalse(identity.revocationCert.isEmpty)
    }

    func test_generateKey_profileB_storesKeychainItems() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)

        XCTAssertEqual(mockKC.saveCallCount, 1)

        let fp = identity.fingerprint
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
    }

    func test_generateKey_profileB_returnsCorrectIdentity() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)

        XCTAssertEqual(identity.keyVersion, 6, "Profile B should produce v6 key")
        XCTAssertEqual(identity.softwareProfile, .advanced)
        XCTAssertTrue(identity.hasEncryptionSubkey)
    }

    func test_generateKey_firstKey_isDefault() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        XCTAssertTrue(identity.isDefault, "First key should be default")
    }

    func test_generateKey_secondKey_isNotDefault() async throws {
        try await TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Second")
        XCTAssertFalse(second.isDefault, "Second key should not be default")
    }

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

}
