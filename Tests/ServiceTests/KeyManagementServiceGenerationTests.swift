import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceGenerationTests: KeyManagementServiceTestCase {

    func test_generateKey_legacy_storesKeychainItems() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)

        // Should store a single Keychain item: the private-key envelope row.
        // Metadata persists through the injected metadata persistence, not the Keychain.
        XCTAssertEqual(mockKC.saveCallCount, 1,
                       "Legacy key gen should store one private-key envelope item")

        // Verify the envelope row exists
        let fp = identity.fingerprint
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
        XCTAssertEqual(metadataPersistence.identities.map(\.fingerprint), [fp])
    }

    func test_generateKey_legacy_returnsCorrectIdentity() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)

        XCTAssertEqual(identity.keyVersion, 4, "Legacy should produce v4 key")
        XCTAssertEqual(identity.softwareSuite, .ed25519LegacyCurve25519Legacy)
        XCTAssertFalse(identity.fingerprint.isEmpty)
        XCTAssertTrue(identity.hasEncryptionSubkey, "Generated key should have encryption subkey")
        XCTAssertFalse(identity.isRevoked)
        XCTAssertFalse(identity.isExpired)
        XCTAssertFalse(identity.isBackedUp)
        XCTAssertFalse(identity.publicKeyData.isEmpty)
        XCTAssertFalse(identity.revocationCert.isEmpty)
    }

    func test_generateKey_modernHigh_storesKeychainItems() async throws {
        let identity = try await TestHelpers.generateModernHighKey(service: service)

        XCTAssertEqual(mockKC.saveCallCount, 1)

        let fp = identity.fingerprint
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
    }

    func test_generateKey_modernHigh_returnsCorrectIdentity() async throws {
        let identity = try await TestHelpers.generateModernHighKey(service: service)

        XCTAssertEqual(identity.keyVersion, 6, "Modern High should produce v6 key")
        XCTAssertEqual(identity.softwareSuite, .ed448X448)
        XCTAssertTrue(identity.hasEncryptionSubkey)
    }

    func test_generateKey_firstKey_isDefault() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)
        XCTAssertTrue(identity.isDefault, "First key should be default")
    }

    func test_generateKey_secondKey_isNotDefault() async throws {
        try await TestHelpers.generateLegacyKey(service: service, name: "First")
        let second = try await TestHelpers.generateModernHighKey(service: service, name: "Second")
        XCTAssertFalse(second.isDefault, "Second key should not be default")
    }

    func test_generateKey_seWrapCalled() async throws {
        try await TestHelpers.generateLegacyKey(service: service)

        XCTAssertEqual(mockSE.generateCallCount, 1, "SE should generate one wrapping key")
        XCTAssertEqual(mockSE.wrapCallCount, 1, "SE should wrap once")
    }

    func test_generateKey_modernHigh_seWrapCalled() async throws {
        try await TestHelpers.generateModernHighKey(service: service)

        XCTAssertEqual(mockSE.generateCallCount, 1)
        XCTAssertEqual(mockSE.wrapCallCount, 1)
    }

}
