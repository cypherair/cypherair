import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceMetadataTests: KeyManagementServiceTestCase {

    func test_generateKey_withInjectedMetadataPersistenceDoesNotWriteMetadataKeychainRows() async throws {
        let metadataPersistence = RecordingKeyMetadataPersistence()
        let protectedMetadataService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth,
            privateKeyControlStore: privateKeyControlStore,
            metadataPersistence: metadataPersistence
        )

        let identity = try await TestHelpers.generateProfileAKey(service: protectedMetadataService)

        XCTAssertEqual(metadataPersistence.saveCallCount, 1)
        XCTAssertEqual(metadataPersistence.identities, [identity])
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
            account: KeychainConstants.metadataAccount
        ))
        XCTAssertFalse(mockKC.listItemsCalls.contains { call in
            call.servicePrefix == KeychainConstants.metadataPrefix
        })
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.sealedKeyService(fingerprint: identity.fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_loadKeys_emptyKeychain_returnsEmpty() async throws {
        try service.loadKeys()
        XCTAssertTrue(service.keys.isEmpty)
    }

    func test_loadKeys_withStoredMetadata_loadsKeys() async throws {
        // Generate a key (stores metadata in mock Keychain)
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        // Create a new service instance pointing at the same Keychain
        let newService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth,
            privateKeyControlStore: privateKeyControlStore
        )

        try newService.loadKeys()
        XCTAssertEqual(newService.keys.count, 1)
        XCTAssertEqual(newService.keys.first?.fingerprint, identity.fingerprint)
    }

    func test_loadKeys_usesDedicatedMetadataAccountOnly() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        mockKC.resetCallHistory()

        let newService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth,
            privateKeyControlStore: privateKeyControlStore
        )

        try newService.loadKeys()

        XCTAssertEqual(newService.keys.first?.fingerprint, identity.fingerprint)
        XCTAssertTrue(mockKC.listItemsCalls.contains { call in
            call.servicePrefix == KeychainConstants.metadataPrefix
                && call.account == KeychainConstants.metadataAccount
        })
        XCTAssertFalse(mockKC.listItemsCalls.contains { call in
            call.servicePrefix == KeychainConstants.metadataPrefix
                && call.account == KeychainConstants.defaultAccount
        })
    }

    func test_legacyMetadataMigration_afterAppAuthentication_movesMetadataToDedicatedAccount() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let serviceName = KeychainConstants.metadataService(fingerprint: identity.fingerprint)
        let metadata = try mockKC.load(
            service: serviceName,
            account: KeychainConstants.metadataAccount
        )
        try mockKC.save(
            metadata,
            service: serviceName,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try mockKC.delete(service: serviceName, account: KeychainConstants.metadataAccount)

        let freshService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth,
            privateKeyControlStore: privateKeyControlStore
        )
        try freshService.loadKeys()
        XCTAssertTrue(freshService.keys.isEmpty)

        let context = LAContext()
        await freshService.migrateLegacyMetadataAfterAppAuthentication(
            authenticationContext: context,
            source: "unitTest"
        )

        XCTAssertEqual(freshService.keys.map(\.fingerprint), [identity.fingerprint])
        XCTAssertNil(freshService.legacyMetadataMigrationLoadWarning)
        XCTAssertTrue(mockKC.exists(service: serviceName, account: KeychainConstants.metadataAccount))
        XCTAssertFalse(mockKC.exists(service: serviceName, account: KeychainConstants.defaultAccount))
        XCTAssertTrue(mockKC.listItemsCalls.contains { call in
            call.account == KeychainConstants.defaultAccount && call.hasAuthenticationContext
        })
    }

    func test_legacyMetadataMigration_listFailureDoesNotBlockCurrentSession() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let serviceName = KeychainConstants.metadataService(fingerprint: identity.fingerprint)
        let metadata = try mockKC.load(
            service: serviceName,
            account: KeychainConstants.metadataAccount
        )
        try mockKC.save(
            metadata,
            service: serviceName,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try mockKC.delete(service: serviceName, account: KeychainConstants.metadataAccount)

        let freshService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth,
            privateKeyControlStore: privateKeyControlStore
        )
        mockKC.listItemsError = MockKeychainError.userCancelled

        await freshService.migrateLegacyMetadataAfterAppAuthentication(
            authenticationContext: LAContext(),
            source: "unitTest"
        )

        XCTAssertTrue(freshService.keys.isEmpty)
        XCTAssertNotNil(freshService.legacyMetadataMigrationLoadWarning)
        freshService.clearLegacyMetadataMigrationLoadWarning()
        XCTAssertNil(freshService.legacyMetadataMigrationLoadWarning)
        XCTAssertTrue(mockKC.exists(service: serviceName, account: KeychainConstants.defaultAccount))
        XCTAssertFalse(mockKC.exists(service: serviceName, account: KeychainConstants.metadataAccount))
    }

    func test_loadKeys_corruptMetadata_skipsCorruptEntry() async throws {
        // Store valid metadata
        try await TestHelpers.generateProfileAKey(service: service)

        // Store corrupt metadata under a fake fingerprint
        let corruptData = Data("not-valid-json".utf8)
        try mockKC.save(
            corruptData,
            service: KeychainConstants.metadataService(fingerprint: "deadbeef"),
            account: KeychainConstants.metadataAccount,
            accessControl: nil
        )

        // Load should succeed, skipping the corrupt entry
        let newService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth,
            privateKeyControlStore: privateKeyControlStore
        )
        try newService.loadKeys()

        // Should load only the valid key, not the corrupt one
        XCTAssertEqual(newService.keys.count, 1)
    }

}
