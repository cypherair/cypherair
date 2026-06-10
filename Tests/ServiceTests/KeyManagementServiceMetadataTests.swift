import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceMetadataTests: KeyManagementServiceTestCase {

    func test_generateKey_persistsIdentityThroughInjectedMetadataPersistence() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        XCTAssertEqual(metadataPersistence.saveCallCount, 1)
        XCTAssertEqual(metadataPersistence.identities, [identity])
        XCTAssertTrue(mockKC.exists(
            service: KeychainConstants.sealedKeyService(fingerprint: identity.fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_loadKeys_emptyPersistence_returnsEmpty() async throws {
        try service.loadKeys()
        XCTAssertTrue(service.keys.isEmpty)
    }

    func test_loadKeys_withStoredMetadata_loadsKeys() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        // Create a new service instance over the same metadata persistence
        let newService = makeFreshService()

        try newService.loadKeys()
        XCTAssertEqual(newService.keys.count, 1)
        XCTAssertEqual(newService.keys.first?.fingerprint, identity.fingerprint)
    }

    func test_loadKeys_persistenceFailure_entersRecoveryNeeded() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: service)
        metadataPersistence.failNextLoadAll = true

        let newService = makeFreshService()
        XCTAssertThrowsError(try newService.loadKeys())

        XCTAssertTrue(newService.keys.isEmpty)
        XCTAssertEqual(newService.metadataLoadState, .recoveryNeeded)
    }

}
