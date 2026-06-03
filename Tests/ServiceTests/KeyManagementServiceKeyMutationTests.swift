import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceKeyMutationTests: KeyManagementServiceTestCase {

    func test_deleteKey_removesKeychainItems() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let fp = identity.fingerprint

        try service.deleteKey(fingerprint: fp)

        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.seKeyService(fingerprint: fp),
            account: KeychainConstants.defaultAccount))
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.metadataService(fingerprint: fp),
            account: KeychainConstants.metadataAccount))
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
        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        try service.deleteKey(fingerprint: fp)

        XCTAssertNil(try recoveryJournal().modifyExpiry)
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
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)

        try service.deleteKey(fingerprint: identity.fingerprint)

        XCTAssertNil(try recoveryJournal().rewrapTargetMode)
    }

    func test_deleteKey_interruptedRewrap_withOtherKeysPreservesGlobalRecoveryState() async throws {
        let first = try await TestHelpers.generateProfileAKey(service: service, name: "First")
        let second = try await TestHelpers.generateProfileBKey(service: service, name: "Second")

        try copyPermanentBundleToPending(fingerprint: first.fingerprint)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)

        try service.deleteKey(fingerprint: first.fingerprint)

        XCTAssertEqual(try recoveryJournal().rewrapTargetMode, .highSecurity)
        XCTAssertEqual(service.keys.map(\.fingerprint), [second.fingerprint])
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: first.fingerprint),
            account: KeychainConstants.defaultAccount))
    }

    func test_unwrapPrivateKey_validFingerprint_returnsData() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        let privateKeyData = try await service.unwrapPrivateKey(fingerprint: identity.fingerprint)
        XCTAssertFalse(privateKeyData.isEmpty, "Unwrapped private key should not be empty")

        // Verify SE unwrap was called
        XCTAssertEqual(mockSE.unwrapCallCount, 1)
    }

    func test_unwrapPrivateKey_usesAuthenticationPromptCoordinator() async throws {
        let coordinator = CypherAir.AuthenticationPromptCoordinator()
        let observingSecureEnclave = PromptObservingSecureEnclave(
            base: mockSE,
            coordinator: coordinator
        )
        let promptAwareService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: observingSecureEnclave,
            keychain: mockKC,
            authenticator: mockAuth,
            authenticationPromptCoordinator: coordinator,
            privateKeyControlStore: privateKeyControlStore
        )
        let identity = try await TestHelpers.generateProfileAKey(service: promptAwareService)

        let privateKeyData = try await promptAwareService.unwrapPrivateKey(
            fingerprint: identity.fingerprint
        )

        XCTAssertFalse(privateKeyData.isEmpty)
        XCTAssertTrue(observingSecureEnclave.sawOperationPromptInProgressDuringReconstruct)
        XCTAssertFalse(coordinator.isOperationPromptInProgress)
    }

    func test_unwrapPrivateKey_unknownFingerprint_throwsError() async {
        do {
            _ = try await service.unwrapPrivateKey(fingerprint: "unknown-fp")
            XCTFail("Expected unwrapPrivateKey to throw for unknown fingerprint")
        } catch {
            // Expected: Keychain load fails for unknown fingerprint
        }
    }

    func test_unwrapPrivateKey_profileB_returnsData() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)

        let privateKeyData = try await service.unwrapPrivateKey(fingerprint: identity.fingerprint)
        XCTAssertFalse(privateKeyData.isEmpty)
    }

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
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth,
            privateKeyControlStore: privateKeyControlStore
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
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth,
            privateKeyControlStore: privateKeyControlStore
        )
        try freshService.loadKeys()

        // Verify the promoted default persisted through reload
        XCTAssertEqual(freshService.keys.count, 1)
        XCTAssertTrue(freshService.keys.first?.isDefault == true,
                      "Promoted default should persist across reload")
        XCTAssertEqual(freshService.keys.first?.fingerprint, second.fingerprint)
    }

}
