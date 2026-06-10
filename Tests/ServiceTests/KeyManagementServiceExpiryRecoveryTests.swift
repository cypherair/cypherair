import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceExpiryRecoveryTests: KeyManagementServiceTestCase {

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

        XCTAssertNil(try recoveryJournal().modifyExpiry)

        _ = try await service.modifyExpiry(
            fingerprint: identity.fingerprint,
            newExpirySeconds: 31_536_000,
            authMode: .standard
        )

        XCTAssertNil(try recoveryJournal().modifyExpiry)
    }

    func test_modifyExpiry_beginJournalFailureCleansPendingBundle() async throws {
        let failingStore = FailingModifyExpiryPrivateKeyControlStore()
        failingStore.failNextBeginModifyExpiry = true
        let stack = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: failingStore
        )
        let localService = stack.service
        let localKeychain = stack.mockKC
        let identity = try await TestHelpers.generateProfileAKey(service: localService, name: "Begin Journal Failure")
        let account = KeychainConstants.defaultAccount

        do {
            _ = try await localService.modifyExpiry(
                fingerprint: identity.fingerprint,
                newExpirySeconds: 31_536_000,
                authMode: .standard
            )
            XCTFail("Expected beginModifyExpiry failure to be surfaced.")
        } catch KeyManagementPrivateKeyControlTestError.delayedFailure {
        } catch {
            XCTFail("Expected delayedFailure, got \(error)")
        }

        XCTAssertTrue(localKeychain.exists(
            service: KeychainConstants.seKeyService(fingerprint: identity.fingerprint),
            account: account
        ))
        XCTAssertTrue(localKeychain.exists(
            service: KeychainConstants.saltService(fingerprint: identity.fingerprint),
            account: account
        ))
        XCTAssertTrue(localKeychain.exists(
            service: KeychainConstants.sealedKeyService(fingerprint: identity.fingerprint),
            account: account
        ))
        XCTAssertFalse(localKeychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: identity.fingerprint),
            account: account
        ))
        XCTAssertFalse(localKeychain.exists(
            service: KeychainConstants.pendingSaltService(fingerprint: identity.fingerprint),
            account: account
        ))
        XCTAssertFalse(localKeychain.exists(
            service: KeychainConstants.pendingSealedKeyService(fingerprint: identity.fingerprint),
            account: account
        ))
        XCTAssertNil(try failingStore.recoveryJournal().modifyExpiry)
    }

    func test_modifyExpiry_clearJournalFailureKeepsUpdatedMetadataAndJournal() async throws {
        let failingStore = FailingModifyExpiryPrivateKeyControlStore()
        failingStore.failNextClearModifyExpiry = true
        let localMetadataPersistence = RecordingKeyMetadataPersistence()
        let stack = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: failingStore,
            metadataPersistence: localMetadataPersistence
        )
        let localService = stack.service
        let localKeychain = stack.mockKC
        let identity = try await TestHelpers.generateProfileAKey(service: localService, name: "Clear Journal Failure")
        let originalStoredIdentity = try loadStoredIdentity(
            fingerprint: identity.fingerprint,
            persistence: localMetadataPersistence
        )

        do {
            _ = try await localService.modifyExpiry(
                fingerprint: identity.fingerprint,
                newExpirySeconds: 31_536_000,
                authMode: .standard
            )
            XCTFail("Expected clearModifyExpiryJournal failure to be surfaced.")
        } catch KeyManagementPrivateKeyControlTestError.delayedFailure {
        } catch {
            XCTFail("Expected delayedFailure, got \(error)")
        }

        let updatedStoredIdentity = try loadStoredIdentity(
            fingerprint: identity.fingerprint,
            persistence: localMetadataPersistence
        )
        XCTAssertNotEqual(updatedStoredIdentity.expiryDate, originalStoredIdentity.expiryDate)
        XCTAssertEqual(localService.keys.first?.expiryDate, updatedStoredIdentity.expiryDate)
        XCTAssertEqual(localService.keys.first?.publicKeyData, updatedStoredIdentity.publicKeyData)
        XCTAssertEqual(try failingStore.recoveryJournal().modifyExpiry?.fingerprint, identity.fingerprint)
        XCTAssertFalse(localKeychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: identity.fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_modifyExpiryCrashRecovery_oldAndPendingExist_deletesPending() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Recovery Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        // Simulate interrupted modifyExpiry: write protected journal and store pending items
        // while old permanent items still exist.
        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        let dummyData = Data("pending-data".utf8)
        try mockKC.save(dummyData, service: KeychainConstants.pendingSeKeyService(fingerprint: fp),
                        account: account, accessControl: nil)
        try mockKC.save(dummyData, service: KeychainConstants.pendingSaltService(fingerprint: fp),
                        account: account, accessControl: nil)
        try mockKC.save(dummyData, service: KeychainConstants.pendingSealedKeyService(fingerprint: fp),
                        account: account, accessControl: nil)

        // Run recovery
        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .cleanedPendingSafe)
        XCTAssertNil(try recoveryJournal().modifyExpiry)

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

        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        // Run recovery
        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .promotedPendingSafe)
        XCTAssertNil(try recoveryJournal().modifyExpiry)

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

        try privateKeyControlStore.clearModifyExpiryJournal()

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

        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .promotedPendingSafe)
        XCTAssertNil(try recoveryJournal().modifyExpiry)
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

        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .retryableFailure)
        XCTAssertEqual(try recoveryJournal().modifyExpiry?.fingerprint, fp)
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.pendingSeKeyService(fingerprint: fp), account: account))
    }

    func test_modifyExpiryCrashRecovery_unrecoverable_clearsFlags() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Unrecoverable Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        try mockKC.delete(service: KeychainConstants.saltService(fingerprint: fp), account: account)
        try mockKC.save(Data([0xAA]), service: KeychainConstants.pendingSeKeyService(fingerprint: fp),
                        account: account, accessControl: nil)

        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .unrecoverable)
        XCTAssertNil(try recoveryJournal().modifyExpiry)
    }

}
