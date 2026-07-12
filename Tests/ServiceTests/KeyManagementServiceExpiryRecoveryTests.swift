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

    func test_modifyExpiry_beginJournalFailure_leavesNoPendingBundleOrJournalEntry() async throws {
        // modifyExpiry journals first (beginModifyExpiry precedes the pending-bundle
        // write), so a begin-journal failure fails closed before any pending bundle
        // exists: the permanent envelope stays intact, no pending row is written, and
        // no journal entry is left behind. (The former "CleansPendingBundle" name
        // predated the journal-first ordering, when a pending row could exist first.)
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
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: identity.fingerprint),
            account: account
        ))
        XCTAssertFalse(localKeychain.exists(
            service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: identity.fingerprint),
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
            service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: identity.fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_modifyExpiryCrashRecovery_oldAndPendingExist_deletesPending() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Recovery Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        // Simulate interrupted modifyExpiry: write protected journal and store the pending
        // envelope while the old permanent envelope still exists.
        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        try mockKC.save(Data("pending-data".utf8),
                        service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fp),
                        account: account, accessControl: nil)

        // Run recovery
        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .cleanedPendingSafe)
        XCTAssertNil(try recoveryJournal().modifyExpiry)

        // Verify: pending envelope deleted
        XCTAssertFalse(mockKC.exists(service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fp),
                                     account: account),
                       "Pending envelope should be deleted")

        // Verify: original permanent envelope still intact
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp),
                                    account: account),
                      "Original private-key envelope should remain intact")
    }

    func test_modifyExpiryCrashRecovery_onlyPendingExists_promotesToPermanent() async throws {
        // Generate a key, then manually move its envelope to the pending row and delete the
        // permanent row to simulate a crash after deletion but before promotion.
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Promote Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        let envelopeData = try mockKC.load(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp), account: account)

        try mockKC.save(envelopeData, service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fp),
                        account: account, accessControl: nil)

        // Delete the permanent envelope (simulating the crash point)
        try mockKC.delete(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp), account: account)

        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        // Run recovery
        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .promotedPendingSafe)
        XCTAssertNil(try recoveryJournal().modifyExpiry)

        // Verify: permanent envelope restored from pending
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp),
                                    account: account),
                      "Envelope should be promoted to permanent")
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
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp),
                                    account: account))
    }

    // The former `_partialPermanentAndCompletePending_replacesPermanent` case was removed:
    // with the single-row envelope, a partially-present permanent bundle is impossible, so
    // that scenario collapses to `_onlyPendingExists_promotesToPermanent` above.

    func test_modifyExpiryCrashRecovery_retryableFailure_keepsFlags() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Retry Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        // Pending envelope present, permanent deleted → recovery must promote pending.
        try mockKC.save(Data([0xAA]), service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fp),
                        account: account, accessControl: nil)
        try mockKC.delete(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp), account: account)
        mockKC.failOnSaveNumber = mockKC.saveCallCount + 1

        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .retryableFailure)
        XCTAssertEqual(try recoveryJournal().modifyExpiry?.fingerprint, fp)
        XCTAssertTrue(mockKC.exists(service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fp), account: account))
    }

    func test_modifyExpiryCrashRecovery_unrecoverable_clearsFlags() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service, name: "Unrecoverable Test")
        let fp = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        // Neither permanent nor pending envelope present → unrecoverable.
        try mockKC.delete(service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fp), account: account)

        try privateKeyControlStore.beginModifyExpiry(fingerprint: fp)

        let outcome = service.checkAndRecoverFromInterruptedModifyExpiry()

        XCTAssertEqual(outcome, .unrecoverable)
        XCTAssertNil(try recoveryJournal().modifyExpiry)
    }

}
