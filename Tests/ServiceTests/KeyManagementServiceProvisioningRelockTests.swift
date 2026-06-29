import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceProvisioningRelockTests: KeyManagementServiceTestCase {

    func test_generateKey_invalidatedBeforeProvisioning_doesNotPersistBundleOrMetadata() async throws {
        let checkpointGate = ProvisioningCheckpointGate()
        let target = makeCheckpointedProvisioningService {
            await checkpointGate.suspend()
        }
        let targetService = target.service

        let generationTask = Task { [targetService] in
            try await targetService.generateKey(
                name: "Reset Race",
                email: "reset-race@example.com",
                expirySeconds: nil,
                profile: .universal
            )
        }

        await waitUntil("key generation provisioning checkpoint") {
            await checkpointGate.isSuspended()
        }

        targetService.resetInMemoryStateAfterLocalDataReset()
        await checkpointGate.resume()

        do {
            _ = try await generationTask.value
            XCTFail("Expected invalidated key generation to cancel")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }

        XCTAssertTrue(targetService.keys.isEmpty)
        try assertNoProvisionedKeyMaterial(
            in: target.keychain,
            metadataPersistence: target.metadataPersistence
        )
    }

    func test_generateKey_invalidatedBeforeAuthModeRead_doesNotPersistBundleOrMetadata() async throws {
        let checkpointGate = ProvisioningCheckpointGate()
        let target = makeRecordingMetadataService(
            beforeAuthModeReadCheckpoint: {
                await checkpointGate.suspend()
            }
        )
        let targetService = target.service

        let generationTask = Task { [targetService] in
            try await targetService.generateKey(
                name: "Relock Before Auth Mode",
                email: "relock-before-auth-mode@example.com",
                expirySeconds: nil,
                profile: .universal
            )
        }

        await waitUntil("key generation auth-mode checkpoint") {
            await checkpointGate.isSuspended()
        }

        try await targetService.relockProtectedData()
        await checkpointGate.resume()

        do {
            _ = try await generationTask.value
            XCTFail("Expected invalidated key generation to cancel before auth mode read")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }

        XCTAssertEqual(targetService.metadataLoadState, .locked)
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertEqual(target.metadataPersistence.saveCallCount, 0)
        try assertNoProvisionedKeyMaterial(
            in: target.keychain,
            metadataPersistence: target.metadataPersistence
        )
    }

    func test_generateKey_invalidatedAfterProvisioningBeforeSync_doesNotRepublishCatalogKeys() async throws {
        let checkpointGate = ProvisioningCheckpointGate()
        let target = makePostProvisioningCheckpointedService {
            await checkpointGate.suspend()
        }
        let targetService = target.service

        let generationTask = Task { [targetService] in
            try await targetService.generateKey(
                name: "Relock Race",
                email: "relock-race@example.com",
                expirySeconds: nil,
                profile: .universal
            )
        }

        await waitUntil("key generation post-provisioning checkpoint") {
            await checkpointGate.isSuspended()
        }

        try await targetService.relockProtectedData()
        XCTAssertEqual(targetService.metadataLoadState, .locked)
        XCTAssertTrue(targetService.keys.isEmpty)

        await checkpointGate.resume()

        do {
            _ = try await generationTask.value
            XCTFail("Expected invalidated key generation to cancel")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }

        XCTAssertEqual(targetService.metadataLoadState, .locked)
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertEqual(target.metadataPersistence.saveCallCount, 1)
    }

    func test_generateKey_cancelledAfterProvisioningBeforeSync_stillSyncsCommittedIdentity() async throws {
        let checkpointGate = ProvisioningCheckpointGate()
        let target = makePostProvisioningCheckpointedService {
            await checkpointGate.suspend()
        }
        let targetService = target.service

        let generationTask = Task { [targetService] in
            try await targetService.generateKey(
                name: "Cancelled After Commit",
                email: "cancelled-after-commit@example.com",
                expirySeconds: nil,
                profile: .universal
            )
        }

        await waitUntil("key generation post-provisioning cancellation checkpoint") {
            await checkpointGate.isSuspended()
        }

        generationTask.cancel()
        await checkpointGate.resume()

        let generated = try await generationTask.value

        XCTAssertEqual(targetService.keys.map(\.fingerprint), [generated.fingerprint])
        XCTAssertEqual(target.metadataPersistence.identities.map(\.fingerprint), [generated.fingerprint])
        XCTAssertEqual(target.metadataPersistence.saveCallCount, 1)
    }

    func test_generateKey_relockWaitsForBundleCommitAndRollsBackNewBundle() async throws {
        let bundleStoreGate = ProvisioningCheckpointGate()
        let waiterRegisteredGate = ProvisioningCheckpointGate()
        let target = makeRecordingMetadataService(
            afterPermanentBundleStoreCheckpoint: {
                await bundleStoreGate.suspend()
            },
            commitDrainWaiterRegisteredCheckpoint: {
                await waiterRegisteredGate.suspend()
            }
        )
        let targetService = target.service

        let generationTask = Task { [targetService] in
            try await targetService.generateKey(
                name: "Relock During Bundle Commit",
                email: "relock-during-bundle-commit@example.com",
                expirySeconds: nil,
                profile: .universal
            )
        }

        await waitUntil("key generation permanent bundle checkpoint") {
            await bundleStoreGate.isSuspended()
        }

        XCTAssertEqual(target.metadataPersistence.saveCallCount, 0)
        XCTAssertEqual(
            try target.keychain.listItems(
                servicePrefix: KeychainConstants.prefix,
                account: KeychainConstants.defaultAccount
            ).count,
            1
        )

        let relockTask = Task { [targetService] in
            try await targetService.relockProtectedData()
        }
        await waitUntil("key generation commit-drain waiter") {
            await waiterRegisteredGate.isSuspended()
        }

        await waiterRegisteredGate.resume()
        await bundleStoreGate.resume()

        do {
            _ = try await generationTask.value
            XCTFail("Expected invalidated key generation to cancel during bundle commit")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }
        try await relockTask.value

        XCTAssertEqual(targetService.metadataLoadState, .locked)
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertEqual(target.metadataPersistence.saveCallCount, 0)
        try assertNoProvisionedKeyMaterial(
            in: target.keychain,
            metadataPersistence: target.metadataPersistence
        )
    }

    func test_importKey_invalidatedBeforeAuthModeRead_doesNotPersistBundleOrMetadata() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: service,
            name: "Import Before Auth Mode Source"
        )
        let passphrase = "import-before-auth-mode-passphrase"
        var exportedData = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        defer {
            exportedData.resetBytes(in: 0..<exportedData.count)
        }
        let checkpointGate = ProvisioningCheckpointGate()
        let target = makeRecordingMetadataService(
            beforeAuthModeReadCheckpoint: {
                await checkpointGate.suspend()
            }
        )
        let targetService = target.service

        let importTask = Task { [targetService, exportedData] in
            try await targetService.importKey(
                armoredData: exportedData,
                passphrase: passphrase
            )
        }

        await waitUntil("key import auth-mode checkpoint") {
            await checkpointGate.isSuspended()
        }

        try await targetService.relockProtectedData()
        await checkpointGate.resume()

        do {
            _ = try await importTask.value
            XCTFail("Expected invalidated key import to cancel before auth mode read")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }

        XCTAssertEqual(targetService.metadataLoadState, .locked)
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertEqual(target.metadataPersistence.saveCallCount, 0)
        try assertNoProvisionedKeyMaterial(
            in: target.keychain,
            metadataPersistence: target.metadataPersistence
        )
    }

    func test_importKey_invalidatedAfterOffMainImportBeforeDuplicateLookup_prioritizesCancellation() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: service,
            name: "Import Duplicate Race Source"
        )
        let passphrase = "import-duplicate-race-passphrase"
        var exportedData = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        defer {
            exportedData.resetBytes(in: 0..<exportedData.count)
        }
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.seed([identity])
        let importReturnGate = ProvisioningCheckpointGate()
        let relockInvalidationGate = ProvisioningCheckpointGate()
        let target = makeRecordingMetadataService(
            metadataPersistence: metadataPersistence,
            afterImportOffMainActorCheckpoint: {
                await importReturnGate.suspend()
            },
            relockInvalidationCheckpoint: {
                await relockInvalidationGate.suspend()
            }
        )
        let targetService = target.service
        try targetService.loadKeys()
        XCTAssertEqual(targetService.keys.map(\.fingerprint), [identity.fingerprint])

        let importTask = Task { [targetService, exportedData] in
            try await targetService.importKey(
                armoredData: exportedData,
                passphrase: passphrase
            )
        }

        await waitUntil("key import off-main return checkpoint") {
            await importReturnGate.isSuspended()
        }

        let relockTask = Task { [targetService] in
            try await targetService.relockProtectedData()
        }
        await waitUntil("key import relock invalidation checkpoint") {
            await relockInvalidationGate.isSuspended()
        }

        await importReturnGate.resume()
        do {
            _ = try await importTask.value
            XCTFail("Expected invalidated key import to cancel before duplicate lookup")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }

        await relockInvalidationGate.resume()
        try await relockTask.value

        XCTAssertEqual(targetService.metadataLoadState, .locked)
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertEqual(metadataPersistence.identities.map(\.fingerprint), [identity.fingerprint])
        XCTAssertEqual(metadataPersistence.saveCallCount, 0)
        XCTAssertEqual(metadataPersistence.deleteCallCount, 0)
        try assertNoPrivateKeyMaterial(in: target.keychain)
    }

    func test_importKey_existingPersistenceMetadataButUnloadedCatalog_keepsExistingMetadataAndRollsBackNewBundle() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: service,
            name: "Existing Metadata"
        )
        let passphrase = "existing-metadata-passphrase"
        var exportedData = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        defer {
            exportedData.resetBytes(in: 0..<exportedData.count)
        }
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.seed([identity])
        let target = makeRecordingMetadataService(metadataPersistence: metadataPersistence)

        do {
            _ = try await target.service.importKey(
                armoredData: exportedData,
                passphrase: passphrase
            )
            XCTFail("Expected duplicate persisted metadata to reject import")
        } catch RecordingKeyMetadataPersistenceError.duplicateIdentity {
            // Expected.
        } catch {
            XCTFail("Expected duplicate metadata error, got \(error)")
        }

        XCTAssertEqual(metadataPersistence.identities.map(\.fingerprint), [identity.fingerprint])
        XCTAssertEqual(metadataPersistence.saveCallCount, 1)
        XCTAssertEqual(metadataPersistence.deleteCallCount, 0)
        try assertNoPrivateKeyMaterial(in: target.keychain)
    }

    func test_importKey_existingPermanentBundleButUnloadedCatalog_keepsExistingBundle() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: service,
            name: "Existing Bundle"
        )
        let passphrase = "existing-bundle-passphrase"
        var exportedData = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        defer {
            exportedData.resetBytes(in: 0..<exportedData.count)
        }
        let target = makeRecordingMetadataService()
        try copyPermanentBundle(
            fingerprint: identity.fingerprint,
            from: mockKC,
            to: target.keychain
        )
        let bundleStore = KeyBundleStore(keychain: target.keychain)
        let originalBundle = try bundleStore.loadBundle(fingerprint: identity.fingerprint)

        do {
            _ = try await target.service.importKey(
                armoredData: exportedData,
                passphrase: passphrase
            )
            XCTFail("Expected duplicate keychain bundle to reject import")
        } catch {
            // Expected.
        }

        let storedBundle = try bundleStore.loadBundle(fingerprint: identity.fingerprint)
        XCTAssertEqual(storedBundle.envelope, originalBundle.envelope)
        XCTAssertEqual(target.metadataPersistence.saveCallCount, 0)
        XCTAssertEqual(target.metadataPersistence.deleteCallCount, 0)
    }

    func test_generateKey_metadataSaveFailure_rollsBackNewBundleWithoutDeletingMetadata() async throws {
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.failNextSave = true
        let target = makeRecordingMetadataService(metadataPersistence: metadataPersistence)

        do {
            _ = try await target.service.generateKey(
                name: "Save Failure",
                email: "save-failure@example.com",
                expirySeconds: nil,
                profile: .universal
            )
            XCTFail("Expected metadata save failure")
        } catch RecordingKeyMetadataPersistenceError.saveFailed {
            // Expected.
        } catch {
            XCTFail("Expected metadata save failure, got \(error)")
        }

        XCTAssertTrue(metadataPersistence.identities.isEmpty)
        XCTAssertEqual(metadataPersistence.saveCallCount, 1)
        XCTAssertEqual(metadataPersistence.deleteCallCount, 0)
        try assertNoPrivateKeyMaterial(in: target.keychain)
    }

    func test_generateKey_invalidatedAfterIdentityStore_rollsBackOnlyNewIdentityAndBundle() async throws {
        let existing = try await TestHelpers.generateProfileBKey(
            service: service,
            name: "Existing Unrelated"
        )
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.seed([existing])
        let checkpointGate = ProvisioningCheckpointGate()
        let relockInvalidationGate = ProvisioningCheckpointGate()
        let target = makeRecordingMetadataService(
            metadataPersistence: metadataPersistence,
            identityStoreCheckpoint: {
                await checkpointGate.suspend()
            },
            relockInvalidationCheckpoint: {
                await relockInvalidationGate.suspend()
            }
        )
        try copyPermanentBundle(
            fingerprint: existing.fingerprint,
            from: mockKC,
            to: target.keychain
        )
        let targetService = target.service

        let generationTask = Task { [targetService] in
            try await targetService.generateKey(
                name: "Cancelled After Metadata",
                email: "cancelled-after-metadata@example.com",
                expirySeconds: nil,
                profile: .universal
            )
        }

        await waitUntil("key generation identity-store checkpoint") {
            await checkpointGate.isSuspended()
        }
        XCTAssertEqual(metadataPersistence.saveCallCount, 1)
        XCTAssertEqual(Set(metadataPersistence.identities.map(\.fingerprint)).count, 2)

        let relockTask = Task { [targetService] in
            try await targetService.relockProtectedData()
        }
        await waitUntil("key generation relock invalidation checkpoint") {
            await relockInvalidationGate.isSuspended()
        }
        await relockInvalidationGate.resume()
        await checkpointGate.resume()

        do {
            _ = try await generationTask.value
            XCTFail("Expected invalidated key generation to cancel")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }
        try await relockTask.value

        XCTAssertEqual(metadataPersistence.identities.map(\.fingerprint), [existing.fingerprint])
        XCTAssertEqual(metadataPersistence.deleteCallCount, 1)
        let bundleStore = KeyBundleStore(keychain: target.keychain)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: existing.fingerprint, namespace: .permanent),
            .complete
        )
        let privateKeyServices = try target.keychain.listItems(
            servicePrefix: KeychainConstants.prefix,
            account: KeychainConstants.defaultAccount
        )
        XCTAssertEqual(
            Set(privateKeyServices),
            Set([
                KeychainConstants.privateKeyEnvelopeService(fingerprint: existing.fingerprint)
            ])
        )
    }

    func test_generateKey_metadataDiscardFailureAfterIdentityStore_preservesNewBundle() async throws {
        let existing = try await TestHelpers.generateProfileBKey(
            service: service,
            name: "Existing Metadata Discard Failure"
        )
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.seed([existing])
        metadataPersistence.failNextDelete = true
        let checkpointGate = ProvisioningCheckpointGate()
        let relockInvalidationGate = ProvisioningCheckpointGate()
        let target = makeRecordingMetadataService(
            metadataPersistence: metadataPersistence,
            identityStoreCheckpoint: {
                await checkpointGate.suspend()
            },
            relockInvalidationCheckpoint: {
                await relockInvalidationGate.suspend()
            }
        )
        try copyPermanentBundle(
            fingerprint: existing.fingerprint,
            from: mockKC,
            to: target.keychain
        )
        let targetService = target.service

        let generationTask = Task { [targetService] in
            try await targetService.generateKey(
                name: "Discard Failure",
                email: "discard-failure@example.com",
                expirySeconds: nil,
                profile: .universal
            )
        }

        await waitUntil("key generation identity-store checkpoint") {
            await checkpointGate.isSuspended()
        }
        let newFingerprint = try XCTUnwrap(
            metadataPersistence.identities.first { $0.fingerprint != existing.fingerprint }?.fingerprint
        )

        let relockTask = Task { [targetService] in
            try await targetService.relockProtectedData()
        }
        await waitUntil("key generation relock invalidation checkpoint") {
            await relockInvalidationGate.isSuspended()
        }
        await relockInvalidationGate.resume()
        await checkpointGate.resume()

        do {
            _ = try await generationTask.value
            XCTFail("Expected metadata discard failure to be surfaced")
        } catch RecordingKeyMetadataPersistenceError.deleteFailed {
            // Expected.
        } catch {
            XCTFail("Expected metadata delete failure, got \(error)")
        }
        try await relockTask.value

        XCTAssertEqual(metadataPersistence.deleteCallCount, 1)
        XCTAssertEqual(
            Set(metadataPersistence.identities.map(\.fingerprint)),
            Set([existing.fingerprint, newFingerprint])
        )
        let bundleStore = KeyBundleStore(keychain: target.keychain)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: existing.fingerprint, namespace: .permanent),
            .complete
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: newFingerprint, namespace: .permanent),
            .complete
        )
    }

    func test_generateKey_realProtectedDataRelockAfterIdentityStore_doesNotLeaveOrphanedMetadata() async throws {
        guard try supportsCompleteProtectedFileCreation() else {
            throw XCTSkip("Complete file protection is unavailable in this macOS test sandbox.")
        }

        let checkpointGate = ProvisioningCheckpointGate()
        let relockInvalidationGate = ProvisioningCheckpointGate()
        let target = try await makeProtectedKeyMetadataProvisioningTarget(
            identityStoreCheckpoint: {
                await checkpointGate.suspend()
            },
            relockInvalidationCheckpoint: {
                await relockInvalidationGate.suspend()
            }
        )
        defer {
            try? FileManager.default.removeItem(at: target.baseDirectory)
            UserDefaults(suiteName: target.defaultsSuiteName)?
                .removePersistentDomain(forName: target.defaultsSuiteName)
        }

        let generationTask = Task { [keyManagement = target.keyManagement] in
            try await keyManagement.generateKey(
                name: "Protected Relock Race",
                email: "protected-relock-race@example.com",
                expirySeconds: nil,
                profile: .universal
            )
        }

        await waitUntil("protected key metadata identity-store checkpoint") {
            await checkpointGate.isSuspended()
        }
        let storedDuringCommit = try target.keyMetadataStore.loadAll()
        let orphanCandidate = try XCTUnwrap(storedDuringCommit.first)
        XCTAssertEqual(storedDuringCommit.count, 1)

        let relockTask = Task { [coordinator = target.protectedDataSessionCoordinator] in
            await coordinator.relockCurrentSession()
        }
        await waitUntil("protected-data relock invalidation checkpoint") {
            await relockInvalidationGate.isSuspended()
        }
        await relockInvalidationGate.resume()
        await checkpointGate.resume()

        do {
            _ = try await generationTask.value
            XCTFail("Expected invalidated protected key generation to cancel")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }
        await relockTask.value

        let reopenedPayload = try await target.keyMetadataStore.openDomainIfNeeded(
            wrappingRootKey: target.wrappingRootKey
        )
        XCTAssertEqual(reopenedPayload.identities, [])
        XCTAssertEqual(
            KeyBundleStore(keychain: target.keychain).bundleState(
                fingerprint: orphanCandidate.fingerprint,
                namespace: .permanent
            ),
            .missing
        )
    }

    func test_importKey_invalidatedBeforeProvisioning_doesNotPersistBundleOrMetadata() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: service,
            name: "Import Source"
        )
        let passphrase = "import-reset-passphrase"
        let exportedData = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        let checkpointGate = ProvisioningCheckpointGate()
        let target = makeCheckpointedProvisioningService {
            await checkpointGate.suspend()
        }
        let targetService = target.service

        let importTask = Task { [targetService] in
            try await targetService.importKey(
                armoredData: exportedData,
                passphrase: passphrase
            )
        }

        await waitUntil("key import provisioning checkpoint") {
            await checkpointGate.isSuspended()
        }

        try await targetService.relockProtectedData()
        await checkpointGate.resume()

        do {
            _ = try await importTask.value
            XCTFail("Expected invalidated key import to cancel")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }

        XCTAssertTrue(targetService.keys.isEmpty)
        try assertNoProvisionedKeyMaterial(
            in: target.keychain,
            metadataPersistence: target.metadataPersistence
        )
    }

    func test_importKey_invalidatedAfterProvisioningBeforeSync_doesNotRepublishCatalogKeys() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: service,
            name: "Import Post Source"
        )
        let passphrase = "import-post-race-passphrase"
        var exportedData = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        defer {
            exportedData.resetBytes(in: 0..<exportedData.count)
        }
        let checkpointGate = ProvisioningCheckpointGate()
        let target = makePostProvisioningCheckpointedService {
            await checkpointGate.suspend()
        }
        let targetService = target.service

        let importTask = Task { [targetService, exportedData] in
            try await targetService.importKey(
                armoredData: exportedData,
                passphrase: passphrase
            )
        }

        await waitUntil("key import post-provisioning checkpoint") {
            await checkpointGate.isSuspended()
        }

        try await targetService.relockProtectedData()
        XCTAssertEqual(targetService.metadataLoadState, .locked)
        XCTAssertTrue(targetService.keys.isEmpty)

        await checkpointGate.resume()

        do {
            _ = try await importTask.value
            XCTFail("Expected invalidated key import to cancel")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }

        XCTAssertEqual(targetService.metadataLoadState, .locked)
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertEqual(target.metadataPersistence.saveCallCount, 1)
    }

    func test_importKey_cancelledAfterProvisioningBeforeSync_stillSyncsCommittedIdentity() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: service,
            name: "Import Cancel Source"
        )
        let passphrase = "import-cancel-after-commit-passphrase"
        var exportedData = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: passphrase
        )
        defer {
            exportedData.resetBytes(in: 0..<exportedData.count)
        }
        let checkpointGate = ProvisioningCheckpointGate()
        let target = makePostProvisioningCheckpointedService {
            await checkpointGate.suspend()
        }
        let targetService = target.service

        let importTask = Task { [targetService, exportedData] in
            try await targetService.importKey(
                armoredData: exportedData,
                passphrase: passphrase
            )
        }

        await waitUntil("key import post-provisioning cancellation checkpoint") {
            await checkpointGate.isSuspended()
        }

        importTask.cancel()
        await checkpointGate.resume()

        let imported = try await importTask.value

        XCTAssertEqual(targetService.keys.map(\.fingerprint), [imported.fingerprint])
        XCTAssertEqual(target.metadataPersistence.identities.map(\.fingerprint), [imported.fingerprint])
        XCTAssertEqual(target.metadataPersistence.saveCallCount, 1)
    }

}
