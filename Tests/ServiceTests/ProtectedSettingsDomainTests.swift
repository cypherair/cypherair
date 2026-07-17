import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class ProtectedSettingsDomainTests: ProtectedDataFrameworkTestCase {
    func test_protectedSettingsResetRequiresWrappingKeyBeforeDeletingWhenSentinelRemains() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSettingsResetPreflight")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-reset-preflight"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let settingsStore = CypherAir.ProtectedSettingsStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager
        )
        let capturedSharedSecret = AsyncDataBox()
        try await settingsStore.ensureCommittedIfNeeded(
            persistSharedRight: { secret in
                await capturedSharedSecret.set(secret)
            }
        )
        var rootSecret = await capturedSharedSecret.data()
        let wrappingRootKey = try keyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()

        let sentinelStore = ProtectedDataTestAppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        try await sentinelStore.ensureCommittedIfNeeded(wrappingRootKey: wrappingRootKey)
        let currentEnvelopeURL = storageRoot.domainEnvelopeURL(
            for: CypherAir.ProtectedSettingsStore.domainID,
            slot: .current
        )

        XCTAssertEqual(settingsStore.resetAuthorizationRequirement(), .wrappingRootKeyRequired)
        do {
            try await settingsStore.resetDomain(
                persistSharedRight: { _ in
                    XCTFail("Second-domain settings reset must not create a new shared root.")
                },
                removeSharedRight: { _ in
                    XCTFail("Second-domain settings reset must not remove the shared root.")
                },
                currentWrappingRootKey: {
                    throw ProtectedDataError.missingWrappingRootKey
                }
            )
            XCTFail("Expected reset to fail before deleting settings without a wrapping key.")
        } catch ProtectedDataError.missingWrappingRootKey {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        let retainedRegistry = try registryStore.loadRegistry()
        XCTAssertEqual(retainedRegistry.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertEqual(retainedRegistry.committedMembership[ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID], .active)
        XCTAssertNil(retainedRegistry.pendingMutation)
        XCTAssertTrue(try storageRoot.managedItemExists(at: currentEnvelopeURL))
    }

    func test_protectedSettingsFreshInstallCreatesSchemaV2OrdinarySettingsPayload() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsFreshV2")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let payload = try await harness.store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)

        XCTAssertEqual(payload.clipboardNotice, true)
        XCTAssertEqual(payload.ordinarySettings, .firstRunDefaults)

        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: harness.store
            )
        )
        coordinator.loadAfterAppAuthentication(availability: .available)

        XCTAssertEqual(coordinator.snapshot, .firstRunDefaults)
    }

    func test_protectedSettingsEnsureCommittedIsNoOpWhenDomainAlreadyCommitted() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsEnsureCommittedNoOp")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let generationURL = harness.storageRoot.domainEnvelopeURL(
            for: ProtectedSettingsStore.domainID,
            slot: .current
        )
        let committedEnvelopeData = try harness.storageRoot.readManagedData(at: generationURL)

        try await harness.store.ensureCommittedIfNeeded(
            persistSharedRight: { _ in
                XCTFail("Ensure-committed on a committed settings domain must not provision a new shared right.")
            },
            currentWrappingRootKey: {
                XCTFail("Ensure-committed on a committed settings domain must not request the wrapping root key.")
                throw ProtectedDataError.missingWrappingRootKey
            }
        )

        XCTAssertEqual(harness.store.domainState, .locked)
        XCTAssertNil(harness.store.payload)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .active
        )
        XCTAssertEqual(try harness.storageRoot.readManagedData(at: generationURL), committedEnvelopeData)

        let payload = try await harness.store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        XCTAssertEqual(payload, .initial)
    }

    func test_protectedSettingsCorruptCommittedPayloadFailsClosedAndRequiresRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCorruptPayload")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        try writeProtectedSettingsEnvelope(
            payload: ["corrupt": "not-a-protected-settings-payload"],
            schemaVersion: ProtectedSettingsStore.Payload.currentSchemaVersion,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: wrappingRootKey
        )

        let reopenedStore = ProtectedSettingsStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        do {
            _ = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
            XCTFail("Expected corrupt protected settings payload to fail closed.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertNil(reopenedStore.payload)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .recoveryNeeded
        )
    }

    func test_protectedSettingsCorruptWrappedDomainMasterKeyFailsClosedAndRequiresRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCorruptWrappedDMK")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        try harness.keychain.update(
            Data("not a plist wrapped DMK".utf8),
            service: KeychainConstants.protectedDataDomainKeyService(domainID: ProtectedSettingsStore.domainID),
            account: KeychainConstants.defaultAccount,
            authenticationContext: nil
        )

        let reopenedStore = ProtectedSettingsStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        do {
            _ = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
            XCTFail("Expected corrupt wrapped domain master key to fail closed.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertNil(reopenedStore.payload)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .recoveryNeeded
        )
    }

    func test_protectedSettingsMissingWrappedDomainMasterKeyFailsClosedAndRequiresRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsMissingWrappedDMK")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        try harness.domainKeyManager.deleteWrappedDomainMasterKeyRecords(for: ProtectedSettingsStore.domainID)

        let reopenedStore = ProtectedSettingsStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        do {
            _ = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
            XCTFail("Expected missing wrapped domain master key to fail closed.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertNil(reopenedStore.payload)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .recoveryNeeded
        )
    }

    func test_protectedSettingsOrdinaryMutationsPersistAcrossRelockAndReopen() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsMutationPersistence")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        _ = try await harness.store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: harness.store
            )
        )
        coordinator.loadAfterAppAuthentication(availability: .available)

        coordinator.setGracePeriod(300)
        coordinator.setHasCompletedOnboarding(true)
        coordinator.setEncryptToSelf(false)
        coordinator.markGuidedTutorialCompleted()
        let expectedSnapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: 300,
            hasCompletedOnboarding: true,
            encryptToSelf: false,
            hasCompletedGuidedTutorial: true
        )
        XCTAssertEqual(coordinator.snapshot, expectedSnapshot)

        try await harness.store.relockProtectedData()
        harness.domainKeyManager.clearUnlockedDomainMasterKeys()
        coordinator.relock()

        XCTAssertNil(harness.store.payload)
        XCTAssertNil(coordinator.snapshot)
        XCTAssertFalse(harness.domainKeyManager.hasUnlockedDomainMasterKeys)

        let reopenedStore = ProtectedSettingsStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        _ = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let reloadedCoordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: reopenedStore
            )
        )
        reloadedCoordinator.loadAfterAppAuthentication(availability: .available)

        XCTAssertEqual(reloadedCoordinator.snapshot, expectedSnapshot)
    }

    func test_protectedSettingsResetRecreatesWithWrappingKeyWhenSentinelRemains() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSettingsResetWithKey")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-reset-with-key"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let settingsStore = CypherAir.ProtectedSettingsStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager,
            currentWrappingRootKey: {
                throw ProtectedDataError.missingWrappingRootKey
            }
        )
        let capturedSharedSecret = AsyncDataBox()
        try await settingsStore.ensureCommittedIfNeeded(
            persistSharedRight: { secret in
                await capturedSharedSecret.set(secret)
            }
        )
        var rootSecret = await capturedSharedSecret.data()
        let wrappingRootKey = try keyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()

        let sentinelStore = ProtectedDataTestAppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        try await sentinelStore.ensureCommittedIfNeeded(wrappingRootKey: wrappingRootKey)

        try await settingsStore.resetDomain(
            persistSharedRight: { _ in
                XCTFail("Second-domain settings reset must not create a new shared root.")
            },
            removeSharedRight: { _ in
                XCTFail("Second-domain settings reset must not remove the shared root.")
            },
            currentWrappingRootKey: {
                wrappingRootKey
            }
        )

        let resetRegistry = try registryStore.loadRegistry()
        XCTAssertEqual(resetRegistry.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertEqual(resetRegistry.committedMembership[ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID], .active)
        XCTAssertNil(resetRegistry.pendingMutation)
        XCTAssertTrue(try storageRoot.managedItemExists(
            at: storageRoot.domainEnvelopeURL(
                for: CypherAir.ProtectedSettingsStore.domainID,
                slot: .current
            )
        ))
    }
}
