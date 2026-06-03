import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class ProtectedSettingsDomainTests: ProtectedDataFrameworkTestCase {
    func test_protectedSettingsResetRequiresWrappingKeyBeforeDeletingWhenSentinelRemains() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSettingsResetPreflight")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.settings-reset-preflight.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-reset-preflight"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager
        )
        let capturedSharedSecret = AsyncDataBox()
        try await settingsStore.ensureCommittedAndMigrateSettingsIfNeeded(
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

    func test_protectedSettingsMigrationAuthorizationRequirementReflectsRegistryShape() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedSettingsMigrationRequirement")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-settings-migration-requirement.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-settings-migration-requirement"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        )

        XCTAssertEqual(settingsStore.migrationAuthorizationRequirement(), .notRequired)

        let privateKeyControlOnlyRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-settings-migration-requirement",
            sharedResourceLifecycleState: .ready,
            committedMembership: [ProtectedDataTestAppPrivateKeyControlStore.domainID: .active],
            pendingMutation: nil
        )
        try registryStore.saveRegistry(privateKeyControlOnlyRegistry)

        XCTAssertEqual(settingsStore.migrationAuthorizationRequirement(), .wrappingRootKeyRequired)

        let pendingRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-settings-migration-requirement",
            sharedResourceLifecycleState: .ready,
            committedMembership: [ProtectedDataTestAppPrivateKeyControlStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(pendingRegistry)

        XCTAssertEqual(settingsStore.migrationAuthorizationRequirement(), .frameworkRecoveryNeeded)
    }

    func test_protectedSettingsFreshInstallCreatesSchemaV2OrdinarySettingsPayload() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsFreshV2")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let payload = try await harness.store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let metadata = try ProtectedDomainBootstrapStore(
            storageRoot: harness.storageRoot
        ).loadMetadata(for: ProtectedSettingsStore.domainID)

        XCTAssertEqual(metadata?.schemaVersion, ProtectedSettingsStore.Payload.currentSchemaVersion)
        XCTAssertEqual(payload.ordinarySettings, .firstRunDefaults)

        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: harness.store
            )
        )
        coordinator.loadAfterAppAuthentication(availability: .available)

        XCTAssertEqual(coordinator.snapshot, .firstRunDefaults)
    }

    func test_protectedSettingsV1PayloadMigratesOrdinarySettingsAndCleansLegacyAfterVerifiedReadback() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsV1Migration")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let expectedSnapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: 300,
            hasCompletedOnboarding: true,
            colorTheme: .teal,
            encryptToSelf: false,
            guidedTutorialCompletedVersion: GuidedTutorialVersion.current
        )
        setLegacyOrdinarySettings(expectedSnapshot, defaults: harness.defaults)
        harness.defaults.set(true, forKey: AppConfiguration.clipboardNoticeLegacyKey)
        try writeProtectedSettingsEnvelope(
            payload: ProtectedSettingsPayloadV1(clipboardNotice: false),
            schemaVersion: 1,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: wrappingRootKey
        )

        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        let payload = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let metadata = try ProtectedDomainBootstrapStore(
            storageRoot: harness.storageRoot
        ).loadMetadata(for: ProtectedSettingsStore.domainID)

        XCTAssertEqual(metadata?.schemaVersion, ProtectedSettingsStore.Payload.currentSchemaVersion)
        XCTAssertEqual(payload.clipboardNotice, false)
        XCTAssertEqual(payload.ordinarySettings, expectedSnapshot)
        assertLegacyOrdinarySettingsRemoved(defaults: harness.defaults)
    }

    func test_protectedSettingsV2PayloadWinsOverConflictingLegacyOrdinarySettings() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsV2Authority")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        _ = try await harness.store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let protectedSnapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: 60,
            hasCompletedOnboarding: true,
            colorTheme: .pink,
            encryptToSelf: false,
            guidedTutorialCompletedVersion: GuidedTutorialVersion.current
        )
        try harness.store.updateOrdinarySettingsSnapshot(protectedSnapshot)
        try await harness.store.relockProtectedData()

        setLegacyOrdinarySettings(
            ProtectedOrdinarySettingsSnapshot(
                gracePeriod: 300,
                hasCompletedOnboarding: false,
                colorTheme: .orange,
                encryptToSelf: true,
                guidedTutorialCompletedVersion: 0
            ),
            defaults: harness.defaults
        )
        harness.defaults.set(false, forKey: AppConfiguration.clipboardNoticeLegacyKey)

        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        let payload = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)

        XCTAssertEqual(payload.clipboardNotice, true)
        XCTAssertEqual(payload.ordinarySettings, protectedSnapshot)
        assertLegacyOrdinarySettingsRemoved(defaults: harness.defaults)
    }

    func test_protectedSettingsCommittedUpgradeMissingWrappingKeyDoesNotPersistRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedMissingWrappingKey")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        _ = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: {
                throw ProtectedDataError.missingWrappingRootKey
            }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected committed settings upgrade to require the wrapping root key.")
        } catch ProtectedDataError.missingWrappingRootKey {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(reopenedStore.domainState, .locked)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .active
        )
    }

    func test_protectedSettingsCommittedUpgradePendingMutationDoesNotPersistRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedPendingMutation")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        var registry = try harness.registryStore.loadRegistry()
        registry.pendingMutation = .createDomain(
            targetDomainID: ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID,
            phase: .journaled
        )
        try harness.registryStore.saveRegistry(registry)
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected committed settings upgrade to stop for pending mutation.")
        } catch ProtectedDataError.invalidRegistry(_) {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(reopenedStore.domainState, .pendingRetryRequired)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .active
        )
    }

    func test_protectedSettingsCommittedUpgradeStorageReadFailureDoesNotPersistRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedStorageReadFailure")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        try writeProtectedSettingsEnvelope(
            payload: ProtectedSettingsStore.Payload(
                clipboardNotice: true,
                ordinarySettings: .firstRunDefaults
            ),
            schemaVersion: ProtectedSettingsStore.Payload.currentSchemaVersion,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: wrappingRootKey
        )
        let currentURL = harness.storageRoot.domainEnvelopeURL(
            for: ProtectedSettingsStore.domainID,
            slot: .current
        )
        let previousURL = harness.storageRoot.domainEnvelopeURL(
            for: ProtectedSettingsStore.domainID,
            slot: .previous
        )
        XCTAssertTrue(try harness.storageRoot.managedItemExists(at: previousURL))
        try FileManager.default.removeItem(at: currentURL)
        try FileManager.default.createDirectory(at: currentURL, withIntermediateDirectories: false)
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected committed settings upgrade to fail on storage read.")
        } catch ProtectedDataError.invalidEnvelope(_) {
            XCTFail("Storage read failure must not be folded into invalidEnvelope.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .frameworkUnavailable)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .active
        )
    }

    func test_protectedSettingsCommittedUpgradeWrappedDMKStorageReadFailureDoesNotPersistRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedWrappedDMKStorageReadFailure")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let wrappedDMKURL = harness.storageRoot.committedWrappedDomainMasterKeyURL(
            for: ProtectedSettingsStore.domainID
        )
        try FileManager.default.removeItem(at: wrappedDMKURL)
        try FileManager.default.createDirectory(at: wrappedDMKURL, withIntermediateDirectories: false)
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected committed settings upgrade to fail on wrapped DMK storage read.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .frameworkUnavailable)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .active
        )
    }

    func test_protectedSettingsCommittedUpgradeCorruptWrappedDMKPersistsRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedCorruptWrappedDMK")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        try harness.storageRoot.writeProtectedData(
            Data("not a plist wrapped DMK".utf8),
            to: harness.storageRoot.committedWrappedDomainMasterKeyURL(
                for: ProtectedSettingsStore.domainID
            )
        )
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected corrupt committed wrapped DMK to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .recoveryNeeded
        )
    }

    func test_protectedSettingsCommittedUpgradeCorruptPayloadPersistsRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedCorruptUpgrade")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        try writeProtectedSettingsEnvelope(
            payload: ProtectedSettingsPayloadV1(clipboardNotice: true),
            schemaVersion: ProtectedSettingsStore.Payload.currentSchemaVersion,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: wrappingRootKey
        )
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected corrupt committed settings payload to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .recoveryNeeded
        )
    }

    func test_protectedSettingsCorruptCommittedPayloadRequiresRecoveryAndLeavesLegacySources() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCorrupt")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let legacySnapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: 180,
            hasCompletedOnboarding: true,
            colorTheme: .graphite,
            encryptToSelf: false,
            guidedTutorialCompletedVersion: GuidedTutorialVersion.current
        )
        setLegacyOrdinarySettings(legacySnapshot, defaults: harness.defaults)
        harness.defaults.set(false, forKey: AppConfiguration.clipboardNoticeLegacyKey)
        try writeProtectedSettingsEnvelope(
            payload: ProtectedSettingsPayloadV1(clipboardNotice: true),
            schemaVersion: ProtectedSettingsStore.Payload.currentSchemaVersion,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: wrappingRootKey
        )

        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        do {
            _ = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
            XCTFail("Expected corrupt protected settings payload to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .recoveryNeeded
        )
        XCTAssertNotNil(harness.defaults.object(forKey: AppConfiguration.clipboardNoticeLegacyKey))
        XCTAssertNotNil(harness.defaults.object(forKey: ProtectedOrdinarySettingsLegacyKeys.gracePeriod))
    }

    func test_protectedSettingsOrdinaryMutationsPersistAcrossRelockAndReopen() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsMutationPersistence")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

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
        coordinator.setColorTheme(.teal)
        coordinator.setEncryptToSelf(false)
        coordinator.markGuidedTutorialCompletedCurrentVersion()
        let expectedSnapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: 300,
            hasCompletedOnboarding: true,
            colorTheme: .teal,
            encryptToSelf: false,
            guidedTutorialCompletedVersion: GuidedTutorialVersion.current
        )
        XCTAssertEqual(coordinator.snapshot, expectedSnapshot)

        try await harness.store.relockProtectedData()
        harness.domainKeyManager.clearUnlockedDomainMasterKeys()
        coordinator.relock()

        XCTAssertNil(harness.store.payload)
        XCTAssertNil(coordinator.snapshot)
        XCTAssertFalse(harness.domainKeyManager.hasUnlockedDomainMasterKeys)

        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
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

        let defaultsSuiteName = "com.cypherair.tests.protected-data.settings-reset-with-key.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-reset-with-key"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager,
            currentWrappingRootKey: {
                throw ProtectedDataError.missingWrappingRootKey
            }
        )
        let capturedSharedSecret = AsyncDataBox()
        try await settingsStore.ensureCommittedAndMigrateSettingsIfNeeded(
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
