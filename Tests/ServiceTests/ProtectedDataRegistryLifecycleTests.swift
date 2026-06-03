import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class ProtectedDataRegistryLifecycleTests: ProtectedDataFrameworkTestCase {
    func test_registryBootstrap_withoutRootOrArtifacts_bootstrapsEmptySteadyState() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataBootstrap")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let store = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.bootstrap"
        )

        let result = try store.performSynchronousBootstrap()
        let registry = try store.loadRegistry()

        guard case .emptySteadyState(let bootstrappedRegistry, let didBootstrap) = result.bootstrapOutcome else {
            return XCTFail("Expected empty steady-state bootstrap outcome, got \(result.bootstrapOutcome)")
        }
        XCTAssertEqual(result.frameworkState, .sessionLocked)
        XCTAssertTrue(didBootstrap)
        XCTAssertTrue(FileManager.default.fileExists(atPath: storageRoot.registryURL.path))
        XCTAssertEqual(bootstrappedRegistry, registry)
        XCTAssertEqual(registry.committedMembership, [:])
        XCTAssertEqual(registry.sharedResourceLifecycleState, .absent)
        XCTAssertNil(registry.pendingMutation)
    }

    func test_registryBootstrap_missingRegistryWithArtifacts_entersFrameworkRecoveryNeeded() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataArtifacts")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        try FileManager.default.createDirectory(at: storageRoot.rootURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: storageRoot.domainDirectory(for: "synthetic-domain"),
            withIntermediateDirectories: true
        )

        let store = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.artifacts"
        )

        let result = try store.performSynchronousBootstrap()

        XCTAssertEqual(result.bootstrapOutcome, .frameworkRecoveryNeeded)
        XCTAssertEqual(result.frameworkState, .frameworkRecoveryNeeded)
        XCTAssertFalse(FileManager.default.fileExists(atPath: storageRoot.registryURL.path))
    }

    func test_registryBootstrap_loadedRegistry_preservesContinuePendingMutationDisposition() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataPendingMutation")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let store = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.pending"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.pending",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(targetDomainID: "contacts", phase: .journaled)
        )
        try store.saveRegistry(registry)

        let result = try store.performSynchronousBootstrap()

        guard case .loadedRegistry(let loadedRegistry, let recoveryDisposition) = result.bootstrapOutcome else {
            return XCTFail("Expected loaded registry bootstrap outcome, got \(result.bootstrapOutcome)")
        }
        XCTAssertEqual(loadedRegistry, registry)
        XCTAssertEqual(recoveryDisposition, .continuePendingMutation)
        XCTAssertEqual(result.frameworkState, .sessionLocked)
    }

    func test_firstDomainCleanupRunsAfterCreateJournalBeforeProvisioning() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataFirstDomainCleanupOrder")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.first-domain-cleanup-order"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let rootSecretProbe = ProtectedDataRootSecretCleanupProbe(exists: true)
        let cleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { _ in rootSecretProbe.rootSecretExists() },
            removePersistedSharedRight: { _ in rootSecretProbe.removeRootSecret() }
        )
        let domainID: ProtectedDataDomainID = "first-domain"

        let registry = try await registryStore.performCreateDomainTransaction(
            domainID: domainID,
            cleanupJournaledFirstDomainSharedRightIfNeeded: {
                rootSecretProbe.record("cleanup")
                let journaledRegistry = try registryStore.loadRegistry()
                XCTAssertEqual(
                    journaledRegistry.pendingMutation,
                    .createDomain(targetDomainID: domainID, phase: .journaled)
                )
                let outcome = try await cleaner.cleanupJournaledFirstDomainSharedRightIfSafe(
                    expectedDomainID: domainID,
                    source: "unitTest",
                    loadCurrentRegistry: {
                        let currentRegistry = try registryStore.loadRegistry()
                        XCTAssertEqual(currentRegistry, journaledRegistry)
                        return currentRegistry
                    }
                )
                XCTAssertEqual(outcome, .removedOrphanedSharedRight)
            },
            provisionSharedResourceIfNeeded: {
                rootSecretProbe.provisionRootSecret()
            },
            stageArtifacts: {},
            validateArtifacts: {}
        )

        let snapshot = rootSecretProbe.snapshot()
        XCTAssertTrue(snapshot.exists)
        XCTAssertEqual(snapshot.events, ["cleanup", "exists", "remove", "provision"])
        XCTAssertEqual(registry.committedMembership[domainID], .active)
        XCTAssertEqual(registry.sharedResourceLifecycleState, .ready)
        XCTAssertNil(registry.pendingMutation)
    }

    func test_firstDomainSharedRightCleaner_abortsWhenCurrentRegistryHasCommittedMembership() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataFirstDomainCleanupCommitted")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let rootSecretProbe = ProtectedDataRootSecretCleanupProbe(exists: true)
        let cleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { _ in rootSecretProbe.rootSecretExists() },
            removePersistedSharedRight: { _ in rootSecretProbe.removeRootSecret() }
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.first-domain-cleanup-committed",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["committed-domain": .active],
            pendingMutation: nil
        )

        let outcome = try await cleaner.cleanupJournaledFirstDomainSharedRightIfSafe(
            expectedDomainID: "committed-domain",
            source: "unitTest",
            loadCurrentRegistry: { registry }
        )

        let snapshot = rootSecretProbe.snapshot()
        XCTAssertEqual(outcome, .notNeeded)
        XCTAssertTrue(snapshot.exists)
        XCTAssertFalse(snapshot.events.contains("remove"))
    }

    func test_firstDomainSharedRightCleaner_abortsWhenCurrentRegistryHasUnrelatedPendingMutation() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataFirstDomainCleanupPending")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let rootSecretProbe = ProtectedDataRootSecretCleanupProbe(exists: true)
        let cleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { _ in rootSecretProbe.rootSecretExists() },
            removePersistedSharedRight: { _ in rootSecretProbe.removeRootSecret() }
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.first-domain-cleanup-pending",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: "other-domain",
                phase: .journaled
            )
        )

        let outcome = try await cleaner.cleanupJournaledFirstDomainSharedRightIfSafe(
            expectedDomainID: "requested-domain",
            source: "unitTest",
            loadCurrentRegistry: { registry }
        )

        let snapshot = rootSecretProbe.snapshot()
        XCTAssertEqual(outcome, .notNeeded)
        XCTAssertTrue(snapshot.exists)
        XCTAssertFalse(snapshot.events.contains("remove"))
    }

    func test_firstDomainSharedRightCleaner_doesNotDeleteRootSecretFromConcurrentPendingCreate() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataFirstDomainCleanupConcurrent")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let rootSecretProbe = ProtectedDataRootSecretCleanupProbe(exists: true)
        let cleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { _ in rootSecretProbe.rootSecretExists() },
            removePersistedSharedRight: { _ in rootSecretProbe.removeRootSecret() }
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.first-domain-cleanup-concurrent",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: "first-domain-in-progress",
                phase: .sharedResourceProvisioned
            )
        )

        let outcome = try await cleaner.cleanupJournaledFirstDomainSharedRightIfSafe(
            expectedDomainID: "competing-first-domain",
            source: "unitTest",
            loadCurrentRegistry: { registry }
        )

        let snapshot = rootSecretProbe.snapshot()
        XCTAssertEqual(outcome, .notNeeded)
        XCTAssertTrue(snapshot.exists)
        XCTAssertFalse(snapshot.events.contains("remove"))
    }


    func test_secondDomainDeletePreservesSharedRootUntilLastDomainIsRemoved() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSecondDomainDelete")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.second-domain-delete"
        )
        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let wrappingRootKey = Data(repeating: 0xB4, count: 32)
        let sentinelStore = ProtectedDataTestAppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.second-domain-delete",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: nil
        )
        try registryStore.saveRegistry(registry)
        try await sentinelStore.ensureCommittedIfNeeded(wrappingRootKey: wrappingRootKey)

        let secondDomainCleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.performDeleteDomainTransaction(
            domainID: ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID,
            deleteArtifacts: {
                try sentinelStore.deleteDomainArtifactsForRecovery()
            },
            cleanupSharedResourceIfNeeded: {
                await secondDomainCleanupCalled.setTrue()
            }
        )
        let afterSecondDomainDelete = try registryStore.loadRegistry()

        XCTAssertEqual(afterSecondDomainDelete.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertNil(afterSecondDomainDelete.committedMembership[ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID])
        XCTAssertEqual(afterSecondDomainDelete.sharedResourceLifecycleState, .ready)
        XCTAssertNil(afterSecondDomainDelete.pendingMutation)
        let didRunSecondDomainCleanup = await secondDomainCleanupCalled.currentValue()
        XCTAssertFalse(didRunSecondDomainCleanup)

        let lastDomainCleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.performDeleteDomainTransaction(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {},
            cleanupSharedResourceIfNeeded: {
                await lastDomainCleanupCalled.setTrue()
            }
        )
        let afterLastDomainDelete = try registryStore.loadRegistry()

        XCTAssertTrue(afterLastDomainDelete.committedMembership.isEmpty)
        XCTAssertEqual(afterLastDomainDelete.sharedResourceLifecycleState, .absent)
        XCTAssertNil(afterLastDomainDelete.pendingMutation)
        let didRunLastDomainCleanup = await lastDomainCleanupCalled.currentValue()
        XCTAssertTrue(didRunLastDomainCleanup)
    }


    func test_abandonPendingCreate_clearsPendingMutationAndArtifacts() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonPendingCreate")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.abandon-create.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-create"
        )
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager
        )

        try storageRoot.ensureDomainDirectoryExists(for: CypherAir.ProtectedSettingsStore.domainID)
        try storageRoot.writeProtectedData(
            Data("staged".utf8),
            to: storageRoot.domainEnvelopeURL(
                for: CypherAir.ProtectedSettingsStore.domainID,
                slot: .pending
            )
        )

        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-create",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .artifactsStaged
            )
        )
        try registryStore.saveRegistry(registry)

        _ = try await registryStore.abandonPendingCreate(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {
                try settingsStore.deleteDomainArtifactsForRecovery()
            },
            cleanupSharedResourceIfNeeded: {}
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        XCTAssertFalse(
            try storageRoot.managedItemExists(
                at: storageRoot.domainEnvelopeURL(
                    for: CypherAir.ProtectedSettingsStore.domainID,
                    slot: .pending
                )
            )
        )
    }

    func test_abandonPendingCreate_membershipCommittedLastDomainCleansSharedResource() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonCommittedCreate")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-committed-create"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-committed-create",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .membershipCommitted
            )
        )
        try registryStore.saveRegistry(registry)

        let cleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.abandonPendingCreate(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {},
            cleanupSharedResourceIfNeeded: {
                await cleanupCalled.setTrue()
            }
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertTrue(clearedRegistry.committedMembership.isEmpty)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertTrue(didCleanup)
    }

    func test_abandonPendingCreate_cleanupFailureLeavesPendingMutation() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonCleanupFailure")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.abandon-cleanup-failure.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-cleanup-failure"
        )
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-cleanup-failure",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .membershipCommitted
            )
        )
        try registryStore.saveRegistry(registry)
        try storageRoot.ensureDomainDirectoryExists(for: CypherAir.ProtectedSettingsStore.domainID)
        let currentEnvelopeURL = storageRoot.domainEnvelopeURL(
            for: CypherAir.ProtectedSettingsStore.domainID,
            slot: .current
        )
        try storageRoot.writeProtectedData(Data("current".utf8), to: currentEnvelopeURL)

        do {
            _ = try await registryStore.abandonPendingCreate(
                domainID: CypherAir.ProtectedSettingsStore.domainID,
                deleteArtifacts: {
                    try settingsStore.deleteDomainArtifactsForRecovery()
                },
                cleanupSharedResourceIfNeeded: {
                    throw ProtectedDataError.internalFailure("Injected cleanup failure.")
                }
            )
            XCTFail("Expected shared-resource cleanup failure to fail closed.")
        } catch ProtectedDataError.internalFailure {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        let retainedRegistry = try registryStore.loadRegistry()
        XCTAssertEqual(
            retainedRegistry.pendingMutation,
            .deleteDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .sharedResourceCleanupStarted
            )
        )
        XCTAssertEqual(retainedRegistry.sharedResourceLifecycleState, .cleanupPending)
        XCTAssertTrue(retainedRegistry.committedMembership.isEmpty)
        XCTAssertFalse(try storageRoot.managedItemExists(at: currentEnvelopeURL))

        let cleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.completePendingDelete(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {
                try settingsStore.deleteDomainArtifactsForRecovery()
            },
            cleanupSharedResourceIfNeeded: {
                await cleanupCalled.setTrue()
            }
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        XCTAssertTrue(clearedRegistry.committedMembership.isEmpty)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertTrue(didCleanup)
    }

    func test_abandonPendingCreate_preMembershipCleanupFailurePreservesArtifacts() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonPreMembershipCleanupFailure")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.abandon-pre-membership-cleanup-failure.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-pre-membership-cleanup-failure"
        )
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-pre-membership-cleanup-failure",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .artifactsStaged
            )
        )
        try registryStore.saveRegistry(registry)
        try storageRoot.ensureDomainDirectoryExists(for: CypherAir.ProtectedSettingsStore.domainID)
        let pendingEnvelopeURL = storageRoot.domainEnvelopeURL(
            for: CypherAir.ProtectedSettingsStore.domainID,
            slot: .pending
        )
        try storageRoot.writeProtectedData(Data("pending".utf8), to: pendingEnvelopeURL)
        let deleteCalled = AsyncBooleanFlag()

        do {
            _ = try await registryStore.abandonPendingCreate(
                domainID: CypherAir.ProtectedSettingsStore.domainID,
                deleteArtifacts: {
                    await deleteCalled.setTrue()
                    try settingsStore.deleteDomainArtifactsForRecovery()
                },
                cleanupSharedResourceIfNeeded: {
                    throw ProtectedDataError.internalFailure("Injected cleanup failure.")
                }
            )
            XCTFail("Expected shared-resource cleanup failure to fail closed.")
        } catch ProtectedDataError.internalFailure {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        let retainedRegistry = try registryStore.loadRegistry()
        XCTAssertEqual(retainedRegistry.pendingMutation, registry.pendingMutation)
        XCTAssertEqual(retainedRegistry.sharedResourceLifecycleState, .absent)
        XCTAssertTrue(retainedRegistry.committedMembership.isEmpty)
        XCTAssertTrue(try storageRoot.managedItemExists(at: pendingEnvelopeURL))
        let didDelete = await deleteCalled.currentValue()
        XCTAssertFalse(didDelete)
    }

    func test_abandonPendingCreate_journaledFirstDomainDoesNotRequireSharedCleanup() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonJournaledCreate")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-journaled-create"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-journaled-create",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)

        let cleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.abandonPendingCreate(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {},
            cleanupSharedResourceIfNeeded: {
                await cleanupCalled.setTrue()
            }
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertFalse(didCleanup)
    }


    func test_completePendingDelete_clearsCleanupPendingAndPendingMutation() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataCompletePendingDelete")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.complete-delete.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.complete-delete"
        )
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager
        )

        try storageRoot.ensureDomainDirectoryExists(for: CypherAir.ProtectedSettingsStore.domainID)
        try storageRoot.writeProtectedData(
            Data("current".utf8),
            to: storageRoot.domainEnvelopeURL(
                for: CypherAir.ProtectedSettingsStore.domainID,
                slot: .current
            )
        )

        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.complete-delete",
            sharedResourceLifecycleState: .cleanupPending,
            committedMembership: [:],
            pendingMutation: .deleteDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .membershipRemoved
            )
        )
        try registryStore.saveRegistry(registry)

        let cleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.completePendingDelete(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {
                try settingsStore.deleteDomainArtifactsForRecovery()
            },
            cleanupSharedResourceIfNeeded: {
                await cleanupCalled.setTrue()
            }
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertTrue(didCleanup)
        XCTAssertFalse(
            try storageRoot.managedItemExists(
                at: storageRoot.domainEnvelopeURL(
                    for: CypherAir.ProtectedSettingsStore.domainID,
                    slot: .current
                )
            )
        )
    }
}
