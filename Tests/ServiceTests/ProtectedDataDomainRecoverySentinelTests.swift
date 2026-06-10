import CryptoKit
import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class ProtectedDataDomainRecoverySentinelTests: ProtectedDataFrameworkTestCase {
    func test_privateKeyControl_emptyRegistryRequiresHandoffContext() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("PrivateKeyControlNoHandoff"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.private-key-control.no-handoff"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let defaultsSuiteName = "com.cypherair.tests.private-key-control.no-handoff.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        defaults.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.authModeKey)
        let store = ProtectedDataTestAppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        )

        let created = try await store.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
            authenticationContext: nil,
            persistSharedRight: { _ in XCTFail("Root secret must not be persisted without a handoff context") }
        )

        XCTAssertFalse(created)
        XCTAssertNil(try registryStore.loadRegistry().committedMembership[ProtectedDataTestAppPrivateKeyControlStore.domainID])
        XCTAssertEqual(defaults.string(forKey: AuthPreferences.authModeKey), AuthenticationMode.highSecurity.rawValue)
        XCTAssertEqual(store.privateKeyControlState, .locked)
    }

    func test_privateKeyControl_emptyRegistryCreatesFirstDomainAndMigratesLegacyJournal() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("PrivateKeyControlFirstDomain"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.private-key-control.first"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let defaultsSuiteName = "com.cypherair.tests.private-key-control.first.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        defaults.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.authModeKey)
        defaults.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        defaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)
        defaults.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        defaults.set("abc123", forKey: AuthPreferences.modifyExpiryFingerprintKey)
        let store = ProtectedDataTestAppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }
        let persistedSecretBox = AsyncDataBox()

        let created = try await store.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
            authenticationContext: handoffContext,
            persistSharedRight: { secret in await persistedSecretBox.set(secret) }
        )

        XCTAssertTrue(created)
        XCTAssertEqual(try registryStore.loadRegistry().committedMembership[ProtectedDataTestAppPrivateKeyControlStore.domainID], .active)
        XCTAssertNil(defaults.string(forKey: AuthPreferences.authModeKey))
        XCTAssertFalse(defaults.bool(forKey: AuthPreferences.rewrapInProgressKey))
        XCTAssertNil(defaults.string(forKey: AuthPreferences.rewrapTargetModeKey))
        XCTAssertFalse(defaults.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))
        XCTAssertNil(defaults.string(forKey: AuthPreferences.modifyExpiryFingerprintKey))

        var rootSecret = await persistedSecretBox.data()
        XCTAssertFalse(rootSecret.isEmpty)
        let wrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()
        let payload = try await store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)

        XCTAssertEqual(payload.settings.authMode, .highSecurity)
        XCTAssertEqual(payload.recoveryJournal.rewrapTargetMode, .standard)
        XCTAssertEqual(payload.recoveryJournal.modifyExpiry?.fingerprint, "abc123")
        XCTAssertEqual(try store.requireUnlockedAuthMode(), .highSecurity)
    }

    func test_realComponents_privateKeyControlFirstLeavesSettingsCreationNeedingAuthorizedSessionAfterRestart() async throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave is required for the real ProtectedData root-secret store.")
        }

        let baseDirectory = makeTemporaryDirectory("RealProtectedDataPrivateKeyControlFirst")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }
        let account = "com.cypherair.tests.real-components.\(UUID().uuidString)"
        let sharedRightIdentifier = "com.cypherair.tests.real-components.shared-right.\(UUID().uuidString)"
        let systemKeychain = SystemKeychain()
        let formatFloorStore = ProtectedDataRootSecretFormatFloorStore(
            keychain: systemKeychain,
            account: account
        )
        let deviceBindingProvider = HardwareProtectedDataDeviceBindingProvider(
            keychain: systemKeychain,
            account: account
        )
        let rootSecretStore = KeychainProtectedDataRootSecretStore(
            account: account,
            supportKeychain: systemKeychain,
            deviceBindingProvider: deviceBindingProvider,
            formatFloorStore: formatFloorStore
        )
        defer {
            try? rootSecretStore.deleteRootSecret(identifier: sharedRightIdentifier)
            try? formatFloorStore.deleteMarker()
            try? systemKeychain.delete(
                service: KeychainConstants.protectedDataDeviceBindingKeyService,
                account: account,
                authenticationContext: nil
            )
        }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: sharedRightIdentifier
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)

        let defaultsSuiteName = "com.cypherair.tests.real-components.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        let privateKeyControlStore = ProtectedDataTestAppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager
        )
        let initialSessionCoordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: sharedRightIdentifier
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }

        let created = try await privateKeyControlStore.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
            authenticationContext: handoffContext,
            persistSharedRight: { secret in
                try await initialSessionCoordinator.persistSharedRight(secretData: secret)
            }
        )

        XCTAssertTrue(created)
        XCTAssertTrue(initialSessionCoordinator.hasPersistedRootSecret(identifier: sharedRightIdentifier))
        XCTAssertEqual(
            try registryStore.loadRegistry().committedMembership[ProtectedDataTestAppPrivateKeyControlStore.domainID],
            .active
        )

        let restartedSessionCoordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: sharedRightIdentifier
        )
        let settingsStore = CypherAir.ProtectedSettingsStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try restartedSessionCoordinator.wrappingRootKeyData()
            }
        )

        do {
            try await settingsStore.ensureCommittedIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("A second ProtectedData domain must reuse the existing shared root.")
                }
            )
            XCTFail("Expected settings domain creation to require an authorized wrapping root key after restart.")
        } catch ProtectedDataError.missingWrappingRootKey {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func test_privateKeyControl_pendingMutationFailsClosed() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("PrivateKeyControlPending"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.private-key-control.pending"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.private-key-control.pending",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)
        let defaultsSuiteName = "com.cypherair.tests.private-key-control.pending.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        let store = ProtectedDataTestAppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        )

        do {
            try await store.ensureCommittedIfNeeded(wrappingRootKey: Data(repeating: 0xC1, count: 32))
            XCTFail("Expected pending mutation to block private-key-control creation.")
        } catch PrivateKeyControlError.recoveryNeeded {
        } catch {
            XCTFail("Expected recoveryNeeded, got \(error)")
        }
        XCTAssertEqual(store.privateKeyControlState, .recoveryNeeded)
    }

    func test_frameworkSentinel_doesNotCreateFirstDomainFromEmptyRegistry() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataSentinelEmpty"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.sentinel.empty"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let sentinelStore = ProtectedDataTestAppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        )

        try await sentinelStore.ensureCommittedIfNeeded(
            wrappingRootKey: Data(repeating: 0xE1, count: 32)
        )

        let registry = try registryStore.loadRegistry()
        XCTAssertTrue(registry.committedMembership.isEmpty)
        XCTAssertNil(registry.pendingMutation)
        XCTAssertEqual(registry.sharedResourceLifecycleState, .absent)
    }

    func test_postUnlockCoordinator_emptyRegistryWithSentinelOpenerDoesNotReadRootSecret() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataSentinelEmptyPostUnlock"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let registry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: "com.cypherair.tests.protected-data.sentinel.empty-post-unlock"
        )
        let rootSecretStore = MockProtectedDataRightStoreClient()
        let sessionCoordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: registry.sharedRightIdentifier
        )
        let coordinator = ProtectedDataTestAppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                ProtectedDataTestAppProtectedDataPostUnlockDomainOpener(
                    domainID: ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID,
                    ensureCommittedIfNeeded: { _ in XCTFail("Sentinel should not be created for an empty registry.") },
                    open: { _ in XCTFail("Sentinel should not open for an empty registry.") }
                )
            ]
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }

        let outcome = await coordinator.openRegisteredDomains(
            authenticationContext: handoffContext,
            localizedReason: "Open protected domains",
            source: "unitTest"
        )

        XCTAssertEqual(outcome, .noProtectedDomainPresent)
        XCTAssertEqual(rootSecretStore.rightLookupCallCount, 0)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionLocked)
    }

    func test_authorization_missingRight_returnsFrameworkRecoveryNeeded() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationMissingRight"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.missing"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.missing",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xD1, count: 32), for: "contacts")

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )

        XCTAssertEqual(result, .frameworkRecoveryNeeded)
        XCTAssertEqual(coordinator.frameworkState, .frameworkRecoveryNeeded)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
    }

    func test_authorization_legacyMigrationDeferredClearsUnlockedDomainKeys() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationDeferredMigration"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.deferred-migration"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.deferred-migration",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xD3, count: 32), for: "contacts")

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data",
            allowLegacyMigration: false
        )

        XCTAssertEqual(result, .cancelledOrDenied)
        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
    }

    func test_authorization_secretUnreadable_returnsFrameworkRecoveryNeededAndDeauthorizes() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationUnreadableSecret"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let handle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.authorization.secret",
            secretData: Data(repeating: 0xAE, count: 32)
        )
        handle.rawSecretError = ProtectedDataError.internalFailure("secret unreadable")
        rightStoreClient.persistedRightHandle = handle
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.secret"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.secret",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xD2, count: 32), for: "contacts")

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )

        XCTAssertEqual(result, .frameworkRecoveryNeeded)
        XCTAssertEqual(coordinator.frameworkState, .frameworkRecoveryNeeded)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
    }

    func test_authorization_mockKeychainCancellationFailures_returnCancelledOrDenied() async throws {
        let cases: [(suffix: String, error: MockKeychainError)] = [
            ("user-cancelled", .userCancelled),
            ("authentication-failed", .authenticationFailed),
            ("interaction-not-allowed", .interactionNotAllowed),
        ]

        for testCase in cases {
            let sharedRightIdentifier = "com.cypherair.tests.protected-data.authorization.mock-\(testCase.suffix)"
            let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
                baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationMock-\(testCase.suffix)")
            )
            let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
            let rootSecretStore = ProtectedDataTestAppMockProtectedDataRootSecretStore()
            try rootSecretStore.saveRootSecret(
                Data(repeating: 0xB0, count: 32),
                identifier: sharedRightIdentifier,
                policy: .userPresence
            )
            rootSecretStore.loadError = testCase.error
            let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
                rootSecretStore: rootSecretStore,
                domainKeyManager: keyManager,
                sharedRightIdentifier: sharedRightIdentifier
            )
            let registry = ProtectedDataRegistry(
                formatVersion: ProtectedDataRegistry.currentFormatVersion,
                sharedRightIdentifier: sharedRightIdentifier,
                sharedResourceLifecycleState: .ready,
                committedMembership: ["contacts": .active],
                pendingMutation: nil
            )
            keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xD4, count: 32), for: "contacts")

            let result = await coordinator.beginProtectedDataAuthorization(
                registry: registry,
                localizedReason: "Authorize protected data"
            )

            XCTAssertEqual(result, .cancelledOrDenied, "case: \(testCase.suffix)")
            XCTAssertEqual(coordinator.frameworkState, .sessionLocked, "case: \(testCase.suffix)")
            XCTAssertFalse(coordinator.hasActiveWrappingRootKey, "case: \(testCase.suffix)")
            XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys, "case: \(testCase.suffix)")
        }
    }

    func test_authorization_userCancelled_returnsCancelledOrDenied() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationCancelled"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let handle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.authorization.cancelled",
            secretData: Data(repeating: 0xAF, count: 32)
        )
        handle.authorizeError = AuthenticationError.cancelled
        rightStoreClient.persistedRightHandle = handle
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.cancelled"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.cancelled",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )

        XCTAssertEqual(result, .cancelledOrDenied)
        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
    }

    func test_pendingRecovery_firstDomainCreateWithoutReady_returnsResetRequired() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataPendingCreateReset")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.pending-create"
        )
        let recoveryCoordinator = ProtectedDataTestAppProtectedDomainRecoveryCoordinator(registryStore: registryStore)
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.pending-create",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .artifactsStaged
            )
        )
        try registryStore.saveRegistry(registry)

        XCTAssertEqual(recoveryCoordinator.pendingRecoveryAuthorizationRequirement(), .notRequired)

        let outcome = try await registryStore.recoverPendingMutation(
            targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
            continueDelete: { _ in }
        )

        XCTAssertEqual(outcome, ProtectedDataTestAppPendingRecoveryOutcome.resetRequired)
    }

    func test_recoveryCoordinator_dispatchesPendingDeleteToDomainHandler() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataGenericRecoveryDelete")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let domainID: ProtectedDataDomainID = "generic-domain"
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.generic-recovery"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.generic-recovery",
            sharedResourceLifecycleState: .cleanupPending,
            committedMembership: [:],
            pendingMutation: .deleteDomain(
                targetDomainID: domainID,
                phase: .membershipRemoved
            )
        )
        try registryStore.saveRegistry(registry)

        let handler = MockProtectedDomainRecoveryHandler(domainID: domainID)
        let cleanupCalled = AsyncBooleanFlag()
        let recoveryCoordinator = ProtectedDataTestAppProtectedDomainRecoveryCoordinator(registryStore: registryStore)

        let outcome = try await recoveryCoordinator.recoverPendingMutation(
            handler: handler,
            removeSharedRight: { identifier in
                XCTAssertEqual(identifier, registry.sharedRightIdentifier)
                await cleanupCalled.setTrue()
            }
        )

        XCTAssertEqual(outcome, .resumedToSteadyState)
        XCTAssertEqual(handler.deleteArtifactsCallCount, 1)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertTrue(didCleanup)
        XCTAssertNil(try registryStore.loadRegistry().pendingMutation)
    }

    func test_recoveryCoordinator_targetMismatchReturnsFrameworkRecoveryNeeded() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataGenericRecoveryMismatch")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.generic-recovery-mismatch"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.generic-recovery-mismatch",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: "other-domain",
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)

        let handler = MockProtectedDomainRecoveryHandler(domainID: "generic-domain")
        let recoveryCoordinator = ProtectedDataTestAppProtectedDomainRecoveryCoordinator(registryStore: registryStore)

        let outcome = try await recoveryCoordinator.recoverPendingMutation(
            handler: handler,
            removeSharedRight: { _ in }
        )

        XCTAssertEqual(outcome, .frameworkRecoveryNeeded)
        XCTAssertEqual(handler.deleteArtifactsCallCount, 0)
        XCTAssertTrue(handler.continuedCreatePhases.isEmpty)
    }

    func test_protectedSettings_surfacesSentinelPendingCreateAsRetryable() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSettingsSentinelPending")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-sentinel-pending"
        )
        let defaultsSuiteName = "com.cypherair.tests.protected-data.settings-sentinel-pending.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        let protectedSettingsStore = ProtectedSettingsStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-sentinel-pending",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)

        protectedSettingsStore.syncPreAuthorizationState()

        XCTAssertEqual(protectedSettingsStore.domainState, .pendingRetryRequired)
        do {
            _ = try await protectedSettingsStore.openDomainIfNeeded(
                wrappingRootKey: Data(repeating: 0xC1, count: 32)
            )
            XCTFail("Protected settings must not open while sentinel recovery is pending.")
        } catch {
            XCTAssertEqual(protectedSettingsStore.domainState, .pendingRetryRequired)
        }
    }

    func test_recoveryCoordinator_handlerListDispatchesByPendingDomainID() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataHandlerListRecovery")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.handler-list"
        )
        let wrappingRootKey = Data(repeating: 0xA4, count: 32)
        let sentinelStore = ProtectedDataTestAppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot),
            currentWrappingRootKey: { wrappingRootKey }
        )
        let mismatchedHandler = MockProtectedDomainRecoveryHandler(domainID: "other-domain")
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.handler-list",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)
        let recoveryCoordinator = ProtectedDataTestAppProtectedDomainRecoveryCoordinator(registryStore: registryStore)

        XCTAssertEqual(
            recoveryCoordinator.pendingRecoveryAuthorizationRequirement(),
            .wrappingRootKeyRequired
        )

        let outcome = try await recoveryCoordinator.recoverPendingMutation(
            handlers: [
                mismatchedHandler,
                sentinelStore
            ],
            removeSharedRight: { _ in
                XCTFail("Second-domain create recovery must not remove the shared root.")
            }
        )
        let recoveredRegistry = try registryStore.loadRegistry()

        XCTAssertEqual(outcome, .resumedToSteadyState)
        XCTAssertEqual(recoveredRegistry.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertEqual(recoveredRegistry.committedMembership[ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID], .active)
        XCTAssertNil(recoveredRegistry.pendingMutation)
        XCTAssertEqual(mismatchedHandler.deleteArtifactsCallCount, 0)
        XCTAssertTrue(mismatchedHandler.continuedCreatePhases.isEmpty)
        XCTAssertTrue(try storageRoot.managedItemExists(
            at: storageRoot.committedWrappedDomainMasterKeyURL(
                for: ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID
            )
        ))
    }
}
