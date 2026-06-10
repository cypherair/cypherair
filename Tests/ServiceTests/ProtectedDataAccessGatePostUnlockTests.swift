import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class ProtectedDataAccessGatePostUnlockTests: ProtectedDataFrameworkTestCase {
    func test_accessGateClassifier_classifiesBootstrapAndSessionStates() throws {
        let sharedRightIdentifier = "com.cypherair.tests.protected-data.gate.classifier"
        let emptyRegistry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: sharedRightIdentifier
        )
        let pendingRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: sharedRightIdentifier,
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(targetDomainID: "contacts", phase: .journaled)
        )
        let readyRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: sharedRightIdentifier,
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        XCTAssertEqual(
            ProtectedDataTestAppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .emptySteadyState(registry: emptyRegistry, didBootstrap: false),
                frameworkState: .sessionLocked
            ),
            .noProtectedDomainPresent
        )
        XCTAssertEqual(
            ProtectedDataTestAppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: pendingRegistry, recoveryDisposition: .continuePendingMutation),
                frameworkState: .sessionLocked
            ),
            .pendingMutationRecoveryRequired
        )
        XCTAssertEqual(
            ProtectedDataTestAppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: readyRegistry, recoveryDisposition: .frameworkRecoveryNeeded),
                frameworkState: .sessionLocked
            ),
            .frameworkRecoveryNeeded
        )
        XCTAssertEqual(
            ProtectedDataTestAppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: readyRegistry, recoveryDisposition: .resumeSteadyState),
                frameworkState: .sessionLocked
            ),
            .authorizationRequired(registry: readyRegistry)
        )
        XCTAssertEqual(
            ProtectedDataTestAppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: readyRegistry, recoveryDisposition: .resumeSteadyState),
                frameworkState: .sessionAuthorized
            ),
            .alreadyAuthorized(registry: readyRegistry)
        )
        XCTAssertEqual(
            ProtectedDataTestAppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: readyRegistry, recoveryDisposition: .resumeSteadyState),
                frameworkState: .restartRequired
            ),
            .frameworkRecoveryNeeded
        )
    }

    func test_accessGateClassifier_afterFirstAccessReloadsCurrentRegistry() throws {
        let sharedRightIdentifier = "com.cypherair.tests.protected-data.gate.classifier-reload"
        let startupRegistry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: sharedRightIdentifier
        )
        let currentRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: sharedRightIdentifier,
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        var currentRegistryLookupCount = 0
        let classifier = ProtectedDataTestAppProtectedDataAccessGateClassifier(
            currentRegistryProvider: {
                currentRegistryLookupCount += 1
                return currentRegistry
            },
            frameworkStateProvider: { .sessionLocked }
        )

        let decision = classifier.evaluate(
            startupBootstrapOutcome: .emptySteadyState(registry: startupRegistry, didBootstrap: true),
            isFirstProtectedAccessInCurrentProcess: false
        )

        XCTAssertEqual(currentRegistryLookupCount, 1)
        XCTAssertEqual(decision, .authorizationRequired(registry: currentRegistry))
    }

    func test_accessGateClassifier_currentRegistryLookupFailureFailsClosed() throws {
        let sharedRightIdentifier = "com.cypherair.tests.protected-data.gate.classifier-failure"
        let startupRegistry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: sharedRightIdentifier
        )
        let classifier = ProtectedDataTestAppProtectedDataAccessGateClassifier(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Registry unavailable")
            },
            frameworkStateProvider: { .sessionAuthorized }
        )

        let decision = classifier.evaluate(
            startupBootstrapOutcome: .emptySteadyState(registry: startupRegistry, didBootstrap: true),
            isFirstProtectedAccessInCurrentProcess: false
        )

        XCTAssertEqual(decision, .frameworkRecoveryNeeded)
    }

    func test_accessGate_emptySteadyState_returnsNoProtectedDomainPresent() throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessEmpty"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.empty"
        )
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("Should not be called") },
            protectedDataSessionCoordinator: coordinator
        )
        let registry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.empty"
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .emptySteadyState(registry: registry, didBootstrap: false),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .noProtectedDomainPresent)
        XCTAssertEqual(rightStoreClient.loadCallCount, 0)
    }

    func test_accessGate_continuePendingMutation_returnsPendingMutationRecoveryRequired() throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessPending"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.pending"
        )
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("Should not be called") },
            protectedDataSessionCoordinator: coordinator
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.pending",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(targetDomainID: "contacts", phase: .journaled)
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .continuePendingMutation),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .pendingMutationRecoveryRequired)
        XCTAssertEqual(rightStoreClient.loadCallCount, 0)
    }

    func test_accessGate_readyRegistryWithoutAuthorization_requiresAuthorization() throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessAuth"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.auth"
        )
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("Should not be called") },
            protectedDataSessionCoordinator: coordinator
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.auth",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        guard case .authorizationRequired(let authorizationRegistry) = decision else {
            return XCTFail("Expected authorizationRequired gate decision, got \(decision)")
        }
        XCTAssertEqual(authorizationRegistry, registry)
    }

    func test_accessGate_readyRegistryWithAuthorizedSession_returnsAlreadyAuthorized() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessAlreadyAuthorized"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        rightStoreClient.seedRootSecret(Data(repeating: 0xAD, count: 32), identifier: "com.cypherair.tests.protected-data.gate.reuse")
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.reuse"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.reuse",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )
        XCTAssertEqual(authorizationResult, .authorized)

        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: coordinator
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        guard case .alreadyAuthorized(let reusedRegistry) = decision else {
            return XCTFail("Expected alreadyAuthorized gate decision, got \(decision)")
        }
        XCTAssertEqual(reusedRegistry, registry)
    }

    func test_accessGate_readyRegistryWithLatchedFrameworkRecovery_returnsFrameworkRecoveryNeeded() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessFrameworkRecovery"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.framework-recovery"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.framework-recovery",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Trigger framework recovery"
        )
        XCTAssertEqual(authorizationResult, .frameworkRecoveryNeeded)
        XCTAssertEqual(coordinator.frameworkState, .frameworkRecoveryNeeded)

        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: coordinator
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .frameworkRecoveryNeeded)
    }

    func test_accessGate_readyRegistryWithRestartRequired_returnsFrameworkRecoveryNeeded() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessRestartRequired"))
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        rightStoreClient.seedRootSecret(Data(repeating: 0xB0, count: 32), identifier: "com.cypherair.tests.protected-data.gate.restart-required")
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.restart-required"
        )
        let participant = MockProtectedDataRelockParticipant()
        participant.shouldThrow = true
        coordinator.registerRelockParticipant(participant)
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.restart-required",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )
        XCTAssertEqual(authorizationResult, .authorized)
        await coordinator.relockCurrentSession()
        XCTAssertEqual(coordinator.frameworkState, .restartRequired)

        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: coordinator
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .frameworkRecoveryNeeded)
    }

    func test_postUnlockCoordinator_opensCommittedRegisteredDomainWithHandoffContext() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockOpen"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        rightStoreClient.seedRootSecret(Data(repeating: 0xCA, count: 32), identifier: "com.cypherair.tests.protected-data.post-unlock.open")
        let sessionCoordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.open"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.open",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: nil
        )
        let openCalled = AsyncBooleanFlag()
        let coordinator = ProtectedDataTestAppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                ProtectedDataTestAppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { wrappingRootKey in
                        XCTAssertEqual(wrappingRootKey.count, 32)
                        await openCalled.setTrue()
                    }
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

        XCTAssertEqual(outcome, .opened([CypherAir.ProtectedSettingsStore.domainID]))
        let didOpen = await openCalled.currentValue()
        XCTAssertTrue(didOpen)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionAuthorized)
        XCTAssertTrue(rightStoreClient.lastAuthenticationContext === handoffContext)
        XCTAssertTrue(handoffContext.interactionNotAllowed)
    }

    func test_postUnlockCoordinator_withoutContextDoesNotAuthorize() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockNoContext"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        let sessionCoordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.no-context"
        )
        let coordinator = ProtectedDataTestAppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: {
                XCTFail("Registry should not load without an authenticated context.")
                return ProtectedDataRegistry.emptySteadyState(sharedRightIdentifier: "unused")
            },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                ProtectedDataTestAppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { _ in XCTFail("Domain should not open without an authenticated context.") }
                )
            ]
        )

        let outcome = await coordinator.openRegisteredDomains(
            authenticationContext: nil,
            localizedReason: "Open protected domains",
            source: "unitTest"
        )

        XCTAssertEqual(outcome, .noAuthenticatedContext)
        XCTAssertEqual(rightStoreClient.loadCallCount, 0)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionLocked)
    }

    func test_postUnlockCoordinator_pendingMutationDoesNotOpenDomain() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockPending"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        let sessionCoordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.pending"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.pending",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .journaled
            )
        )
        let openCalled = AsyncBooleanFlag()
        let coordinator = ProtectedDataTestAppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                ProtectedDataTestAppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { _ in await openCalled.setTrue() }
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

        XCTAssertEqual(outcome, .pendingMutationRecoveryRequired)
        let didOpen = await openCalled.currentValue()
        XCTAssertFalse(didOpen)
        XCTAssertEqual(rightStoreClient.loadCallCount, 0)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionLocked)
    }

    func test_postUnlockCoordinator_mockKeychainInteractionNotAllowedReturnsAuthorizationDenied() async throws {
        let sharedRightIdentifier = "com.cypherair.tests.protected-data.post-unlock.mock-interaction"
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockMockInteraction"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let rootSecretStore = ProtectedDataTestAppMockProtectedDataRootSecretStore()
        try rootSecretStore.saveRootSecret(
            Data(repeating: 0xC8, count: 32),
            identifier: sharedRightIdentifier,
            policy: .userPresence
        )
        rootSecretStore.loadError = .interactionNotAllowed
        let sessionCoordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: sharedRightIdentifier
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: sharedRightIdentifier,
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: nil
        )
        let openCalled = AsyncBooleanFlag()
        let coordinator = ProtectedDataTestAppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                ProtectedDataTestAppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { _ in await openCalled.setTrue() }
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

        XCTAssertEqual(outcome, .authorizationDenied)
        XCTAssertEqual(rootSecretStore.loadCallCount, 1)
        XCTAssertTrue(rootSecretStore.lastAuthenticationContext === handoffContext)
        XCTAssertTrue(handoffContext.interactionNotAllowed)
        let didOpen = await openCalled.currentValue()
        XCTAssertFalse(didOpen)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionLocked)
        XCTAssertFalse(sessionCoordinator.hasActiveWrappingRootKey)
    }

    func test_postUnlockCoordinator_createsAndOpensFrameworkSentinelAsSecondDomain() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockSentinel"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let sharedRightIdentifier = "com.cypherair.tests.protected-data.post-unlock.sentinel"
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: sharedRightIdentifier
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rootSecretStore = RecordingProtectedDataRootSecretStore()
        let sessionCoordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: sharedRightIdentifier
        )
        let protectedSettingsStore = ProtectedSettingsStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try sessionCoordinator.wrappingRootKeyData()
            }
        )
        let sentinelStore = ProtectedDataTestAppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try sessionCoordinator.wrappingRootKeyData()
            }
        )
        try await protectedSettingsStore.ensureCommittedIfNeeded(
            persistSharedRight: { secret in
                try rootSecretStore.saveRootSecret(
                    secret,
                    identifier: sharedRightIdentifier,
                    policy: .userPresence
                )
            }
        )

        let coordinator = ProtectedDataTestAppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { try registryStore.loadRegistry() },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                ProtectedDataTestAppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { wrappingRootKey in
                        _ = try await protectedSettingsStore.openDomainIfNeeded(
                            wrappingRootKey: wrappingRootKey
                        )
                    }
                ),
                ProtectedDataTestAppProtectedDataPostUnlockDomainOpener(
                    domainID: ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID,
                    ensureCommittedIfNeeded: { wrappingRootKey in
                        try await sentinelStore.ensureCommittedIfNeeded(
                            wrappingRootKey: wrappingRootKey
                        )
                    },
                    open: { wrappingRootKey in
                        _ = try await sentinelStore.openDomainIfNeeded(
                            wrappingRootKey: wrappingRootKey
                        )
                    }
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
        let registry = try registryStore.loadRegistry()

        XCTAssertEqual(
            outcome,
            .opened([
                CypherAir.ProtectedSettingsStore.domainID,
                ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID
            ])
        )
        XCTAssertEqual(registry.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertEqual(registry.committedMembership[ProtectedDataTestAppProtectedDataFrameworkSentinelStore.domainID], .active)
        XCTAssertEqual(registry.pendingMutation, nil)
        XCTAssertEqual(sentinelStore.payload, .current)
        XCTAssertEqual(rootSecretStore.loadCallCount, 1)
        XCTAssertTrue(rootSecretStore.lastAuthenticationContext === handoffContext)
        XCTAssertTrue(handoffContext.interactionNotAllowed)
    }
}
