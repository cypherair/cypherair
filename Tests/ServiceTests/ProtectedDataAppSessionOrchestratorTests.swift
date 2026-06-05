import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class ProtectedDataAppSessionOrchestratorTests: ProtectedDataFrameworkTestCase {
    func test_preAuthBootstrap_doesNotTouchRightStoreClient() throws {
        let engine = PgpEngine()
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let defaultsSuiteName = "com.cypherair.tests.protected-data.startup.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let config = AppConfiguration(defaults: defaults)
        let protectedDataBaseDirectory = makeTemporaryDirectory("ProtectedDataStartup")
        let documentDirectory = makeTemporaryDirectory("ProtectedDataStartupDocuments")
        let legacySelfTestReportsDirectory = documentDirectory.appendingPathComponent("self-test", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: protectedDataBaseDirectory) }
        defer { try? FileManager.default.removeItem(at: documentDirectory) }
        try FileManager.default.createDirectory(at: legacySelfTestReportsDirectory, withIntermediateDirectories: true)
        try Data("legacy self-test report".utf8).write(
            to: legacySelfTestReportsDirectory.appendingPathComponent("self-test-legacy.txt")
        )

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: protectedDataBaseDirectory)
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: ProtectedDataTestAppProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let recoveryCoordinator = ProtectedDataTestAppProtectedDomainRecoveryCoordinator(registryStore: registryStore)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let protectedDataSessionCoordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: ProtectedDataTestAppProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let protectedSettingsStore = ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let protectedOrdinarySettingsCoordinator = ProtectedDataTestAppProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: protectedSettingsStore
            )
        )
        let protectedDataFrameworkSentinelStore = ProtectedDataTestAppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let privateKeyControlStore = ProtectedDataTestAppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        authManager.configurePrivateKeyControlStore(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedSettingsStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedDataFrameworkSentinelStore)
        let appSessionOrchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                try recoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: {
                protectedOrdinarySettingsCoordinator.gracePeriodForSession
            },
            evaluateAppAuthentication: { reason in
                try await authManager.evaluateAppSession(
                    policy: config.appSessionAuthenticationPolicy,
                    reason: reason
                )
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let keyManagement = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: certificateAdapter,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore
        )
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let selfTestAdapter = PGPSelfTestOperationAdapter(engine: engine)
        let contactsDomainStore = ContactsDomainStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let contactService = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            contactsDomainStore: contactsDomainStore
        )
        let textEncryptor = TestHelpers.makeTextEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let fileEncryptor = TestHelpers.makeFileEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let encryptionService = EncryptionService(
            keyManagement: keyManagement,
            contactService: contactService,
            textEncryptor: textEncryptor,
            fileEncryptor: fileEncryptor
        )
        let decryptionService = DecryptionService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            messageDecryptor: TestHelpers.makeMessageDecryptor(
                engine: engine,
                keyManagement: keyManagement,
                messageAdapter: messageAdapter
            ),
            fileDecryptor: TestHelpers.makeFileDecryptor(
                engine: engine,
                keyManagement: keyManagement,
                messageAdapter: messageAdapter
            )
        )
        let passwordMessageEncryptor = TestHelpers.makePasswordMessageEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let passwordMessageService = PasswordMessageService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            passwordEncryptor: passwordMessageEncryptor
        )
        let cleartextSigner = TestHelpers.makeCleartextSigner(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let detachedFileSigner = TestHelpers.makeDetachedFileSigner(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let signingService = SigningService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            cleartextSigner: cleartextSigner,
            detachedFileSigner: detachedFileSigner
        )
        let certificateSignatureService = CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            certificationSigner: TestHelpers.makeContactCertificationSigner(
                engine: engine,
                keyManagement: keyManagement,
                certificateAdapter: certificateAdapter
            )
        )
        let qrService = QRService(contactImportAdapter: contactImportAdapter)
        let selfTestService = SelfTestService(
            selfTestAdapter: selfTestAdapter,
            messageAdapter: messageAdapter
        )
        let localDataResetService = LocalDataResetService(
            keychain: keychain,
            protectedDataStorageRoot: storageRoot,
            defaults: defaults,
            defaultsDomainName: defaultsSuiteName,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            authManager: authManager,
            keyManagement: keyManagement,
            contactService: contactService,
            selfTestService: selfTestService,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory
        )
        let container = ProtectedDataTestAppAppContainer(
            authLifecycleTraceStore: nil,
            authenticationShieldCoordinator: CypherAir.AuthenticationShieldCoordinator(),
            authPromptCoordinator: authPromptCoordinator,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            protectedDataStorageRoot: storageRoot,
            protectedDataRegistryStore: registryStore,
            protectedDomainKeyManager: domainKeyManager,
            protectedDomainRecoveryCoordinator: recoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            contactsDomainStore: contactsDomainStore,
            protectedSettingsStore: protectedSettingsStore,
            protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore,
            appSessionOrchestrator: appSessionOrchestrator,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            encryptionService: encryptionService,
            decryptionService: decryptionService,
            passwordMessageService: passwordMessageService,
            signingService: signingService,
            certificateSignatureService: certificateSignatureService,
            qrService: qrService,
            selfTestService: selfTestService,
            localDataResetService: localDataResetService,
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory,
            defaultsSuiteName: defaultsSuiteName
        )

        let snapshot = ProtectedDataTestAppAppStartupCoordinator().performPreAuthBootstrap(using: container)

        guard case .emptySteadyState(_, let didBootstrap) = snapshot.bootstrapOutcome else {
            return XCTFail("Expected empty steady-state startup snapshot, got \(snapshot.bootstrapOutcome)")
        }
        XCTAssertEqual(snapshot.protectedDataFrameworkState, ProtectedDataTestAppProtectedDataFrameworkState.sessionLocked)
        XCTAssertTrue(didBootstrap)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
        XCTAssertEqual(rightStoreClient.saveWithoutSecretCallCount, 0)
        XCTAssertEqual(rightStoreClient.saveWithSecretCallCount, 0)
        XCTAssertEqual(keychain.listItemsCallCount, 0)
        XCTAssertEqual(keychain.loadCallCount, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacySelfTestReportsDirectory.path))
        XCTAssertEqual(protectedDataSessionCoordinator.frameworkState, ProtectedDataTestAppProtectedDataFrameworkState.sessionLocked)
    }

    func test_handleInitialAppearance_nonBypassAlwaysAuthenticates() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataInitialAppearance")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.initial-appearance",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleInitialAppearance(
            localizedReason: "Initial appearance should authenticate"
        )
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertTrue(didEvaluate)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(relockParticipant.relockCallCount, 1)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleInitialAppearance_uiTestBypassSkipsAuthentication() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataInitialAppearanceBypass")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.initial-appearance-bypass",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { true },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleInitialAppearance(
            localizedReason: "UI test bypass should skip authentication"
        )
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication)
        XCTAssertFalse(didEvaluate)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_externalAuthenticationPromptInProgress_skipsRelockAndAuthentication() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResumeSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resume-suppression",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        defer { authPromptCoordinator.endOperationPrompt() }

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "External prompt in progress"
        )
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
    }

    func test_handleSceneDidResignActive_externalAuthenticationPromptInProgress_doesNotBlurPrivacyScreen() {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResignSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resign-suppression",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        defer { authPromptCoordinator.endOperationPrompt() }

        orchestrator.handleSceneDidResignActive()

        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_observedOperationPromptSettleLifecycleAfterPromptEnds_blursWithoutResumeAuthentication() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataLateLifecycleSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.late-lifecycle",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        var gate = ProtectedDataTestAppPrivacyScreenLifecycleGate()

        authPromptCoordinator.beginOperationPrompt()
        XCTAssertEqual(
            gate.shouldHandleInactive(
                isAuthenticating: orchestrator.isAuthenticating,
                operationPrompt: orchestrator.operationAuthenticationPromptSnapshot
            ),
            .suppress
        )
        authPromptCoordinator.endOperationPrompt()

        let operationPrompt = orchestrator.operationAuthenticationPromptSnapshot
        switch gate.shouldHandleInactive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            orchestrator.handleSceneDidResignActive()
        case .blurOnly:
            orchestrator.handleAuthenticationSettleInactive(source: "unit.promptSettleInactive")
        case .settleTransientBlur, .suppress:
            break
        }

        orchestrator.handleSceneDidBecomeActive(source: "unit.promptSettleActive")
        let attemptedAuthentication: Bool
        switch gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Late lifecycle after operation prompt"
            )
        case .settleTransientBlur:
            orchestrator.handleAuthenticationSettleActive(source: "unit.promptSettleActive")
            attemptedAuthentication = false
        case .blurOnly, .suppress:
            attemptedAuthentication = false
        }

        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_nestedOperationPromptSessionSettleAfterPromptEnds_blursWithoutResumeAuthentication() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataNestedPromptSettle")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.nested-prompt-settle",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        var gate = ProtectedDataTestAppPrivacyScreenLifecycleGate()

        let outerPrompt = authPromptCoordinator.beginOperationPrompt()
        XCTAssertEqual(orchestrator.operationAuthenticationPromptSnapshot.generation, 1)
        XCTAssertEqual(orchestrator.operationAuthenticationPromptSnapshot.sessionGeneration, 1)
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: orchestrator.isAuthenticating,
                operationPrompt: orchestrator.operationAuthenticationPromptSnapshot
            ),
            .suppress
        )
        let innerPrompt = authPromptCoordinator.beginOperationPrompt()
        XCTAssertEqual(orchestrator.operationAuthenticationPromptSnapshot.generation, 2)
        XCTAssertEqual(orchestrator.operationAuthenticationPromptSnapshot.sessionGeneration, 1)
        authPromptCoordinator.endOperationPrompt(innerPrompt)
        authPromptCoordinator.endOperationPrompt(outerPrompt)

        let operationPrompt = orchestrator.operationAuthenticationPromptSnapshot
        XCTAssertEqual(operationPrompt.generation, 2)
        XCTAssertEqual(operationPrompt.sessionGeneration, 1)
        switch gate.shouldHandleResignActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            orchestrator.handleSceneDidResignActive()
        case .blurOnly:
            orchestrator.handleAuthenticationSettleInactive(source: "unit.nestedPromptSettleInactive")
        case .settleTransientBlur, .suppress:
            break
        }

        orchestrator.handleSceneDidBecomeActive(source: "unit.nestedPromptSettleActive")
        let attemptedAuthentication: Bool
        switch gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Nested operation prompt tail should settle"
            )
        case .settleTransientBlur:
            orchestrator.handleAuthenticationSettleActive(source: "unit.nestedPromptSettleActive")
            attemptedAuthentication = false
        case .blurOnly, .suppress:
            attemptedAuthentication = false
        }
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_unobservedOperationPromptTailTreatsResignAndActiveAsRealResume() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataUnobservedPromptTail")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.unobserved-prompt-tail",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        var gate = ProtectedDataTestAppPrivacyScreenLifecycleGate()

        authPromptCoordinator.beginOperationPrompt()
        authPromptCoordinator.endOperationPrompt()

        let operationPrompt = orchestrator.operationAuthenticationPromptSnapshot
        switch gate.shouldHandleResignActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            orchestrator.handleSceneDidResignActive()
        case .blurOnly:
            orchestrator.handleAuthenticationSettleInactive(source: "unit.unobservedPromptInactive")
        case .settleTransientBlur, .suppress:
            break
        }

        orchestrator.handleSceneDidBecomeActive(source: "unit.unobservedPromptActive")
        let attemptedAuthentication: Bool
        switch gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Unobserved prompt tail should not suppress real resume"
            )
        case .settleTransientBlur:
            orchestrator.handleAuthenticationSettleActive(source: "unit.unobservedPromptActive")
            attemptedAuthentication = false
        case .blurOnly, .suppress:
            attemptedAuthentication = false
        }
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(relockParticipant.relockCallCount, 1)
        XCTAssertTrue(didEvaluate)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_serialOperationPromptSessionDoesNotInheritObservedSettleEligibility() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataSerialPromptSession")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.serial-prompt-session",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        var gate = ProtectedDataTestAppPrivacyScreenLifecycleGate()

        let firstPrompt = authPromptCoordinator.beginOperationPrompt()
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: orchestrator.isAuthenticating,
                operationPrompt: orchestrator.operationAuthenticationPromptSnapshot
            ),
            .suppress
        )
        authPromptCoordinator.endOperationPrompt(firstPrompt)

        let secondPrompt = authPromptCoordinator.beginOperationPrompt()
        authPromptCoordinator.endOperationPrompt(secondPrompt)

        let operationPrompt = orchestrator.operationAuthenticationPromptSnapshot
        XCTAssertEqual(operationPrompt.generation, 2)
        XCTAssertEqual(operationPrompt.sessionGeneration, 2)
        switch gate.shouldHandleResignActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            orchestrator.handleSceneDidResignActive()
        case .blurOnly:
            orchestrator.handleAuthenticationSettleInactive(source: "unit.serialPromptInactive")
        case .settleTransientBlur, .suppress:
            break
        }

        orchestrator.handleSceneDidBecomeActive(source: "unit.serialPromptActive")
        let attemptedAuthentication: Bool
        switch gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Serial operation prompt session should not inherit settle eligibility"
            )
        case .settleTransientBlur:
            orchestrator.handleAuthenticationSettleActive(source: "unit.serialPromptActive")
            attemptedAuthentication = false
        case .blurOnly, .suppress:
            attemptedAuthentication = false
        }
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(relockParticipant.relockCallCount, 1)
        XCTAssertTrue(didEvaluate)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_expiredOperationPromptLifecycleTreatsResignAndActiveAsRealResume() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataExpiredLifecycle")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let clock = ProtectedDataTestMutableDateProvider(Date(timeIntervalSinceReferenceDate: 9_000))
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator(now: clock.now)
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.expired-lifecycle",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        // Explicit small settle window to exercise the safety-expiry bound. Production
        // uses a generous default so a real ~2.4 s Face ID `.active` never expires.
        var gate = ProtectedDataTestAppPrivacyScreenLifecycleGate(
            operationPromptSettleWindow: 1.0,
            now: clock.now
        )

        authPromptCoordinator.beginOperationPrompt()
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: orchestrator.isAuthenticating,
                operationPrompt: orchestrator.operationAuthenticationPromptSnapshot
            ),
            .suppress
        )
        authPromptCoordinator.endOperationPrompt()
        clock.value = clock.value.addingTimeInterval(1.1)

        let operationPrompt = orchestrator.operationAuthenticationPromptSnapshot
        switch gate.shouldHandleResignActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            orchestrator.handleSceneDidResignActive()
        case .blurOnly:
            orchestrator.handleAuthenticationSettleInactive(source: "unit.expiredPromptInactive")
        case .settleTransientBlur, .suppress:
            break
        }

        orchestrator.handleSceneDidBecomeActive(source: "unit.expiredPromptActive")
        let attemptedAuthentication: Bool
        switch gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: operationPrompt
        ) {
        case .handle:
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Expired lifecycle after operation prompt"
            )
        case .settleTransientBlur:
            orchestrator.handleAuthenticationSettleActive(source: "unit.expiredPromptActive")
            attemptedAuthentication = false
        case .blurOnly, .suppress:
            attemptedAuthentication = false
        }
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(relockParticipant.relockCallCount, 1)
        XCTAssertTrue(didEvaluate)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    // Regression for the on-device repro (auth-traces-2026-06-05-duplicate-auth):
    // an OPERATION biometric (encrypt-sign / sign / export) under grace=0 raises a
    // sheet (`.inactive` while the prompt is active) and the dismissal `.active`
    // arrives ~2.4 s later — well past the old 1.0 s settle window. With the
    // generous default window, the gate must still recognise the dismissal as the
    // prompt's own and suppress it: NO content clear, NO second evaluate.
    func test_operationPromptLateActive_withinDefaultSettleWindow_doesNotRelockOrReprompt() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataOperationLateActive")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let clock = ProtectedDataTestMutableDateProvider(Date(timeIntervalSinceReferenceDate: 9_000))
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator(now: clock.now)
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.operation-late-active",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        // Default (generous) settle window — production behaviour.
        var gate = ProtectedDataTestAppPrivacyScreenLifecycleGate(now: clock.now)

        authPromptCoordinator.beginOperationPrompt()
        // Sheet appears: `.inactive` while the operation prompt is in progress.
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: orchestrator.isAuthenticating,
                operationPrompt: orchestrator.anyAuthenticationPromptSnapshot
            ),
            .suppress
        )
        authPromptCoordinator.endOperationPrompt()
        // The dismissal `.active` lands ~2.4 s later — past the old 1.0 s window.
        clock.value = clock.value.addingTimeInterval(2.4)

        let endedPrompt = orchestrator.anyAuthenticationPromptSnapshot
        orchestrator.handleSceneDidBecomeActive(source: "unit.operationLateActive")
        let attemptedAuthentication: Bool
        switch gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: endedPrompt
        ) {
        case .handle:
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Operation prompt dismissal must not resume"
            )
        case .settleTransientBlur:
            orchestrator.handleAuthenticationSettleActive(source: "unit.operationLateActive")
            attemptedAuthentication = false
        case .blurOnly, .suppress:
            attemptedAuthentication = false
        }
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication, "The operation prompt's own dismissal must not trigger a resume")
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
    }

    // Same repro for a PRIVACY biometric (Change App Access Protection / mode
    // switch). Previously the gate was blind to the privacy channel and always
    // re-prompted; the union snapshot now suppresses it identically.
    func test_privacyPromptLateActive_withinDefaultSettleWindow_doesNotRelockOrReprompt() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataPrivacyLateActive")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let clock = ProtectedDataTestMutableDateProvider(Date(timeIntervalSinceReferenceDate: 9_000))
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator(now: clock.now)
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.privacy-late-active",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        var gate = ProtectedDataTestAppPrivacyScreenLifecycleGate(now: clock.now)

        let privacyContext = authPromptCoordinator.beginPrivacyPrompt()
        // Sheet appears: `.inactive` while the PRIVACY prompt is in progress.
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: orchestrator.isAuthenticating,
                operationPrompt: orchestrator.anyAuthenticationPromptSnapshot
            ),
            .suppress
        )
        authPromptCoordinator.endPrivacyPrompt(privacyContext)
        clock.value = clock.value.addingTimeInterval(2.4)

        let endedPrompt = orchestrator.anyAuthenticationPromptSnapshot
        orchestrator.handleSceneDidBecomeActive(source: "unit.privacyLateActive")
        let attemptedAuthentication: Bool
        switch gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: endedPrompt
        ) {
        case .handle:
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Privacy prompt dismissal must not resume"
            )
        case .settleTransientBlur:
            orchestrator.handleAuthenticationSettleActive(source: "unit.privacyLateActive")
            attemptedAuthentication = false
        case .blurOnly, .suppress:
            attemptedAuthentication = false
        }
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication, "A privacy biometric's own dismissal must not trigger a resume")
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
    }

    // Security guard: a genuine background→return with NO app-owned prompt involved
    // must still re-lock + re-prompt under grace=0.
    func test_genuineResignActive_withNoPromptActive_relocksAndReprompts() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataGenuineResume")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let clock = ProtectedDataTestMutableDateProvider(Date(timeIntervalSinceReferenceDate: 9_000))
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator(now: clock.now)
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.genuine-resume",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        var gate = ProtectedDataTestAppPrivacyScreenLifecycleGate(now: clock.now)

        // No app-owned prompt is active: a genuine resign/activate.
        switch gate.shouldHandleResignActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: orchestrator.anyAuthenticationPromptSnapshot
        ) {
        case .handle:
            orchestrator.handleSceneDidResignActive()
        case .blurOnly:
            orchestrator.handleAuthenticationSettleInactive(source: "unit.genuineResume")
        case .settleTransientBlur, .suppress:
            break
        }
        orchestrator.handleSceneDidBecomeActive(source: "unit.genuineResume")
        let attemptedAuthentication: Bool
        switch gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: orchestrator.anyAuthenticationPromptSnapshot
        ) {
        case .handle:
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Genuine background must re-lock"
            )
        case .settleTransientBlur:
            orchestrator.handleAuthenticationSettleActive(source: "unit.genuineResume")
            attemptedAuthentication = false
        case .blurOnly, .suppress:
            attemptedAuthentication = false
        }
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(attemptedAuthentication, "A real background with no biometric must re-lock under grace=0")
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(relockParticipant.relockCallCount, 1)
        XCTAssertTrue(didEvaluate)
    }

    func test_authenticationSettleInactive_blursWithoutRelockOrAuthentication() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataAuthenticationSettleInactive")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.auth-settle-inactive",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        orchestrator.handleAuthenticationSettleInactive(source: "unit.authSettleInactive")
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
    }

    func test_authenticationSettleActive_hidesTransientBlurWithoutAuthentication() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataAuthenticationSettleActive")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.auth-settle-active",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        orchestrator.handleAuthenticationSettleInactive(source: "unit.authSettleInactive")
        orchestrator.handleAuthenticationSettleActive(source: "unit.authSettleActive")
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
    }

    func test_authenticationSettleActive_keepsRetryOverlayAfterAuthFailure() async throws {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataAuthenticationSettleFailure")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.auth-settle-failure",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        orchestrator.authFailed = true
        orchestrator.handleAuthenticationSettleInactive(source: "unit.authSettleInactive")
        orchestrator.handleAuthenticationSettleActive(source: "unit.authSettleActive")
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
        XCTAssertTrue(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertFalse(didEvaluate)
    }

    func test_realResignClearsTransientSettleBlurAndRemainsBlurred() {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataAuthenticationSettleRealResign")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.auth-settle-real-resign",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        orchestrator.handleAuthenticationSettleInactive(source: "unit.authSettleInactive")
        orchestrator.handleSceneDidResignActive()
        orchestrator.handleAuthenticationSettleActive(source: "unit.authSettleActive")

        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
        XCTAssertFalse(orchestrator.authFailed)
    }

    func test_handleSceneDidEnterBackground_duringExternalAuthenticationPrompt_blursPrivacyScreen() {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataBackgroundSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.background-suppression",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        defer { authPromptCoordinator.endOperationPrompt() }

        orchestrator.handleSceneDidEnterBackground()

        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_successfulAuthentication_doesNotActivateProtectedDataSession() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResumeNoWarmUp")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let handoffContext = LAContext()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resume-no-warmup",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .authenticated(context: handoffContext) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Successful privacy unlock should not warm protected settings"
        )

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
        XCTAssertTrue(orchestrator.consumeAuthenticatedContextForProtectedData() === handoffContext)
        XCTAssertNil(orchestrator.consumeAuthenticatedContextForProtectedData())
        handoffContext.invalidate()
    }

    func test_handleResume_successfulAuthenticationIncrementsPostAuthenticationGenerationAfterHandler() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataPostAuthenticationGeneration")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-auth-generation",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didRunPostAuthenticationHandler = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            postAuthenticationHandler: { _, _ in
                await didRunPostAuthenticationHandler.setTrue()
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 0)

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Successful privacy unlock should publish post-auth generation"
        )
        let didRunHandler = await didRunPostAuthenticationHandler.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertTrue(didRunHandler)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 1)
    }

    func test_handleResume_backgroundDuringPostAuthenticationKeepsHardBlurAndDoesNotArmSettle() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataPostAuthenticationBackgroundRace")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-auth-background-race",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let postAuthenticationGate = AsyncSuspensionGate()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            postAuthenticationHandler: { _, _ in
                await postAuthenticationGate.suspend()
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let resumeTask = Task {
            await orchestrator.handleResumeForLifecycle(
                localizedReason: "Successful privacy unlock races with background",
                source: "unit.postAuthBackgroundRace"
            )
        }
        while !(await postAuthenticationGate.isSuspended()) {
            await Task.yield()
        }

        orchestrator.handleSceneDidEnterBackground()
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)

        await postAuthenticationGate.resume()
        let result = await resumeTask.value

        XCTAssertTrue(result.attemptedAuthentication)
        XCTAssertFalse(result.shouldArmAuthenticationSettle)
        XCTAssertFalse(result.shouldStartFreshResume)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 1)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    // A successful auth straddled by a background→active round-trip (here during
    // post-auth) is terminal: the app unblurs directly with no fresh resume and a
    // single authentication attempt. Previously this routed through a second
    // "fresh" resume; that indirection is what double-prompted under grace==0.
    func test_handleResume_successDuringBackgroundReactivation_unblursWithoutFreshResume() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataPostAuthenticationFreshResume")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-auth-fresh-resume",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let postAuthenticationGate = AsyncSuspensionGate()
        let authenticationAttempts = AsyncIntegerCounter()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in
                _ = await authenticationAttempts.next()
                return .authenticated(context: nil)
            },
            postAuthenticationHandler: { _, source in
                if source == "unit.stalePostAuth" {
                    await postAuthenticationGate.suspend()
                }
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let staleResumeTask = Task {
            await orchestrator.handleResumeForLifecycle(
                localizedReason: "Successful privacy unlock races with background and active",
                source: "unit.stalePostAuth"
            )
        }
        while !(await postAuthenticationGate.isSuspended()) {
            await Task.yield()
        }

        orchestrator.handleSceneDidEnterBackground()
        orchestrator.handleSceneDidBecomeActive(source: "unit.activeAfterBackground")
        // Still blurred while post-auth is in flight.
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)

        await postAuthenticationGate.resume()
        let staleResult = await staleResumeTask.value

        XCTAssertTrue(staleResult.attemptedAuthentication)
        XCTAssertTrue(staleResult.shouldArmAuthenticationSettle)
        XCTAssertFalse(staleResult.shouldStartFreshResume)
        let authenticationAttemptCount = await authenticationAttempts.currentValue()
        XCTAssertEqual(authenticationAttemptCount, 1)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 1)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    // T1 — headline grace==0 regression: a background→active round-trip during a
    // successful resume must NOT trigger a second Face ID prompt.
    func test_handleResume_grace0_successDuringBackgroundReactivation_doesNotDoublePrompt() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataGrace0FreshResume")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.grace0-fresh-resume",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let postAuthenticationGate = AsyncSuspensionGate()
        let authenticationAttempts = AsyncIntegerCounter()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                _ = await authenticationAttempts.next()
                return .authenticated(context: nil)
            },
            postAuthenticationHandler: { _, source in
                if source == "unit.grace0PostAuth" {
                    await postAuthenticationGate.suspend()
                }
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let resumeTask = Task {
            await orchestrator.handleResumeForLifecycle(
                localizedReason: "Immediately-grace resume races with background and active",
                source: "unit.grace0PostAuth"
            )
        }
        while !(await postAuthenticationGate.isSuspended()) {
            await Task.yield()
        }

        // App passes through background then returns while the first (successful)
        // auth's post-auth work is still in flight.
        orchestrator.handleSceneDidEnterBackground()
        orchestrator.handleSceneDidBecomeActive(source: "unit.activeAfterBackground")

        await postAuthenticationGate.resume()
        let result = await resumeTask.value

        XCTAssertTrue(result.attemptedAuthentication)
        XCTAssertTrue(result.shouldArmAuthenticationSettle)
        XCTAssertFalse(result.shouldStartFreshResume)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
        XCTAssertFalse(orchestrator.authFailed)
        let authenticationAttemptCount = await authenticationAttempts.currentValue()
        XCTAssertEqual(
            authenticationAttemptCount,
            1,
            "grace==0 must not trigger a second Face ID prompt after a successful auth"
        )
    }

    // T2 — backgrounded-success boundary: if the scene is still backgrounded at
    // completion, keep the hard blur and discard the handoff context so it cannot
    // open protected data while backgrounded.
    func test_handleResume_grace0_backgroundedSuccess_keepsBlurAndDiscardsContext() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataGrace0BackgroundedSuccess")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.grace0-backgrounded-success",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let postAuthenticationGate = AsyncSuspensionGate()
        let handoffContext = LAContext()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                .authenticated(context: handoffContext)
            },
            postAuthenticationHandler: { _, source in
                if source == "unit.backgroundedSuccess" {
                    await postAuthenticationGate.suspend()
                }
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let resumeTask = Task {
            await orchestrator.handleResumeForLifecycle(
                localizedReason: "Backgrounded success keeps hard blur",
                source: "unit.backgroundedSuccess"
            )
        }
        while !(await postAuthenticationGate.isSuspended()) {
            await Task.yield()
        }

        // App goes to background during post-auth and stays there.
        orchestrator.handleSceneDidEnterBackground()

        await postAuthenticationGate.resume()
        let result = await resumeTask.value

        XCTAssertTrue(result.attemptedAuthentication)
        XCTAssertFalse(result.shouldArmAuthenticationSettle)
        XCTAssertFalse(result.shouldStartFreshResume)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
        // The just-minted handoff context must not survive while backgrounded.
        XCTAssertNil(orchestrator.consumeAuthenticatedContextForProtectedData())
        handoffContext.invalidate()
    }

    // T3 — concurrency: a second resume that arrives while the first is parked
    // inside relock must observe the in-flight flag and bail (single prompt).
    func test_handleResume_concurrentEntryDuringRelock_doesNotDoublePrompt() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataConcurrentResumeEntry")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.concurrent-resume-entry",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockGate = AsyncSuspensionGate()
        let relockParticipant = SuspendingRelockParticipant(gate: relockGate)
        coordinator.registerRelockParticipant(relockParticipant)

        let authenticationAttempts = AsyncIntegerCounter()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                _ = await authenticationAttempts.next()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        // First resume parks inside relockCurrentSession() — the exact window
        // between `guard !isAuthenticating` and the in-flight flag set.
        let firstResume = Task {
            await orchestrator.handleResumeForLifecycle(
                localizedReason: "First resume parks in relock",
                source: "unit.concurrentA"
            )
        }
        while !(await relockGate.isSuspended()) {
            await Task.yield()
        }

        // Second resume enters while the first is parked; it must bail.
        let secondResume = await orchestrator.handleResumeForLifecycle(
            localizedReason: "Second resume must be suppressed",
            source: "unit.concurrentB"
        )
        XCTAssertFalse(secondResume.attemptedAuthentication)
        XCTAssertFalse(secondResume.shouldStartFreshResume)

        await relockGate.resume()
        let firstResult = await firstResume.value

        XCTAssertTrue(firstResult.attemptedAuthentication)
        let authenticationAttemptCount = await authenticationAttempts.currentValue()
        XCTAssertEqual(authenticationAttemptCount, 1, "Only one resume may reach the Face ID prompt")
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
    }

    // T4 — macOS path: resign/active (there is no `.background` on macOS) behaves
    // the same as background/active — single prompt, app revealed.
    func test_handleResume_grace0_successDuringResignReactivation_doesNotDoublePrompt() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataGrace0ResignReactivation")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.grace0-resign-reactivation",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let postAuthenticationGate = AsyncSuspensionGate()
        let authenticationAttempts = AsyncIntegerCounter()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                _ = await authenticationAttempts.next()
                return .authenticated(context: nil)
            },
            postAuthenticationHandler: { _, source in
                if source == "unit.resignPostAuth" {
                    await postAuthenticationGate.suspend()
                }
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let resumeTask = Task {
            await orchestrator.handleResumeForLifecycle(
                localizedReason: "Immediately-grace resume races with resign and active",
                source: "unit.resignPostAuth"
            )
        }
        while !(await postAuthenticationGate.isSuspended()) {
            await Task.yield()
        }

        orchestrator.handleSceneDidResignActive()
        orchestrator.handleSceneDidBecomeActive(source: "unit.activeAfterResign")

        await postAuthenticationGate.resume()
        let result = await resumeTask.value

        XCTAssertTrue(result.attemptedAuthentication)
        XCTAssertTrue(result.shouldArmAuthenticationSettle)
        XCTAssertFalse(result.shouldStartFreshResume)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
        let authenticationAttemptCount = await authenticationAttempts.currentValue()
        XCTAssertEqual(authenticationAttemptCount, 1)
    }

    // T5 — the untouched failure path: a prompt cancelled by backgrounding must
    // still request a fresh resume (re-prompt) on return.
    func test_handleResume_grace0_cancelledDuringBackground_stillRequestsFreshResume() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataGrace0CancelledDuringBackground")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.grace0-cancelled-during-background",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let evaluateGate = AsyncSuspensionGate()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await evaluateGate.suspend()
                throw AuthenticationError.cancelled
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let resumeTask = Task {
            await orchestrator.handleResumeForLifecycle(
                localizedReason: "Prompt is cancelled by a real background",
                source: "unit.cancelledDuringBackground"
            )
        }
        while !(await evaluateGate.isSuspended()) {
            await Task.yield()
        }

        orchestrator.handleSceneDidEnterBackground()
        orchestrator.handleSceneDidBecomeActive(source: "unit.activeAfterBackground")

        await evaluateGate.resume()
        let result = await resumeTask.value

        XCTAssertTrue(result.attemptedAuthentication)
        XCTAssertTrue(result.shouldStartFreshResume)
        XCTAssertFalse(result.shouldArmAuthenticationSettle)
        XCTAssertTrue(orchestrator.authFailed)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_graceValidWhileBackgroundKeepsHardBlur() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataBackgroundGraceBlur")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.background-grace-blur",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let authenticationAttempts = AsyncIntegerCounter()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in
                _ = await authenticationAttempts.next()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let initialResult = await orchestrator.handleResumeForLifecycle(
            localizedReason: "Initial authentication before background grace check",
            source: "unit.backgroundGraceInitial"
        )
        XCTAssertTrue(initialResult.attemptedAuthentication)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)

        orchestrator.handleSceneDidEnterBackground()
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)

        let backgroundGraceResult = await orchestrator.handleResumeForLifecycle(
            localizedReason: "Background grace check must not clear hard blur",
            source: "unit.backgroundGrace"
        )

        XCTAssertFalse(backgroundGraceResult.attemptedAuthentication)
        XCTAssertFalse(backgroundGraceResult.shouldArmAuthenticationSettle)
        XCTAssertFalse(backgroundGraceResult.shouldStartFreshResume)
        let authenticationAttemptCount = await authenticationAttempts.currentValue()
        XCTAssertEqual(authenticationAttemptCount, 1)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_failedAuthenticationDoesNotIncrementPostAuthenticationGeneration() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataFailedPostAuthenticationGeneration")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.failed-post-auth-generation",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didRunPostAuthenticationHandler = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .failed },
            postAuthenticationHandler: { _, _ in
                await didRunPostAuthenticationHandler.setTrue()
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Failed privacy unlock should not publish post-auth generation"
        )
        let didRunHandler = await didRunPostAuthenticationHandler.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertFalse(didRunHandler)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 0)
        XCTAssertTrue(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.authenticationFailureReason, .authenticationFailed)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_biometricsLockoutSetsFailureReasonAndKeepsPrivacyOverlay() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataBiometricsLockout")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.biometrics-lockout",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didRunPostAuthenticationHandler = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                throw AuthenticationError.appAccessBiometricsLockedOut
            },
            postAuthenticationHandler: { _, _ in
                await didRunPostAuthenticationHandler.setTrue()
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Locked out privacy unlock should keep content hidden"
        )
        let didRunHandler = await didRunPostAuthenticationHandler.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertFalse(didRunHandler)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 0)
        XCTAssertNil(orchestrator.lastAuthenticationDate)
        XCTAssertTrue(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.authenticationFailureReason, .biometricsLockedOut)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_successfulAuthenticationClearsPreviousFailureReason() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataClearsFailureReason")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.clears-failure-reason",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let authenticationAttempts = AsyncIntegerCounter()
        let didRunPostAuthenticationHandler = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                if await authenticationAttempts.next() == 1 {
                    throw AuthenticationError.appAccessBiometricsLockedOut
                }
                return .authenticated(context: nil)
            },
            postAuthenticationHandler: { _, _ in
                await didRunPostAuthenticationHandler.setTrue()
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let firstAttempt = await orchestrator.handleResume(
            localizedReason: "First privacy unlock attempt is locked out"
        )

        XCTAssertTrue(firstAttempt)
        XCTAssertTrue(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.authenticationFailureReason, .biometricsLockedOut)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 0)

        let secondAttempt = await orchestrator.handleResume(
            localizedReason: "Second privacy unlock succeeds"
        )
        let didRunHandler = await didRunPostAuthenticationHandler.currentValue()

        XCTAssertTrue(secondAttempt)
        XCTAssertTrue(didRunHandler)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertNil(orchestrator.authenticationFailureReason)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 1)
    }

    func test_appAccessPolicyChange_discardsPendingProtectedDataHandoffContext() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataPolicyChangeHandoff")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let handoffContext = LAContext()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.policy-change-handoff",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .authenticated(context: handoffContext) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        defer {
            if orchestrator.hasProtectedDataAuthorizationHandoffContext {
                handoffContext.invalidate()
            }
        }

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Successful privacy unlock stores handoff before policy change"
        )

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertTrue(orchestrator.hasProtectedDataAuthorizationHandoffContext)

        orchestrator.discardProtectedDataAuthorizationHandoffContextForPolicyChange()

        XCTAssertFalse(orchestrator.hasProtectedDataAuthorizationHandoffContext)
        XCTAssertNil(orchestrator.consumeAuthenticatedContextForProtectedData())
    }

    func test_handleResume_afterBackgroundFollowingOperationPrompt_treatsReturnAsRealResume() async {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResumeAfterBackground")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resume-after-background",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = ProtectedDataTestAppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        var gate = ProtectedDataTestAppPrivacyScreenLifecycleGate()
        authPromptCoordinator.beginOperationPrompt()
        if gate.shouldHandleBackground(operationPrompt: orchestrator.operationAuthenticationPromptSnapshot) {
            orchestrator.handleSceneDidEnterBackground()
        }
        authPromptCoordinator.endOperationPrompt()
        orchestrator.handleSceneDidBecomeActive(source: "unit.backgroundPromptActive")

        let attemptedAuthentication: Bool
        switch gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            operationPrompt: orchestrator.operationAuthenticationPromptSnapshot
        ) {
        case .handle:
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Resume after a real background should still re-authenticate"
            )
        case .settleTransientBlur:
            orchestrator.handleAuthenticationSettleActive(source: "unit.backgroundPromptActive")
            attemptedAuthentication = false
        case .blurOnly, .suppress:
            attemptedAuthentication = false
        }
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertTrue(didEvaluate)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(relockParticipant.relockCallCount, 1)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }
}
