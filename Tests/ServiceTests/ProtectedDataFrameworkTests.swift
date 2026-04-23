import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

private typealias AppAppContainer = CypherAir.AppContainer
private typealias AppAppSessionOrchestrator = CypherAir.AppSessionOrchestrator
private typealias AppAppStartupCoordinator = CypherAir.AppStartupCoordinator
private typealias AppProtectedDataBootstrapState = CypherAir.ProtectedDataBootstrapState
private typealias AppProtectedDataFrameworkState = CypherAir.ProtectedDataFrameworkState
private typealias AppProtectedDataPersistedRightHandle = CypherAir.ProtectedDataPersistedRightHandle
private typealias AppProtectedDataRegistryStore = CypherAir.ProtectedDataRegistryStore
private typealias AppProtectedDataRelockParticipant = CypherAir.ProtectedDataRelockParticipant
private typealias AppProtectedDataRightStoreClientProtocol = CypherAir.ProtectedDataRightStoreClientProtocol
private typealias AppProtectedDataRightIdentifiers = CypherAir.ProtectedDataRightIdentifiers
private typealias AppProtectedDataSessionCoordinator = CypherAir.ProtectedDataSessionCoordinator
private typealias AppProtectedDataStorageRoot = CypherAir.ProtectedDataStorageRoot
private typealias AppProtectedDomainKeyManager = CypherAir.ProtectedDomainKeyManager
private typealias AppProtectedDomainRecoveryCoordinator = CypherAir.ProtectedDomainRecoveryCoordinator
private typealias AppPrivacyScreenLifecycleGate = CypherAir.PrivacyScreenLifecycleGate
private typealias AppPendingRecoveryOutcome = CypherAir.PendingRecoveryOutcome
private typealias AppWrappedDomainMasterKeyRecord = CypherAir.WrappedDomainMasterKeyRecord

private final class MockProtectedDataPersistedRightHandle: AppProtectedDataPersistedRightHandle {
    let identifier: String
    private let secretData: Data
    var authorizeError: Error?
    var rawSecretError: Error?

    private(set) var authorizeCallCount = 0
    private(set) var deauthorizeCallCount = 0

    init(identifier: String, secretData: Data) {
        self.identifier = identifier
        self.secretData = secretData
    }

    func authorize(localizedReason: String) async throws {
        authorizeCallCount += 1
        if let authorizeError {
            throw authorizeError
        }
    }

    func deauthorize() async {
        deauthorizeCallCount += 1
    }

    func rawSecretData() async throws -> Data {
        if let rawSecretError {
            throw rawSecretError
        }
        return secretData
    }
}

private final class MockProtectedDataRightStoreClient: AppProtectedDataRightStoreClientProtocol {
    var persistedRightHandle: MockProtectedDataPersistedRightHandle?

    private(set) var rightLookupCallCount = 0
    private(set) var saveWithoutSecretCallCount = 0
    private(set) var saveWithSecretCallCount = 0
    private(set) var removeCallCount = 0
    private(set) var lastRemovedIdentifier: String?

    func right(forIdentifier identifier: String) async throws -> any AppProtectedDataPersistedRightHandle {
        rightLookupCallCount += 1
        guard let persistedRightHandle else {
            throw CypherAir.ProtectedDataError.missingPersistedRight(identifier)
        }
        return persistedRightHandle
    }

    func saveRight(_ right: LARight, identifier: String) async throws -> any AppProtectedDataPersistedRightHandle {
        saveWithoutSecretCallCount += 1
        let handle = MockProtectedDataPersistedRightHandle(identifier: identifier, secretData: Data(repeating: 0x11, count: 32))
        persistedRightHandle = handle
        return handle
    }

    func saveRight(
        _ right: LARight,
        identifier: String,
        secret: Data
    ) async throws -> any AppProtectedDataPersistedRightHandle {
        saveWithSecretCallCount += 1
        let handle = MockProtectedDataPersistedRightHandle(identifier: identifier, secretData: secret)
        persistedRightHandle = handle
        return handle
    }

    func removeRight(forIdentifier identifier: String) async throws {
        removeCallCount += 1
        lastRemovedIdentifier = identifier
        persistedRightHandle = nil
    }
}

private final class MockProtectedDataRelockParticipant: AppProtectedDataRelockParticipant {
    var shouldThrow = false
    private(set) var relockCallCount = 0

    func relockProtectedData() async throws {
        relockCallCount += 1
        if shouldThrow {
            throw ProtectedDataError.restartRequired
        }
    }
}

private actor AsyncBooleanFlag {
    private var value = false

    func setTrue() {
        value = true
    }

    func currentValue() -> Bool {
        value
    }
}

@MainActor
final class ProtectedDataFrameworkTests: XCTestCase {
    private func makeTemporaryDirectory(_ prefix: String) -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    func test_registryBootstrap_withoutRootOrArtifacts_bootstrapsEmptySteadyState() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataBootstrap")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let store = AppProtectedDataRegistryStore(
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

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        try FileManager.default.createDirectory(at: storageRoot.rootURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: storageRoot.domainDirectory(for: "synthetic-domain"),
            withIntermediateDirectories: true
        )

        let store = AppProtectedDataRegistryStore(
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

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let store = AppProtectedDataRegistryStore(
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

    func test_domainKeyManager_deriveWrappingRootKey_zeroizesInputAndWrapsDeterministicallyPerDomain() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataKeys")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        var rawSecret = Data(repeating: 0x7A, count: 32)
        let domainMasterKey = Data(repeating: 0x42, count: 32)

        let wrappingRootKey = try keyManager.deriveWrappingRootKey(from: &rawSecret)
        let firstDomainWrappingKey = try keyManager.deriveDomainWrappingKey(
            from: wrappingRootKey,
            domainID: "contacts"
        )
        let secondDomainWrappingKey = try keyManager.deriveDomainWrappingKey(
            from: wrappingRootKey,
            domainID: "settings"
        )
        let record = try keyManager.wrapDomainMasterKey(
            domainMasterKey,
            for: "contacts",
            wrappingRootKey: wrappingRootKey
        )
        let unwrappedDomainMasterKey = try keyManager.unwrapDomainMasterKey(
            from: record,
            wrappingRootKey: wrappingRootKey
        )

        XCTAssertTrue(rawSecret.allSatisfy { $0 == 0 })
        XCTAssertNotEqual(firstDomainWrappingKey, secondDomainWrappingKey)
        XCTAssertEqual(record.nonce.count, 12)
        XCTAssertEqual(record.tag.count, 16)
        XCTAssertEqual(record.ciphertext.count, 32)
        XCTAssertEqual(unwrappedDomainMasterKey, domainMasterKey)
    }

    func test_domainKeyManager_unwrapRejectsMalformedRecordLengths() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataMalformedRecord")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        var rawSecret = Data(repeating: 0x33, count: 32)
        let wrappingRootKey = try keyManager.deriveWrappingRootKey(from: &rawSecret)
        let malformedRecord = AppWrappedDomainMasterKeyRecord(
            formatVersion: 1,
            domainID: "contacts",
            nonce: Data(repeating: 0x01, count: 8),
            ciphertext: Data(repeating: 0x02, count: 31),
            tag: Data(repeating: 0x03, count: 15)
        )

        XCTAssertThrowsError(
            try keyManager.unwrapDomainMasterKey(
                from: malformedRecord,
                wrappingRootKey: wrappingRootKey
            )
        )
    }

    func test_sensitiveBytes_zeroize_clearsOwnedStorage() {
        var sensitiveBytes = CypherAir.SensitiveBytes(data: Data(repeating: 0xAB, count: 8))

        sensitiveBytes.zeroize()

        XCTAssertEqual(sensitiveBytes.dataCopy(), Data(repeating: 0x00, count: 8))
    }

    func test_sessionCoordinator_authorizeAndRelockClearsWrappingRootKeyAndUnlockedDomainKeys() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSession")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.session",
            secretData: Data(repeating: 0xAB, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.session"
        )
        let participant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(participant)

        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.session",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test authorization"
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xCD, count: 32), for: "contacts")

        XCTAssertEqual(authorizationResult, .authorized)
        XCTAssertEqual(coordinator.frameworkState, .sessionAuthorized)
        XCTAssertTrue(coordinator.hasActiveWrappingRootKey)
        XCTAssertTrue(keyManager.hasUnlockedDomainMasterKeys)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 1)

        await coordinator.relockCurrentSession()

        XCTAssertEqual(participant.relockCallCount, 1)
        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
        XCTAssertEqual(rightStoreClient.persistedRightHandle?.deauthorizeCallCount, 1)
    }

    func test_sessionCoordinator_relockParticipantFailure_entersRestartRequired() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataRestartRequired")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.restart",
            secretData: Data(repeating: 0xAC, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.restart"
        )
        let participant = MockProtectedDataRelockParticipant()
        participant.shouldThrow = true
        coordinator.registerRelockParticipant(participant)

        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.restart",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test authorization"
        )
        await coordinator.relockCurrentSession()

        XCTAssertEqual(authorizationResult, .authorized)
        XCTAssertEqual(participant.relockCallCount, 1)
        XCTAssertEqual(coordinator.frameworkState, .restartRequired)
        let blockedResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Blocked after restartRequired"
        )
        XCTAssertEqual(blockedResult, .frameworkRecoveryNeeded)
    }

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
        let contactsDirectory = makeTemporaryDirectory("ProtectedDataStartupContacts")
        defer { try? FileManager.default.removeItem(at: protectedDataBaseDirectory) }
        defer { try? FileManager.default.removeItem(at: contactsDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: protectedDataBaseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: AppProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let recoveryCoordinator = AppProtectedDomainRecoveryCoordinator(registryStore: registryStore)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let protectedDataSessionCoordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: AppProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let protectedSettingsStore = ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager
        )
        protectedDataSessionCoordinator.registerRelockParticipant(protectedSettingsStore)
        let appSessionOrchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                try recoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { config.gracePeriod },
            requireAuthOnLaunchProvider: { config.requireAuthOnLaunch },
            evaluateAppAuthentication: { reason in
                try await authManager.evaluate(mode: config.authMode, reason: reason)
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let contactService = ContactService(engine: engine, contactsDirectory: contactsDirectory)
        let encryptionService = EncryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let decryptionService = DecryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let passwordMessageService = PasswordMessageService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let signingService = SigningService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let certificateSignatureService = CertificateSignatureService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let qrService = QRService(engine: engine)
        let selfTestService = SelfTestService(engine: engine)
        let container = AppAppContainer(
            authLifecycleTraceStore: nil,
            authenticationShieldCoordinator: CypherAir.AuthenticationShieldCoordinator(),
            authPromptCoordinator: authPromptCoordinator,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedDataStorageRoot: storageRoot,
            protectedDataRegistryStore: registryStore,
            protectedDomainKeyManager: domainKeyManager,
            protectedDomainRecoveryCoordinator: recoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            protectedSettingsStore: protectedSettingsStore,
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
            contactsDirectory: contactsDirectory,
            defaultsSuiteName: defaultsSuiteName
        )

        let snapshot = AppAppStartupCoordinator().performPreAuthBootstrap(using: container)

        guard case .emptySteadyState(_, let didBootstrap) = snapshot.bootstrapOutcome else {
            return XCTFail("Expected empty steady-state startup snapshot, got \(snapshot.bootstrapOutcome)")
        }
        XCTAssertEqual(snapshot.protectedDataFrameworkState, AppProtectedDataFrameworkState.sessionLocked)
        XCTAssertTrue(didBootstrap)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
        XCTAssertEqual(rightStoreClient.saveWithoutSecretCallCount, 0)
        XCTAssertEqual(rightStoreClient.saveWithSecretCallCount, 0)
        XCTAssertEqual(protectedDataSessionCoordinator.frameworkState, AppProtectedDataFrameworkState.sessionLocked)
    }

    func test_handleResume_externalAuthenticationPromptInProgress_skipsRelockAndAuthentication() async throws {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResumeSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resume-suppression",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return true
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
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResignSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resign-suppression",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in true },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        defer { authPromptCoordinator.endOperationPrompt() }

        orchestrator.handleSceneDidResignActive()

        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_lateLifecycleAfterOperationPromptEnds_doesNotTriggerPrivacyResumeAuthentication() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataLateLifecycleSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.late-lifecycle",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return true
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        var gate = AppPrivacyScreenLifecycleGate()

        authPromptCoordinator.beginOperationPrompt()
        authPromptCoordinator.endOperationPrompt()

        gate.syncOperationAuthenticationAttemptGeneration(
            orchestrator.operationAuthenticationAttemptGeneration
        )
        if gate.shouldHandleInactive(
            isAuthenticating: orchestrator.isAuthenticating,
            isOperationPromptInProgress: orchestrator.isOperationAuthenticationPromptInProgress
        ) {
            orchestrator.handleSceneDidResignActive()
        }

        gate.syncOperationAuthenticationAttemptGeneration(
            orchestrator.operationAuthenticationAttemptGeneration
        )
        let attemptedAuthentication: Bool
        if gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            isOperationPromptInProgress: orchestrator.isOperationAuthenticationPromptInProgress
        ) {
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Late lifecycle after operation prompt"
            )
        } else {
            attemptedAuthentication = false
        }

        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleSceneDidEnterBackground_duringExternalAuthenticationPrompt_blursPrivacyScreen() {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataBackgroundSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.background-suppression",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in true },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        defer { authPromptCoordinator.endOperationPrompt() }

        orchestrator.handleSceneDidEnterBackground()

        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_successfulAuthentication_doesNotActivateProtectedDataSession() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResumeNoWarmUp")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resume-no-warmup",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in true },
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
    }

    func test_handleResume_afterBackgroundFollowingOperationPrompt_treatsReturnAsRealResume() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResumeAfterBackground")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resume-after-background",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return true
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        orchestrator.handleSceneDidEnterBackground()
        authPromptCoordinator.endOperationPrompt()

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Resume after a real background should still re-authenticate"
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

    func test_accessGate_emptySteadyState_returnsNoProtectedDomainPresent() throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessEmpty"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.empty"
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("Should not be called") },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in true },
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
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
    }

    func test_accessGate_continuePendingMutation_returnsPendingMutationRecoveryRequired() throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessPending"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.pending"
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("Should not be called") },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in true },
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
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
    }

    func test_accessGate_readyRegistryWithoutAuthorization_requiresAuthorization() throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessAuth"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.auth"
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("Should not be called") },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in true },
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
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessAlreadyAuthorized"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.gate.reuse",
            secretData: Data(repeating: 0xAD, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
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

        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { registry },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in true },
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
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessFrameworkRecovery"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
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

        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { registry },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in true },
            protectedDataSessionCoordinator: coordinator
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .frameworkRecoveryNeeded)
    }

    func test_accessGate_readyRegistryWithRestartRequired_returnsFrameworkRecoveryNeeded() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessRestartRequired"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.gate.restart-required",
            secretData: Data(repeating: 0xB0, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
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

        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { registry },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in true },
            protectedDataSessionCoordinator: coordinator
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .frameworkRecoveryNeeded)
    }

    func test_authorization_missingRight_returnsFrameworkRecoveryNeeded() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationMissingRight"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
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

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )

        XCTAssertEqual(result, .frameworkRecoveryNeeded)
        XCTAssertEqual(coordinator.frameworkState, .frameworkRecoveryNeeded)
    }

    func test_authorization_secretUnreadable_returnsFrameworkRecoveryNeededAndDeauthorizes() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationUnreadableSecret"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let handle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.authorization.secret",
            secretData: Data(repeating: 0xAE, count: 32)
        )
        handle.rawSecretError = ProtectedDataError.internalFailure("secret unreadable")
        rightStoreClient.persistedRightHandle = handle
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
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

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )

        XCTAssertEqual(result, .frameworkRecoveryNeeded)
        XCTAssertEqual(handle.deauthorizeCallCount, 1)
        XCTAssertEqual(coordinator.frameworkState, .frameworkRecoveryNeeded)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
    }

    func test_authorization_userCancelled_returnsCancelledOrDenied() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationCancelled"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let handle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.authorization.cancelled",
            secretData: Data(repeating: 0xAF, count: 32)
        )
        handle.authorizeError = AuthenticationError.cancelled
        rightStoreClient.persistedRightHandle = handle
        let coordinator = AppProtectedDataSessionCoordinator(
            rightStoreClient: rightStoreClient,
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

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.pending-create"
        )
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

        let outcome = try await registryStore.recoverPendingMutation(
            targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
            continueDelete: { _ in }
        )

        XCTAssertEqual(outcome, AppPendingRecoveryOutcome.resetRequired)
    }

    func test_abandonPendingCreate_clearsPendingMutationAndArtifacts() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonPendingCreate")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.abandon-create.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-create"
        )
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
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

    func test_completePendingDelete_clearsCleanupPendingAndPendingMutation() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataCompletePendingDelete")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.complete-delete.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.complete-delete"
        )
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
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

private func XCTAssertThrowsErrorAsync(
    _ expression: @escaping () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await expression()
        XCTFail("Expected expression to throw.", file: file, line: line)
    } catch {
    }
}
