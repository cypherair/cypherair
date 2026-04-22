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
private typealias AppWrappedDomainMasterKeyRecord = CypherAir.WrappedDomainMasterKeyRecord

private final class MockProtectedDataPersistedRightHandle: AppProtectedDataPersistedRightHandle {
    let identifier: String
    private let secretData: Data

    private(set) var authorizeCallCount = 0
    private(set) var deauthorizeCallCount = 0

    init(identifier: String, secretData: Data) {
        self.identifier = identifier
        self.secretData = secretData
    }

    func authorize(localizedReason: String) async throws {
        authorizeCallCount += 1
    }

    func deauthorize() async {
        deauthorizeCallCount += 1
    }

    func rawSecretData() async throws -> Data {
        secretData
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

        XCTAssertEqual(result.bootstrapState, .bootstrappedEmptyRegistry)
        XCTAssertEqual(result.frameworkState, .sessionLocked)
        XCTAssertTrue(result.didBootstrapEmptyRegistry)
        XCTAssertTrue(FileManager.default.fileExists(atPath: storageRoot.registryURL.path))
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

        XCTAssertEqual(result.bootstrapState, .frameworkRecoveryNeeded)
        XCTAssertEqual(result.frameworkState, .frameworkRecoveryNeeded)
        XCTAssertFalse(result.didBootstrapEmptyRegistry)
        XCTAssertFalse(FileManager.default.fileExists(atPath: storageRoot.registryURL.path))
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

        try await coordinator.authorizeSharedRight(localizedReason: "ProtectedData unit test authorization")
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xCD, count: 32), for: "contacts")

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

        try await coordinator.authorizeSharedRight(localizedReason: "ProtectedData unit test authorization")
        await coordinator.relockCurrentSession()

        XCTAssertEqual(participant.relockCallCount, 1)
        XCTAssertEqual(coordinator.frameworkState, .restartRequired)
        await XCTAssertThrowsErrorAsync {
            try await coordinator.authorizeSharedRight(localizedReason: "Blocked after restartRequired")
        }
    }

    func test_preAuthBootstrap_doesNotTouchRightStoreClient() throws {
        let engine = PgpEngine()
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let defaultsSuiteName = "com.cypherair.tests.protected-data.startup.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults
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
            sharedRightIdentifier: AppProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let appSessionOrchestrator = AppAppSessionOrchestrator(
            gracePeriodProvider: { config.gracePeriod },
            requireAuthOnLaunchProvider: { config.requireAuthOnLaunch },
            evaluateAppAuthentication: { reason in
                try await authManager.evaluate(mode: config.authMode, reason: reason)
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator
        )
        let keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults
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
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedDataStorageRoot: storageRoot,
            protectedDataRegistryStore: registryStore,
            protectedDomainKeyManager: domainKeyManager,
            protectedDomainRecoveryCoordinator: recoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
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

        XCTAssertEqual(snapshot.protectedDataBootstrapState, AppProtectedDataBootstrapState.bootstrappedEmptyRegistry)
        XCTAssertEqual(snapshot.protectedDataFrameworkState, AppProtectedDataFrameworkState.sessionLocked)
        XCTAssertTrue(snapshot.didBootstrapEmptyRegistry)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
        XCTAssertEqual(rightStoreClient.saveWithoutSecretCallCount, 0)
        XCTAssertEqual(rightStoreClient.saveWithSecretCallCount, 0)
        XCTAssertEqual(protectedDataSessionCoordinator.frameworkState, AppProtectedDataFrameworkState.sessionLocked)
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
