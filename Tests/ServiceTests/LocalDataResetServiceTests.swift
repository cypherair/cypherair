import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

@MainActor
final class LocalDataResetServiceTests: XCTestCase {
    func test_resetAllLocalData_removesStorageAndClearsMemoryState() async throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }

        let markerService = "\(KeychainConstants.prefix).test-reset-marker.ABCDEF"
        try container.keychain.save(
            Data([0x01]),
            service: markerService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try container.keychain.save(
            Data([0x02]),
            service: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        let classicalComponentService = KeychainConstants.splitCustodyClassicalComponentService(
            fingerprint: "0123456789abcdef0123456789abcdef01234567"
        )
        try container.keychain.save(
            Data([0x09]),
            service: classicalComponentService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        let committedDomainKeyService = KeychainConstants.protectedDataDomainKeyService(domainID: "contacts")
        let stagedDomainKeyService = KeychainConstants.stagedProtectedDataDomainKeyService(domainID: "contacts")
        try container.keychain.save(
            Data([0x07]),
            service: committedDomainKeyService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try container.keychain.save(
            Data([0x08]),
            service: stagedDomainKeyService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        try container.protectedDataStorageRoot.ensureRootDirectoryExists()
        let protectedMarker = container.protectedDataStorageRoot.rootURL
            .appendingPathComponent("reset-marker.txt")
        try Data([0x03]).write(to: protectedMarker)

        await container.selfTestService.runAllTests()
        XCTAssertNotNil(container.selfTestService.latestReport)

        container.protectedOrdinarySettingsCoordinator.setHasCompletedOnboarding(true)
        container.protectedOrdinarySettingsCoordinator.setEncryptToSelf(false)

        let summary = try await container.localDataResetService.resetAllLocalData()

        XCTAssertGreaterThanOrEqual(summary.deletedKeychainItemCount, 4)
        XCTAssertFalse(container.keychain.exists(service: markerService, account: KeychainConstants.defaultAccount))
        XCTAssertFalse(container.keychain.exists(
            service: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(container.keychain.exists(
            service: classicalComponentService,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(container.keychain.exists(
            service: committedDomainKeyService,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(container.keychain.exists(
            service: stagedDomainKeyService,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(FileManager.default.fileExists(atPath: container.protectedDataStorageRoot.rootURL.path))
        XCTAssertNil(container.protectedOrdinarySettingsCoordinator.snapshot)
        XCTAssertEqual(container.protectedOrdinarySettingsCoordinator.state, .locked)
        XCTAssertNil(container.selfTestService.latestReport)
        XCTAssertTrue(container.keyManagement.keys.isEmpty)
        XCTAssertTrue(container.contactService.testContactKeyRecords.isEmpty)
    }

    func test_resetAllLocalData_missingProtectedDataBaseValidatesCleanAndPreservesResetAuth() async throws {
        let container = AppContainer.makeUITest()
        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirResetMissingBase-\(UUID().uuidString)", isDirectory: true)
        let temporaryArtifactStore = CypherAir.AppTemporaryArtifactStore(temporaryDirectory: temporaryDirectory)
        defer {
            cleanup(container)
            try? FileManager.default.removeItem(at: temporaryDirectory)
        }

        let protectedDataBaseDirectory = container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: protectedDataBaseDirectory)

        let resetService = makeResetService(
            from: container,
            temporaryArtifactStore: temporaryArtifactStore
        )
        _ = try await resetService.resetAllLocalData(
            authenticationContext: LAContext()
        )

        XCTAssertFalse(FileManager.default.fileExists(atPath: container.protectedDataStorageRoot.rootURL.path))
        XCTAssertNotNil(container.appSessionOrchestrator.lastAuthenticationDate)
    }

    func test_resetAllLocalData_cleansTemporaryArtifacts() async throws {
        let container = AppContainer.makeUITest()
        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirResetTemp-\(UUID().uuidString)", isDirectory: true)
        let store = CypherAir.AppTemporaryArtifactStore(temporaryDirectory: temporaryDirectory)
        defer {
            cleanup(container)
            try? FileManager.default.removeItem(at: temporaryDirectory)
        }

        try makeSweepableTemporaryArtifacts(in: temporaryDirectory)

        let resetService = makeResetService(
            from: container,
            temporaryArtifactStore: store
        )

        _ = try await resetService.resetAllLocalData()

        XCTAssertTrue(store.remainingTemporaryArtifacts().isEmpty)
    }

    func test_resetAllLocalData_erasesPersistedPreferenceKeys() async throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }
        container.config.beginAppSessionAuthenticationPolicySwitch(to: .biometricsOnly)
        container.config.completeAppSessionAuthenticationPolicySwitch(to: .biometricsOnly)
        XCTAssertFalse(container.config.persistedPreferenceKeysRemaining.isEmpty)
        let resetService = makeResetService(from: container)

        _ = try await resetService.resetAllLocalData()

        XCTAssertTrue(container.config.persistedPreferenceKeysRemaining.isEmpty)
        XCTAssertEqual(container.config.appSessionAuthenticationPolicy, .userPresence)
    }

    func test_resetAllLocalData_failsWhenPreferenceKeySurvives() async throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }
        let stubbornPreferences = RemovalIgnoringPreferenceStorage()
        stubbornPreferences.setString(
            AppSessionAuthenticationPolicy.biometricsOnly.rawValue,
            forKey: AppConfiguration.appSessionAuthenticationPolicyKey
        )
        let resetService = makeResetService(
            from: container,
            config: AppConfiguration(preferences: stubbornPreferences)
        )

        await XCTAssertThrowsErrorAsync({
            try await resetService.resetAllLocalData()
        }) { error in
            XCTAssertTrue(error is LocalDataResetError, "Expected LocalDataResetError, got \(type(of: error))")
        }
    }

    func test_resetAllLocalData_removesSecureEnclaveCustodyHandles() async throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let handleStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            tier: .classicalP256,
            handleSetIdentifierGenerator: { "7265736574636c65616e7570" }
        )
        _ = try handleStore.createLoadedHandlePair(authenticationContext: nil)
        // The unified sweep also removes composite-tier rows and rows whose
        // attributes no longer decode.
        let compositeStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            tier: .postQuantum
        )
        _ = try compositeStore.createLoadedHandlePair(authenticationContext: nil)
        keyStore.insertMalformedRow()
        let resetService = makeResetService(
            from: container,
            secureEnclaveCustodyHandleStore: handleStore
        )

        let summary = try await resetService.resetAllLocalData()

        XCTAssertEqual(keyStore.storedHandleCount(), 0)
    }

    func test_resetAllLocalData_failsClosedWhenSecureEnclaveCustodyCleanupFails() async throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let handleStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            tier: .classicalP256,
            handleSetIdentifierGenerator: { "73656e7369746976652d72657365742d6964" }
        )
        _ = try handleStore.createLoadedHandlePair(authenticationContext: nil)
        keyStore.failDeleteRole = .signing
        let resetService = makeResetService(
            from: container,
            secureEnclaveCustodyHandleStore: handleStore
        )

        await XCTAssertThrowsErrorAsync({
            try await resetService.resetAllLocalData()
        }) { error in
            XCTAssertTrue(error is LocalDataResetError, "Expected LocalDataResetError, got \(type(of: error))")
        }
    }

    func test_resetAllLocalData_failsClosedWhenSecureEnclaveCustodyInventoryFails() async throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        let handleStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let resetService = makeResetService(
            from: container,
            secureEnclaveCustodyHandleStore: handleStore
        )

        await XCTAssertThrowsErrorAsync({
            try await resetService.resetAllLocalData()
        }) { error in
            XCTAssertTrue(error is LocalDataResetError, "Expected LocalDataResetError, got \(type(of: error))")
        }
    }

    func test_resetAllLocalData_failsWhenRootSecretStillExistsAfterReset() async throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }
        let resetService = makeResetService(
            from: container,
            protectedDataRootSecretExists: { true }
        )

        await XCTAssertThrowsErrorAsync({
            try await resetService.resetAllLocalData()
        }) { error in
            XCTAssertTrue(error is LocalDataResetError, "Expected LocalDataResetError, got \(type(of: error))")
        }
    }

    func test_resetAllLocalData_failsWhenKeychainPrefixItemsRemain() async throws {
        let container = AppContainer.makeUITest()
        defer {
            cleanup(container)
        }

        let failingKeychain = MockKeychain()
        try failingKeychain.save(
            Data([0x01]),
            service: "\(KeychainConstants.prefix).residual",
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        failingKeychain.failOnDeleteNumber = 1
        let resetService = makeResetService(
            from: container,
            keychain: failingKeychain
        )

        await XCTAssertThrowsErrorAsync({
            try await resetService.resetAllLocalData()
        }) { error in
            XCTAssertTrue(error is LocalDataResetError, "Expected LocalDataResetError, got \(type(of: error))")
        }
    }

    func test_firstDomainSharedRightCleaner_removesOrphanedRootSecretWhenNoArtifactsRemain() async throws {
        let baseDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: baseDirectory)
        }
        let storageRoot = ProtectedDataStorageRoot(
            baseDirectory: baseDirectory,
            validationMode: .allowArbitraryBaseDirectoryForTesting
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: ProtectedSettingsStore.domainID,
                phase: .journaled
            )
        )
        let rootSecret = ProtectedDataRootSecretFlag(exists: true)
        let cleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { _ in rootSecret.exists },
            removePersistedSharedRight: { _ in rootSecret.exists = false }
        )

        let outcome = try await cleaner.cleanupJournaledFirstDomainSharedRightIfSafe(
            expectedDomainID: ProtectedSettingsStore.domainID,
            loadCurrentRegistry: { registry }
        )

        XCTAssertEqual(outcome, .removedOrphanedSharedRight)
        XCTAssertFalse(rootSecret.exists)
    }

    func test_firstDomainSharedRightCleaner_blocksWhenArtifactsRemain() async throws {
        let baseDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: baseDirectory)
        }
        let storageRoot = ProtectedDataStorageRoot(
            baseDirectory: baseDirectory,
            validationMode: .allowArbitraryBaseDirectoryForTesting
        )
        try storageRoot.ensureRootDirectoryExists()
        try Data([0x01]).write(
            to: storageRoot.rootURL.appendingPathComponent("orphan-artifact.bin")
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: ProtectedSettingsStore.domainID,
                phase: .journaled
            )
        )
        let cleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { _ in true },
            removePersistedSharedRight: { _ in XCTFail("Should not remove root secret when artifacts remain") }
        )

        let outcome = try await cleaner.cleanupJournaledFirstDomainSharedRightIfSafe(
            expectedDomainID: ProtectedSettingsStore.domainID,
            loadCurrentRegistry: { registry }
        )

        XCTAssertEqual(outcome, .blockedByArtifacts)
    }

    private func cleanup(_ container: AppContainer) {
        try? FileManager.default.removeItem(
            at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
        )
    }

    private func makeResetService(
        from container: AppContainer,
        keychain: (any KeychainManageable)? = nil,
        temporaryArtifactStore: CypherAir.AppTemporaryArtifactStore? = nil,
        config: AppConfiguration? = nil,
        protectedDataRootSecretExists: @escaping () -> Bool = { false },
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore? = nil
    ) -> LocalDataResetService {
        LocalDataResetService(
            keychain: keychain ?? container.keychain,
            protectedDataStorageRoot: container.protectedDataStorageRoot,
            config: config ?? container.config,
            protectedOrdinarySettingsCoordinator: container.protectedOrdinarySettingsCoordinator,
            keyManagement: container.keyManagement,
            contactService: container.contactService,
            selfTestService: container.selfTestService,
            protectedDataSessionCoordinator: container.protectedDataSessionCoordinator,
            appSessionOrchestrator: container.appSessionOrchestrator,
            appLockController: container.appLockController,
            temporaryArtifactStore: temporaryArtifactStore,
            protectedDataRootSecretExists: protectedDataRootSecretExists,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore
        )
    }

    private func makeSweepableTemporaryArtifacts(in temporaryDirectory: URL) throws {
        let decryptedDir = temporaryDirectory.appendingPathComponent("decrypted", isDirectory: true)
        let streamingDir = temporaryDirectory.appendingPathComponent("streaming", isDirectory: true)
        let exportURL = temporaryDirectory.appendingPathComponent("export-\(UUID().uuidString)-sample.asc")

        try FileManager.default.createDirectory(
            at: decryptedDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: streamingDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try Data("export".utf8).write(to: exportURL, options: .atomic)
    }

}

/// `AppPreferenceStorage` whose `removeValue` silently does nothing — the
/// storage fault local data reset's preference post-condition must catch.
private final class RemovalIgnoringPreferenceStorage: AppPreferenceStorage {
    private var values: [String: String] = [:]

    func string(forKey key: String) -> String? {
        values[key]
    }

    func setString(_ value: String, forKey key: String) {
        values[key] = value
    }

    func removeValue(forKey key: String) {}
}

private final class ProtectedDataRootSecretFlag: @unchecked Sendable {
    var exists: Bool

    init(exists: Bool) {
        self.exists = exists
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: () async throws -> T,
    _ errorHandler: (Error) -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}
