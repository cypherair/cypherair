import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

@MainActor
final class LocalDataResetServiceTests: XCTestCase {
    func test_resetAllLocalData_removesStorageAndClearsMemoryState() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        defer {
            try? FileManager.default.removeItem(
                at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
            )
            if let legacySelfTestReportsDirectory = container.legacySelfTestReportsDirectory {
                try? FileManager.default.removeItem(at: legacySelfTestReportsDirectory.deletingLastPathComponent())
            }
            if let defaultsSuiteName = container.defaultsSuiteName {
                UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
            }
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
        try container.keychain.save(
            Data([0x06]),
            service: KeychainConstants.protectedDataDeviceBindingKeyService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try container.keychain.save(
            Data([0x07]),
            service: KeychainConstants.protectedDataRootSecretFormatFloorService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try container.keychain.save(
            Data([0x08]),
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        try container.protectedDataStorageRoot.ensureRootDirectoryExists()
        let protectedMarker = container.protectedDataStorageRoot.rootURL
            .appendingPathComponent("reset-marker.txt")
        try Data([0x03]).write(to: protectedMarker)

        let legacySelfTestReportsDirectory = try XCTUnwrap(container.legacySelfTestReportsDirectory)
        try FileManager.default.createDirectory(
            at: legacySelfTestReportsDirectory,
            withIntermediateDirectories: true
        )
        try Data("legacy self-test report".utf8).write(
            to: legacySelfTestReportsDirectory.appendingPathComponent("self-test-legacy.txt")
        )
        await container.selfTestService.runAllTests()
        XCTAssertNotNil(container.selfTestService.latestReport)

        container.protectedOrdinarySettingsCoordinator.setHasCompletedOnboarding(true)
        container.protectedOrdinarySettingsCoordinator.setEncryptToSelf(false)

        let summary = try await container.localDataResetService.resetAllLocalData()

        XCTAssertGreaterThanOrEqual(summary.deletedKeychainItemCount, 5)
        XCTAssertFalse(container.keychain.exists(service: markerService, account: KeychainConstants.defaultAccount))
        XCTAssertFalse(container.keychain.exists(
            service: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(container.keychain.exists(
            service: KeychainConstants.protectedDataDeviceBindingKeyService,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(container.keychain.exists(
            service: KeychainConstants.protectedDataRootSecretFormatFloorService,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(container.keychain.exists(
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(FileManager.default.fileExists(atPath: container.protectedDataStorageRoot.rootURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacySelfTestReportsDirectory.path))
        XCTAssertNil(container.protectedOrdinarySettingsCoordinator.snapshot)
        XCTAssertEqual(container.protectedOrdinarySettingsCoordinator.state, .locked)
        XCTAssertNil(container.selfTestService.latestReport)
        XCTAssertTrue(container.keyManagement.keys.isEmpty)
        XCTAssertTrue(container.contactService.testContactKeyRecords.isEmpty)

        let traceNames = container.authLifecycleTraceStore?.recentEntries.map(\.name) ?? []
        XCTAssertTrue(traceNames.contains("localDataReset.start"))
        XCTAssertTrue(traceNames.contains("localDataReset.finish"))
        XCTAssertTrue(traceNames.contains("localDataReset.validation.finish"))
    }

    func test_resetAllLocalData_missingProtectedDataBaseValidatesCleanAndPreservesResetAuth() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirResetMissingBase-\(UUID().uuidString)", isDirectory: true)
        let temporaryArtifactStore = CypherAir.AppTemporaryArtifactStore(temporaryDirectory: temporaryDirectory)
        defer {
            try? FileManager.default.removeItem(
                at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
            )
            try? FileManager.default.removeItem(at: temporaryDirectory)
            if let legacySelfTestReportsDirectory = container.legacySelfTestReportsDirectory {
                try? FileManager.default.removeItem(at: legacySelfTestReportsDirectory.deletingLastPathComponent())
            }
            if let defaultsSuiteName = container.defaultsSuiteName {
                UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
            }
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
        let validationEntry = try XCTUnwrap(
            container.authLifecycleTraceStore?.recentEntries.last {
                $0.name == "localDataReset.validation.finish"
            }
        )
        XCTAssertEqual(validationEntry.metadata["result"], "clean")
        XCTAssertEqual(validationEntry.metadata["hasProtectedDataArtifacts"], "false")
    }

    func test_resetAllLocalData_cleansPhase7TemporaryArtifactsAndTutorialDefaultsSuites() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirResetTemp-\(UUID().uuidString)", isDirectory: true)
        let store = CypherAir.AppTemporaryArtifactStore(temporaryDirectory: temporaryDirectory)
        let fixedTutorialSuiteName = AppTemporaryArtifactStore.tutorialSandboxDefaultsSuiteName
        let legacyTutorialSuiteName = "com.cypherair.tutorial.\(UUID().uuidString)"
        let similarTutorialSuiteName = "com.cypherair.tutorial.not-a-uuid-\(UUID().uuidString)"
        let unrelatedSuiteName = "com.cypherair.tests.tutorial.\(UUID().uuidString)"
        defer {
            cleanup(container)
            try? FileManager.default.removeItem(at: temporaryDirectory)
            UserDefaults(suiteName: fixedTutorialSuiteName)?.removePersistentDomain(forName: fixedTutorialSuiteName)
            UserDefaults(suiteName: legacyTutorialSuiteName)?.removePersistentDomain(forName: legacyTutorialSuiteName)
            UserDefaults(suiteName: similarTutorialSuiteName)?.removePersistentDomain(forName: similarTutorialSuiteName)
            UserDefaults(suiteName: unrelatedSuiteName)?.removePersistentDomain(forName: unrelatedSuiteName)
        }

        try makePhase7TemporaryArtifacts(in: temporaryDirectory)
        let fixedTutorialDefaults = try XCTUnwrap(UserDefaults(suiteName: fixedTutorialSuiteName))
        fixedTutorialDefaults.set("fixed", forKey: "marker")
        _ = fixedTutorialDefaults.synchronize()
        let legacyTutorialDefaults = try XCTUnwrap(UserDefaults(suiteName: legacyTutorialSuiteName))
        legacyTutorialDefaults.set("orphan", forKey: "marker")
        _ = legacyTutorialDefaults.synchronize()
        let similarTutorialDefaults = try XCTUnwrap(UserDefaults(suiteName: similarTutorialSuiteName))
        similarTutorialDefaults.set("keep", forKey: "marker")
        _ = similarTutorialDefaults.synchronize()
        let unrelatedDefaults = try XCTUnwrap(UserDefaults(suiteName: unrelatedSuiteName))
        unrelatedDefaults.set("keep", forKey: "marker")
        _ = unrelatedDefaults.synchronize()

        let resetService = makeResetService(
            from: container,
            temporaryArtifactStore: store
        )

        _ = try await resetService.resetAllLocalData()

        XCTAssertTrue(store.remainingTemporaryArtifacts().isEmpty)
        XCTAssertNil(UserDefaults(suiteName: fixedTutorialSuiteName)?.string(forKey: "marker"))
        XCTAssertNil(UserDefaults(suiteName: legacyTutorialSuiteName)?.string(forKey: "marker"))
        XCTAssertEqual(UserDefaults(suiteName: similarTutorialSuiteName)?.string(forKey: "marker"), "keep")
        XCTAssertEqual(UserDefaults(suiteName: unrelatedSuiteName)?.string(forKey: "marker"), "keep")
    }

    func test_resetAllLocalData_removesSecureEnclaveCustodyHandles() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        defer {
            cleanup(container)
        }
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let handleStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "resetcleanup" }
        )
        _ = try handleStore.createHandlePair()
        keyStore.insertMalformedApplicationTag(
            "\(SecureEnclaveCustodyHandleReference.applicationTagPrefix).reset-malformed"
        )
        let resetService = makeResetService(
            from: container,
            secureEnclaveCustodyHandleStore: handleStore
        )

        let summary = try await resetService.resetAllLocalData()

        XCTAssertEqual(keyStore.storedHandleCount(), 0)
        let cleanupEntry = try XCTUnwrap(
            container.authLifecycleTraceStore?.recentEntries.last {
                $0.name == "localDataReset.secureEnclaveCustody.cleanup.finish"
            }
        )
        XCTAssertEqual(cleanupEntry.metadata["serviceKind"], "secureEnclaveCustodyHandle")
        XCTAssertEqual(cleanupEntry.metadata["result"], "success")
        XCTAssertEqual(cleanupEntry.metadata["deletedHandleCount"], "3")
        XCTAssertFalse(cleanupEntry.metadata.values.contains { $0.contains("resetcleanup") })
        XCTAssertFalse(cleanupEntry.metadata.values.contains { $0.contains("secure-enclave-custody") })
    }

    func test_resetAllLocalData_failsClosedWhenSecureEnclaveCustodyCleanupFails() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        defer {
            cleanup(container)
        }
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let handleStore = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { "sensitive-reset-id" }
        )
        _ = try handleStore.createHandlePair()
        keyStore.failDeleteRole = .signing
        let resetService = makeResetService(
            from: container,
            secureEnclaveCustodyHandleStore: handleStore
        )

        await XCTAssertThrowsErrorAsync({
            try await resetService.resetAllLocalData()
        }) { error in
            guard let resetError = error as? LocalDataResetError else {
                XCTFail("Expected LocalDataResetError, got \(type(of: error))")
                return
            }
            XCTAssertTrue(
                resetError.failures.contains("keychain.secureEnclaveCustodyHandle.cleanupOrRollbackFailure")
            )
            XCTAssertTrue(
                resetError.failures.contains("keychain.secureEnclaveCustodyHandle.remaining.1")
            )
            XCTAssertFalse(resetError.failures.contains { $0.contains("sensitive-reset-id") })
            XCTAssertFalse(resetError.failures.contains { $0.contains("secure-enclave-custody") })
        }
    }

    func test_resetAllLocalData_failsClosedWhenSecureEnclaveCustodyInventoryFails() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        defer {
            cleanup(container)
        }
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failInventory = true
        let handleStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let resetService = makeResetService(
            from: container,
            secureEnclaveCustodyHandleStore: handleStore
        )

        await XCTAssertThrowsErrorAsync({
            try await resetService.resetAllLocalData()
        }) { error in
            guard let resetError = error as? LocalDataResetError else {
                XCTFail("Expected LocalDataResetError, got \(type(of: error))")
                return
            }
            XCTAssertTrue(
                resetError.failures.contains("keychain.secureEnclaveCustodyHandle.cleanupOrRollbackFailure")
            )
            XCTAssertTrue(
                resetError.failures.contains(
                    "keychain.remaining.secureEnclaveCustodyHandle.privateHandleInaccessible"
                )
            )
        }
    }

    func test_resetAllLocalData_reportsRemainingDataWhenDeviceBindingKeyRowRemains() async throws {
        try await assertResetValidationReportsRemainingProtectedRow(
            service: KeychainConstants.protectedDataDeviceBindingKeyService,
            metadataKey: "hasDeviceBindingKey",
            expectedFailure: "keychain.protectedDataDeviceBindingKey.remaining"
        )
    }

    func test_resetAllLocalData_reportsRemainingDataWhenFormatFloorRowRemains() async throws {
        try await assertResetValidationReportsRemainingProtectedRow(
            service: KeychainConstants.protectedDataRootSecretFormatFloorService,
            metadataKey: "hasFormatFloor",
            expectedFailure: "keychain.protectedDataRootSecretFormatFloor.remaining"
        )
    }

    func test_resetAllLocalData_reportsRemainingDataWhenLegacyCleanupRowRemains() async throws {
        try await assertResetValidationReportsRemainingProtectedRow(
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            metadataKey: "hasLegacyCleanup",
            expectedFailure: "keychain.protectedDataRootSecretLegacyCleanup.remaining"
        )
    }

    func test_resetAllLocalData_failsWhenRootSecretStillExistsAfterReset() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
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
            guard let resetError = error as? LocalDataResetError else {
                XCTFail("Expected LocalDataResetError, got \(type(of: error))")
                return
            }
            XCTAssertTrue(resetError.failures.contains("keychain.protectedDataRootSecret.remaining"))
        }
    }

    func test_resetAllLocalData_failsWhenKeychainPrefixItemsRemain() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        defer {
            cleanup(container)
        }

        try container.keychain.save(
            Data([0x01]),
            service: "\(KeychainConstants.prefix).residual",
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        if let mockKeychain = container.keychain as? MockKeychain {
            mockKeychain.failOnDeleteNumber = 1
        }

        await XCTAssertThrowsErrorAsync({
            try await container.localDataResetService.resetAllLocalData()
        }) { error in
            guard let resetError = error as? LocalDataResetError else {
                XCTFail("Expected LocalDataResetError, got \(type(of: error))")
                return
            }
            XCTAssertTrue(resetError.failures.contains { $0.hasPrefix("keychain.default.remaining.") })
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
            source: "test",
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
            source: "test",
            loadCurrentRegistry: { registry }
        )

        XCTAssertEqual(outcome, .blockedByArtifacts)
    }

    private func cleanup(_ container: AppContainer) {
        try? FileManager.default.removeItem(
            at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
        )
        if let legacySelfTestReportsDirectory = container.legacySelfTestReportsDirectory {
            try? FileManager.default.removeItem(at: legacySelfTestReportsDirectory.deletingLastPathComponent())
        }
        if let defaultsSuiteName = container.defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
        }
    }

    private func makeResetService(
        from container: AppContainer,
        keychain: (any KeychainManageable)? = nil,
        temporaryArtifactStore: CypherAir.AppTemporaryArtifactStore? = nil,
        protectedDataRootSecretExists: @escaping () -> Bool = { false },
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore? = nil
    ) -> LocalDataResetService {
        let defaultsSuiteName = container.defaultsSuiteName ?? UUID().uuidString
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        return LocalDataResetService(
            keychain: keychain ?? container.keychain,
            protectedDataStorageRoot: container.protectedDataStorageRoot,
            defaults: defaults,
            defaultsDomainName: defaultsSuiteName,
            config: container.config,
            protectedOrdinarySettingsCoordinator: container.protectedOrdinarySettingsCoordinator,
            authManager: container.authManager,
            keyManagement: container.keyManagement,
            contactService: container.contactService,
            selfTestService: container.selfTestService,
            protectedDataSessionCoordinator: container.protectedDataSessionCoordinator,
            appSessionOrchestrator: container.appSessionOrchestrator,
            appLockController: container.appLockController,
            temporaryArtifactStore: temporaryArtifactStore,
            legacySelfTestReportsDirectory: container.legacySelfTestReportsDirectory,
            protectedDataRootSecretExists: protectedDataRootSecretExists,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
            traceStore: container.authLifecycleTraceStore
        )
    }

    private func makePhase7TemporaryArtifacts(in temporaryDirectory: URL) throws {
        let decryptedDir = temporaryDirectory.appendingPathComponent("decrypted", isDirectory: true)
        let streamingDir = temporaryDirectory.appendingPathComponent("streaming", isDirectory: true)
        let exportURL = temporaryDirectory.appendingPathComponent("export-\(UUID().uuidString)-sample.asc")
        let tutorialDir = temporaryDirectory
            .appendingPathComponent("CypherAirGuidedTutorial-\(UUID().uuidString)", isDirectory: true)

        try FileManager.default.createDirectory(
            at: decryptedDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: streamingDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(at: tutorialDir, withIntermediateDirectories: true)
        try Data("export".utf8).write(to: exportURL, options: .atomic)
    }

    private func assertResetValidationReportsRemainingProtectedRow(
        service: String,
        metadataKey: String,
        expectedFailure: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        defer {
            cleanup(container)
        }
        let residualKeychain = ResidualProtectedResetRowKeychain(
            base: container.keychain,
            residualService: service
        )
        let resetService = makeResetService(
            from: container,
            keychain: residualKeychain
        )
        var thrownResetError: LocalDataResetError?

        await XCTAssertThrowsErrorAsync({
            try await resetService.resetAllLocalData()
        }) { error in
            guard let resetError = error as? LocalDataResetError else {
                XCTFail("Expected LocalDataResetError, got \(type(of: error))", file: file, line: line)
                return
            }
            thrownResetError = resetError
        }

        let resetError = try XCTUnwrap(thrownResetError, file: file, line: line)
        XCTAssertTrue(resetError.failures.contains(expectedFailure), file: file, line: line)
        let validationEntry = try XCTUnwrap(
            container.authLifecycleTraceStore?.recentEntries.last {
                $0.name == "localDataReset.validation.finish"
            },
            file: file,
            line: line
        )
        XCTAssertEqual(validationEntry.metadata["result"], "remainingData", file: file, line: line)
        XCTAssertEqual(validationEntry.metadata[metadataKey], "true", file: file, line: line)
        XCTAssertEqual(validationEntry.metadata["remainingDefaultKeychainItemCount"], "0", file: file, line: line)
    }
}

private final class ProtectedDataRootSecretFlag: @unchecked Sendable {
    var exists: Bool

    init(exists: Bool) {
        self.exists = exists
    }
}

private final class ResidualProtectedResetRowKeychain: KeychainManageable {
    private let base: any KeychainManageable
    private let residualService: String

    init(base: any KeychainManageable, residualService: String) {
        self.base = base
        self.residualService = residualService
    }

    func save(_ data: Data, service: String, account: String, accessControl: SecAccessControl?) throws {
        try base.save(data, service: service, account: account, accessControl: accessControl)
    }

    func load(service: String, account: String, authenticationContext: LAContext?) throws -> Data {
        try base.load(service: service, account: account, authenticationContext: authenticationContext)
    }

    func delete(service: String, account: String, authenticationContext: LAContext?) throws {
        guard !isResidualRow(service: service, account: account) else {
            return
        }
        try base.delete(service: service, account: account, authenticationContext: authenticationContext)
    }

    func exists(service: String, account: String, authenticationContext: LAContext?) -> Bool {
        if isResidualRow(service: service, account: account) {
            return true
        }
        return base.exists(service: service, account: account, authenticationContext: authenticationContext)
    }

    func listItems(servicePrefix: String, account: String, authenticationContext: LAContext?) throws -> [String] {
        try base.listItems(
            servicePrefix: servicePrefix,
            account: account,
            authenticationContext: authenticationContext
        ).filter { service in
            !isResidualRow(service: service, account: account)
        }
    }

    private func isResidualRow(service: String, account: String) -> Bool {
        service == residualService && account == KeychainConstants.defaultAccount
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
