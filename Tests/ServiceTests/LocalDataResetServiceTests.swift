import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class LocalDataResetServiceTests: XCTestCase {
    func test_resetAllLocalData_removesStorageAndClearsMemoryState() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        defer {
            if let contactsDirectory = container.contactsDirectory {
                try? FileManager.default.removeItem(at: contactsDirectory)
            }
            if let defaultsSuiteName = container.defaultsSuiteName {
                UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
            }
        }

        let metadataService = KeychainConstants.metadataService(fingerprint: "ABCDEF")
        try container.keychain.save(
            Data([0x01]),
            service: metadataService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try container.keychain.save(
            Data([0x05]),
            service: metadataService,
            account: KeychainConstants.metadataAccount,
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

        let contactsDirectory = try XCTUnwrap(container.contactsDirectory)
        try FileManager.default.createDirectory(at: contactsDirectory, withIntermediateDirectories: true)
        let contactMarker = contactsDirectory.appendingPathComponent("contact.gpg")
        try Data([0x04]).write(to: contactMarker)

        container.config.hasCompletedOnboarding = true
        container.config.encryptToSelf = false

        let summary = try await container.localDataResetService.resetAllLocalData()

        XCTAssertGreaterThanOrEqual(summary.deletedKeychainItemCount, 6)
        XCTAssertFalse(container.keychain.exists(service: metadataService, account: KeychainConstants.defaultAccount))
        XCTAssertFalse(container.keychain.exists(service: metadataService, account: KeychainConstants.metadataAccount))
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
        XCTAssertFalse(FileManager.default.fileExists(atPath: contactsDirectory.path))
        XCTAssertFalse(container.config.hasCompletedOnboarding)
        XCTAssertTrue(container.config.encryptToSelf)
        XCTAssertTrue(container.keyManagement.keys.isEmpty)
        XCTAssertTrue(container.contactService.contacts.isEmpty)

        let traceNames = container.authLifecycleTraceStore?.recentEntries.map(\.name) ?? []
        XCTAssertTrue(traceNames.contains("localDataReset.start"))
        XCTAssertTrue(traceNames.contains("localDataReset.finish"))
        XCTAssertTrue(traceNames.contains("localDataReset.validation.finish"))
    }

    func test_resetAllLocalData_missingProtectedDataBaseValidatesCleanAndPreservesResetAuth() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        defer {
            try? FileManager.default.removeItem(
                at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
            )
            if let contactsDirectory = container.contactsDirectory {
                try? FileManager.default.removeItem(at: contactsDirectory)
            }
            if let defaultsSuiteName = container.defaultsSuiteName {
                UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
            }
        }

        let protectedDataBaseDirectory = container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: protectedDataBaseDirectory)

        _ = try await container.localDataResetService.resetAllLocalData(
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
        let registry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let rootSecret = ProtectedDataRootSecretFlag(exists: true)
        let cleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { _ in rootSecret.exists },
            removePersistedSharedRight: { _ in rootSecret.exists = false }
        )

        let outcome = try await cleaner.cleanupOrphanedSharedRightIfSafe(
            registry: registry,
            source: "test"
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
        let registry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let cleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { _ in true },
            removePersistedSharedRight: { _ in XCTFail("Should not remove root secret when artifacts remain") }
        )

        let outcome = try await cleaner.cleanupOrphanedSharedRightIfSafe(
            registry: registry,
            source: "test"
        )

        XCTAssertEqual(outcome, .blockedByArtifacts)
    }

    private func cleanup(_ container: AppContainer) {
        try? FileManager.default.removeItem(
            at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent()
        )
        if let contactsDirectory = container.contactsDirectory {
            try? FileManager.default.removeItem(at: contactsDirectory)
        }
        if let defaultsSuiteName = container.defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
        }
    }

    private func makeResetService(
        from container: AppContainer,
        protectedDataRootSecretExists: @escaping () -> Bool
    ) -> LocalDataResetService {
        let defaultsSuiteName = container.defaultsSuiteName ?? UUID().uuidString
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        return LocalDataResetService(
            keychain: container.keychain,
            protectedDataStorageRoot: container.protectedDataStorageRoot,
            contactsDirectory: container.contactsDirectory ?? FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true),
            defaults: defaults,
            defaultsDomainName: defaultsSuiteName,
            config: container.config,
            authManager: container.authManager,
            keyManagement: container.keyManagement,
            contactService: container.contactService,
            protectedDataSessionCoordinator: container.protectedDataSessionCoordinator,
            appSessionOrchestrator: container.appSessionOrchestrator,
            protectedDataRootSecretExists: protectedDataRootSecretExists,
            traceStore: container.authLifecycleTraceStore
        )
    }
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
