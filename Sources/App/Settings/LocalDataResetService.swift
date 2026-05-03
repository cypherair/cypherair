import Foundation
import LocalAuthentication
import SwiftUI

struct LocalDataResetSummary: Equatable {
    let deletedKeychainItemCount: Int
    let removedDirectoryCount: Int
}

struct LocalDataResetError: LocalizedError, Equatable {
    let failures: [String]

    var errorDescription: String? {
        String(
            localized: "settings.resetAll.error",
            defaultValue: "Some CypherAir data could not be reset. Restart the app and try again."
        )
    }
}

final class LocalDataResetService {
    private let keychain: any KeychainManageable
    private let legacyRightStoreClient: (any ProtectedDataRightStoreClientProtocol)?
    private let protectedDataStorageRoot: ProtectedDataStorageRoot
    private let contactsDirectory: URL
    private let contactsQuarantineDirectory: URL
    private let defaults: UserDefaults
    private let defaultsDomainName: String?
    private let config: AppConfiguration
    private let protectedOrdinarySettingsCoordinator: ProtectedOrdinarySettingsCoordinator
    private let authManager: AuthenticationManager
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let selfTestService: SelfTestService?
    private let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    private let appSessionOrchestrator: AppSessionOrchestrator
    private let fileManager: FileManager
    private let legacySelfTestReportsDirectory: URL
    private let temporaryArtifactStore: AppTemporaryArtifactStore
    private let protectedDataRootSecretExists: () -> Bool
    private let traceStore: AuthLifecycleTraceStore?

    init(
        keychain: any KeychainManageable,
        legacyRightStoreClient: (any ProtectedDataRightStoreClientProtocol)? = nil,
        protectedDataStorageRoot: ProtectedDataStorageRoot,
        contactsDirectory: URL,
        defaults: UserDefaults,
        defaultsDomainName: String?,
        config: AppConfiguration,
        protectedOrdinarySettingsCoordinator: ProtectedOrdinarySettingsCoordinator,
        authManager: AuthenticationManager,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        selfTestService: SelfTestService? = nil,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        appSessionOrchestrator: AppSessionOrchestrator,
        temporaryArtifactStore: AppTemporaryArtifactStore? = nil,
        fileManager: FileManager = .default,
        legacySelfTestReportsDirectory: URL? = nil,
        protectedDataRootSecretExists: (() -> Bool)? = nil,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.keychain = keychain
        self.legacyRightStoreClient = legacyRightStoreClient
        self.protectedDataStorageRoot = protectedDataStorageRoot
        self.contactsDirectory = contactsDirectory
        self.contactsQuarantineDirectory = ContactRepository(
            contactsDirectory: contactsDirectory,
            fileManager: fileManager
        ).quarantineDirectory
        self.defaults = defaults
        self.defaultsDomainName = defaultsDomainName
        self.config = config
        self.protectedOrdinarySettingsCoordinator = protectedOrdinarySettingsCoordinator
        self.authManager = authManager
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.selfTestService = selfTestService
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
        self.appSessionOrchestrator = appSessionOrchestrator
        self.fileManager = fileManager
        self.temporaryArtifactStore = temporaryArtifactStore ?? AppTemporaryArtifactStore(fileManager: fileManager)
        self.legacySelfTestReportsDirectory = legacySelfTestReportsDirectory
            ?? fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("self-test", isDirectory: true)
        self.protectedDataRootSecretExists = protectedDataRootSecretExists ?? {
            keychain.exists(
                service: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
                account: KeychainConstants.defaultAccount,
                authenticationContext: nil
            )
        }
        self.traceStore = traceStore
    }

    func resetAllLocalData(
        authenticationContext: LAContext? = nil
    ) async throws -> LocalDataResetSummary {
        traceStore?.record(
            category: .operation,
            name: "localDataReset.start",
            metadata: ["hasAuthenticationContext": authenticationContext == nil ? "false" : "true"]
        )
        await protectedDataSessionCoordinator.relockCurrentSession()

        var failures: [String] = []
        var deletedKeychainItemCount = 0
        var removedDirectoryCount = 0

        deletedKeychainItemCount += resetKeychainItems(
            account: KeychainConstants.defaultAccount,
            authenticationContext: authenticationContext,
            failures: &failures
        )
        deletedKeychainItemCount += resetKeychainItems(
            account: KeychainConstants.metadataAccount,
            authenticationContext: authenticationContext,
            failures: &failures
        )

        deletedKeychainItemCount += deleteExactKeychainItem(
            service: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            account: KeychainConstants.defaultAccount,
            authenticationContext: authenticationContext,
            failureKey: "keychain.protectedDataRootSecret",
            failures: &failures
        )
        deletedKeychainItemCount += deleteExactKeychainItem(
            service: KeychainConstants.protectedDataDeviceBindingKeyService,
            account: KeychainConstants.defaultAccount,
            authenticationContext: authenticationContext,
            failureKey: "keychain.protectedDataDeviceBindingKey",
            failures: &failures
        )
        deletedKeychainItemCount += deleteExactKeychainItem(
            service: KeychainConstants.protectedDataRootSecretFormatFloorService,
            account: KeychainConstants.defaultAccount,
            authenticationContext: authenticationContext,
            failureKey: "keychain.protectedDataRootSecretFormatFloor",
            failures: &failures
        )
        deletedKeychainItemCount += deleteExactKeychainItem(
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            account: KeychainConstants.defaultAccount,
            authenticationContext: authenticationContext,
            failureKey: "keychain.protectedDataRootSecretLegacyCleanup",
            failures: &failures
        )

        do {
            try await legacyRightStoreClient?.removeRight(
                forIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier
            )
        } catch {
            failures.append("legacyRight.remove.\(String(describing: type(of: error)))")
        }

        for directory in resetDirectories {
            removedDirectoryCount += removeDirectoryIfPresent(
                directory,
                failurePrefix: "directory",
                failures: &failures
            )
        }

        removeTemporaryResetTargets(&removedDirectoryCount, failures: &failures)

        if let defaultsDomainName {
            defaults.removePersistentDomain(forName: defaultsDomainName)
        }
        config.resetToFirstRunDefaults()
        protectedOrdinarySettingsCoordinator.resetAfterLocalDataReset(
            preserveAuthentication: authenticationContext != nil
        )
        selfTestService?.clearLatestReport()
        authManager.clearCachedAuthenticationContextAfterLocalDataReset()
        keyManagement.resetInMemoryStateAfterLocalDataReset()
        contactService.resetInMemoryStateAfterLocalDataReset()
        protectedDataSessionCoordinator.resetAfterLocalDataReset()
        appSessionOrchestrator.resetAfterLocalDataReset(
            preserveAuthentication: authenticationContext != nil
        )
        validateResetPostConditions(
            authenticationContext: authenticationContext,
            failures: &failures
        )

        guard failures.isEmpty else {
            traceStore?.record(
                category: .operation,
                name: "localDataReset.finish",
                metadata: ["result": "failed", "failureCount": String(failures.count)]
            )
            throw LocalDataResetError(failures: failures)
        }

        traceStore?.record(
            category: .operation,
            name: "localDataReset.finish",
            metadata: [
                "result": "success",
                "deletedKeychainItemCount": String(deletedKeychainItemCount),
                "removedDirectoryCount": String(removedDirectoryCount)
            ]
        )
        return LocalDataResetSummary(
            deletedKeychainItemCount: deletedKeychainItemCount,
            removedDirectoryCount: removedDirectoryCount
        )
    }

    private var resetDirectories: [URL] {
        [
            protectedDataStorageRoot.rootURL,
            contactsDirectory,
            contactsQuarantineDirectory,
            legacySelfTestReportsDirectory
        ]
    }

    private func resetKeychainItems(
        account: String,
        authenticationContext: LAContext?,
        failures: inout [String]
    ) -> Int {
        let accountKind = AuthTraceMetadata.keychainAccountKind(for: account)
        traceStore?.record(
            category: .operation,
            name: "localDataReset.keychain.list.start",
            metadata: ["accountKind": accountKind]
        )
        do {
            let services = try keychain.listItems(
                servicePrefix: KeychainConstants.prefix,
                account: account,
                authenticationContext: authenticationContext
            )
            traceStore?.record(
                category: .operation,
                name: "localDataReset.keychain.list.finish",
                metadata: ["accountKind": accountKind, "result": "success", "count": String(services.count)]
            )
            var deletedCount = 0
            for service in services {
                deletedCount += deleteExactKeychainItem(
                    service: service,
                    account: account,
                    authenticationContext: authenticationContext,
                    failureKey: "keychain.\(accountKind).\(AuthTraceMetadata.keychainServiceKind(for: service))",
                    failures: &failures
                )
            }
            return deletedCount
        } catch {
            traceStore?.record(
                category: .operation,
                name: "localDataReset.keychain.list.finish",
                metadata: AuthTraceMetadata.errorMetadata(
                    error,
                    extra: ["accountKind": accountKind, "result": "failed"]
                )
            )
            failures.append("keychain.list.\(accountKind).\(String(describing: type(of: error)))")
            return 0
        }
    }

    private func deleteExactKeychainItem(
        service: String,
        account: String,
        authenticationContext: LAContext?,
        failureKey: String,
        failures: inout [String]
    ) -> Int {
        let accountKind = AuthTraceMetadata.keychainAccountKind(for: account)
        let serviceKind = AuthTraceMetadata.keychainServiceKind(for: service)
        do {
            try keychain.delete(
                service: service,
                account: account,
                authenticationContext: authenticationContext
            )
            traceStore?.record(
                category: .operation,
                name: "localDataReset.keychain.delete.finish",
                metadata: ["accountKind": accountKind, "serviceKind": serviceKind, "result": "success"]
            )
            return 1
        } catch where Self.isItemNotFound(error) {
            traceStore?.record(
                category: .operation,
                name: "localDataReset.keychain.delete.finish",
                metadata: ["accountKind": accountKind, "serviceKind": serviceKind, "result": "missing"]
            )
            return 0
        } catch {
            traceStore?.record(
                category: .operation,
                name: "localDataReset.keychain.delete.finish",
                metadata: AuthTraceMetadata.errorMetadata(
                    error,
                    extra: ["accountKind": accountKind, "serviceKind": serviceKind, "result": "failed"]
                )
            )
            failures.append("\(failureKey).\(String(describing: type(of: error)))")
            return 0
        }
    }

    private func removeDirectoryIfPresent(
        _ directory: URL,
        failurePrefix: String,
        failures: inout [String]
    ) -> Int {
        let existedBefore = fileManager.fileExists(atPath: directory.path)
        traceStore?.record(
            category: .operation,
            name: "localDataReset.directory.remove.start",
            metadata: ["name": directory.lastPathComponent, "existsBefore": existedBefore ? "true" : "false"]
        )
        do {
            if existedBefore {
                try fileManager.removeItem(at: directory)
            }
            let existsAfter = fileManager.fileExists(atPath: directory.path)
            traceStore?.record(
                category: .operation,
                name: "localDataReset.directory.remove.finish",
                metadata: [
                    "name": directory.lastPathComponent,
                    "result": existsAfter ? "remaining" : "removedOrMissing",
                    "existsAfter": existsAfter ? "true" : "false"
                ]
            )
            if existsAfter {
                failures.append("\(failurePrefix).\(directory.lastPathComponent).remaining")
            }
            return existedBefore && !existsAfter ? 1 : 0
        } catch {
            traceStore?.record(
                category: .operation,
                name: "localDataReset.directory.remove.finish",
                metadata: AuthTraceMetadata.errorMetadata(
                    error,
                    extra: ["name": directory.lastPathComponent, "result": "failed"]
                )
            )
            failures.append("\(failurePrefix).\(directory.lastPathComponent).\(String(describing: type(of: error)))")
            return 0
        }
    }

    private func validateResetPostConditions(
        authenticationContext: LAContext?,
        failures: inout [String]
    ) {
        do {
            let hasProtectedArtifacts = try protectedDataStorageRoot.hasProtectedDataArtifacts()
            let rootExists = fileManager.fileExists(atPath: protectedDataStorageRoot.rootURL.path)
            let contactsDirectoryExists = fileManager.fileExists(atPath: contactsDirectory.path)
            let contactsQuarantineDirectoryExists = fileManager.fileExists(
                atPath: contactsQuarantineDirectory.path
            )
            let legacySelfTestReportsDirectoryExists = fileManager.fileExists(
                atPath: legacySelfTestReportsDirectory.path
            )
            let hasRootSecret = protectedDataRootSecretExists()
            let hasDeviceBindingKey = keychain.exists(
                service: KeychainConstants.protectedDataDeviceBindingKeyService,
                account: KeychainConstants.defaultAccount,
                authenticationContext: nil
            )
            let hasFormatFloor = keychain.exists(
                service: KeychainConstants.protectedDataRootSecretFormatFloorService,
                account: KeychainConstants.defaultAccount,
                authenticationContext: nil
            )
            let hasLegacyCleanup = keychain.exists(
                service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
                account: KeychainConstants.defaultAccount,
                authenticationContext: nil
            )
            let remainingDefaultAccountServices = remainingKeychainServices(
                account: KeychainConstants.defaultAccount,
                authenticationContext: authenticationContext,
                failures: &failures
            )
            let remainingMetadataAccountServices = remainingKeychainServices(
                account: KeychainConstants.metadataAccount,
                authenticationContext: authenticationContext,
                failures: &failures
            )
            let remainingTemporaryTargets = temporaryResetTargetsRemaining()
            let remainingContactRuntimeCount = contactService.runtimeContactCountForDiagnostics
            let hasRemainingData = hasProtectedArtifacts
                || hasRootSecret
                || contactsDirectoryExists
                || contactsQuarantineDirectoryExists
                || legacySelfTestReportsDirectoryExists
                || !remainingDefaultAccountServices.isEmpty
                || !remainingMetadataAccountServices.isEmpty
                || !remainingTemporaryTargets.isEmpty
                || !keyManagement.keys.isEmpty
                || remainingContactRuntimeCount > 0
            traceStore?.record(
                category: .operation,
                name: "localDataReset.validation.finish",
                metadata: [
                    "result": hasRemainingData ? "remainingData" : "clean",
                    "protectedDataRootExists": rootExists ? "true" : "false",
                    "hasProtectedDataArtifacts": hasProtectedArtifacts ? "true" : "false",
                    "hasProtectedDataRootSecret": hasRootSecret ? "true" : "false",
                    "hasDeviceBindingKey": hasDeviceBindingKey ? "true" : "false",
                    "hasFormatFloor": hasFormatFloor ? "true" : "false",
                    "hasLegacyCleanup": hasLegacyCleanup ? "true" : "false",
                    "contactsDirectoryExists": contactsDirectoryExists ? "true" : "false",
                    "contactsQuarantineDirectoryExists": contactsQuarantineDirectoryExists ? "true" : "false",
                    "legacySelfTestReportsDirectoryExists": legacySelfTestReportsDirectoryExists ? "true" : "false",
                    "remainingDefaultKeychainItemCount": String(remainingDefaultAccountServices.count),
                    "remainingMetadataKeychainItemCount": String(remainingMetadataAccountServices.count),
                    "remainingTemporaryTargetCount": String(remainingTemporaryTargets.count),
                    "keyCount": String(keyManagement.keys.count),
                    "contactCount": String(remainingContactRuntimeCount)
                ]
            )
            if hasProtectedArtifacts {
                failures.append("protectedData.artifactsRemaining")
            }
            if hasRootSecret {
                failures.append("keychain.protectedDataRootSecret.remaining")
            }
            if hasDeviceBindingKey {
                failures.append("keychain.protectedDataDeviceBindingKey.remaining")
            }
            if hasFormatFloor {
                failures.append("keychain.protectedDataRootSecretFormatFloor.remaining")
            }
            if hasLegacyCleanup {
                failures.append("keychain.protectedDataRootSecretLegacyCleanup.remaining")
            }
            if contactsDirectoryExists {
                failures.append("directory.\(contactsDirectory.lastPathComponent).remaining")
            }
            if contactsQuarantineDirectoryExists {
                failures.append("directory.\(contactsQuarantineDirectory.lastPathComponent).remaining")
            }
            if legacySelfTestReportsDirectoryExists {
                failures.append("directory.\(legacySelfTestReportsDirectory.lastPathComponent).remaining")
            }
            if !remainingDefaultAccountServices.isEmpty {
                failures.append("keychain.default.remaining.\(remainingDefaultAccountServices.count)")
            }
            if !remainingMetadataAccountServices.isEmpty {
                failures.append("keychain.metadata.remaining.\(remainingMetadataAccountServices.count)")
            }
            if !remainingTemporaryTargets.isEmpty {
                failures.append("temporary.remaining.\(remainingTemporaryTargets.count)")
            }
            if !keyManagement.keys.isEmpty {
                failures.append("memory.keys.remaining.\(keyManagement.keys.count)")
            }
            if remainingContactRuntimeCount > 0 {
                failures.append("memory.contacts.remaining.\(remainingContactRuntimeCount)")
            }
        } catch {
            traceStore?.record(
                category: .operation,
                name: "localDataReset.validation.finish",
                metadata: AuthTraceMetadata.errorMetadata(
                    error,
                    extra: ["result": "storageContractFailed"]
                )
            )
            failures.append("protectedData.storageContract.\(Self.failureName(for: error))")
        }
    }

    private func remainingKeychainServices(
        account: String,
        authenticationContext: LAContext?,
        failures: inout [String]
    ) -> [String] {
        do {
            return try keychain.listItems(
                servicePrefix: KeychainConstants.prefix,
                account: account,
                authenticationContext: authenticationContext
            )
        } catch {
            failures.append("keychain.remaining.\(AuthTraceMetadata.keychainAccountKind(for: account)).\(String(describing: type(of: error)))")
            return []
        }
    }

    private func removeTemporaryResetTargets(
        _ removedDirectoryCount: inout Int,
        failures: inout [String]
    ) {
        let temporaryCleanup = temporaryArtifactStore.cleanupTemporaryArtifacts()
        removedDirectoryCount += temporaryCleanup.removedItemCount
        failures.append(contentsOf: temporaryCleanup.failures.map { "temporary.\($0)" })

        let tutorialDefaultsCleanup = temporaryArtifactStore.cleanupTutorialDefaultsSuites()
        removedDirectoryCount += tutorialDefaultsCleanup.removedItemCount
        failures.append(contentsOf: tutorialDefaultsCleanup.failures.map { "tutorialDefaults.\($0)" })
    }

    private func temporaryResetTargetsRemaining() -> [String] {
        temporaryArtifactStore.remainingTemporaryArtifacts()
            + temporaryArtifactStore.remainingTutorialDefaultsSuites()
    }

    private static func isItemNotFound(_ error: Error) -> Bool {
        if let keychainError = error as? KeychainError {
            return keychainError == .itemNotFound
        }
        if let mockKeychainError = error as? MockKeychainError {
            switch mockKeychainError {
            case .itemNotFound:
                return true
            case .duplicateItem, .saveFailed, .deleteFailed:
                return false
            }
        }
        return false
    }

    private static func failureName(for error: Error) -> String {
        let nsError = error as NSError
        let domain = nsError.domain
            .replacingOccurrences(of: ".", with: "_")
            .replacingOccurrences(of: " ", with: "_")
        return "\(domain).\(nsError.code)"
    }
}

private struct LocalDataResetServiceKey: EnvironmentKey {
    nonisolated(unsafe) static let defaultValue: LocalDataResetService? = nil
}

extension EnvironmentValues {
    var localDataResetService: LocalDataResetService? {
        get { self[LocalDataResetServiceKey.self] }
        set { self[LocalDataResetServiceKey.self] = newValue }
    }
}
