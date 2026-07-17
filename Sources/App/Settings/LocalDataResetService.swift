import Foundation
import LocalAuthentication
import SwiftUI

struct LocalDataResetSummary: Equatable {
    let deletedKeychainItemCount: Int
}

struct LocalDataResetError: LocalizedError, Equatable {
    var errorDescription: String? {
        String(
            localized: "settings.resetAll.error",
            defaultValue: "Some CypherAir X data could not be reset. Restart the app and try again."
        )
    }
}

final class LocalDataResetService {
    private let keychain: any KeychainManageable
    private let protectedDataStorageRoot: ProtectedDataStorageRoot
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
    private let appLockController: AppLockController
    private let fileManager: FileManager
    private let temporaryArtifactStore: AppTemporaryArtifactStore
    private let protectedDataRootSecretExists: () -> Bool
    private let secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore?

    init(
        keychain: any KeychainManageable,
        protectedDataStorageRoot: ProtectedDataStorageRoot,
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
        appLockController: AppLockController,
        temporaryArtifactStore: AppTemporaryArtifactStore? = nil,
        fileManager: FileManager = .default,
        protectedDataRootSecretExists: (() -> Bool)? = nil,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore? = nil
    ) {
        self.keychain = keychain
        self.protectedDataStorageRoot = protectedDataStorageRoot
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
        self.appLockController = appLockController
        self.fileManager = fileManager
        self.temporaryArtifactStore = temporaryArtifactStore ?? AppTemporaryArtifactStore(fileManager: fileManager)
        self.protectedDataRootSecretExists = protectedDataRootSecretExists ?? {
            keychain.exists(
                service: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
                account: KeychainConstants.defaultAccount,
                authenticationContext: nil
            )
        }
        self.secureEnclaveCustodyHandleStore = secureEnclaveCustodyHandleStore
    }

    func resetAllLocalData(
        authenticationContext: LAContext? = nil
    ) async throws -> LocalDataResetSummary {
        await protectedDataSessionCoordinator.relockCurrentSession()

        var failures: [String] = []
        var deletedKeychainItemCount = 0
        var removedDirectoryCount = 0

        deletedKeychainItemCount += resetKeychainItems(
            account: KeychainConstants.defaultAccount,
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
        cleanupSecureEnclaveCustodyHandles(
            deletedKeychainItemCount: &deletedKeychainItemCount,
            failures: &failures
        )

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
        // `AppSessionOrchestrator` is `@MainActor`-isolated; hop to the main actor
        // for this single state mutation. The surrounding reset I/O stays off the
        // main actor (this method remains nonisolated `async`).
        await appSessionOrchestrator.resetAfterLocalDataReset(
            preserveAuthentication: authenticationContext != nil
        )
        await appLockController.resetAfterLocalDataReset(
            preserveAuthentication: authenticationContext != nil
        )
        validateResetPostConditions(
            authenticationContext: authenticationContext,
            failures: &failures
        )

        guard failures.isEmpty else {
            throw LocalDataResetError()
        }

        return LocalDataResetSummary(
            deletedKeychainItemCount: deletedKeychainItemCount
        )
    }

    private var resetDirectories: [URL] {
        [
            protectedDataStorageRoot.rootURL
        ]
    }

    private func resetKeychainItems(
        account: String,
        authenticationContext: LAContext?,
        failures: inout [String]
    ) -> Int {
        let accountKind = Self.keychainAccountKind(for: account)
        do {
            let services = try keychain.listItems(
                servicePrefix: KeychainConstants.prefix,
                account: account,
                authenticationContext: authenticationContext
            )
            var deletedCount = 0
            for service in services {
                deletedCount += deleteExactKeychainItem(
                    service: service,
                    account: account,
                    authenticationContext: authenticationContext,
                    failureKey: "keychain.\(accountKind).\(Self.keychainServiceKind(for: service))",
                    failures: &failures
                )
            }
            return deletedCount
        } catch {
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
        do {
            try keychain.delete(
                service: service,
                account: account,
                authenticationContext: authenticationContext
            )
            return 1
        } catch where Self.isItemNotFound(error) {
            return 0
        } catch {
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
        do {
            if existedBefore {
                try fileManager.removeItem(at: directory)
            }
            let existsAfter = fileManager.fileExists(atPath: directory.path)
            if existsAfter {
                failures.append("\(failurePrefix).\(directory.lastPathComponent).remaining")
            }
            return existedBefore && !existsAfter ? 1 : 0
        } catch {
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
            let hasRootSecret = protectedDataRootSecretExists()
            let remainingDefaultAccountServices = remainingKeychainServices(
                account: KeychainConstants.defaultAccount,
                authenticationContext: authenticationContext,
                failures: &failures
            )
            let remainingSecureEnclaveCustodyHandleCount = remainingSecureEnclaveCustodyHandleCount(
                failures: &failures
            )
            let remainingTemporaryTargets = temporaryResetTargetsRemaining()
            let remainingContactRuntimeCount = contactService.runtimeContactCountForDiagnostics
            if hasProtectedArtifacts {
                failures.append("protectedData.artifactsRemaining")
            }
            if hasRootSecret {
                failures.append("keychain.protectedDataRootSecret.remaining")
            }
            if !remainingDefaultAccountServices.isEmpty {
                failures.append("keychain.default.remaining.\(remainingDefaultAccountServices.count)")
            }
            if remainingSecureEnclaveCustodyHandleCount > 0 {
                failures.append("keychain.secureEnclaveCustodyHandle.remaining.\(remainingSecureEnclaveCustodyHandleCount)")
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
            failures.append("protectedData.storageContract.\(Self.failureName(for: error))")
        }
    }

    private func cleanupSecureEnclaveCustodyHandles(
        deletedKeychainItemCount: inout Int,
        failures: inout [String]
    ) {
        guard let secureEnclaveCustodyHandleStore else {
            return
        }
        let result = secureEnclaveCustodyHandleStore.cleanupAllHandlesForLocalDataReset()
        deletedKeychainItemCount += result.deletedHandleCount
        if let failureCategory = result.failureCategory {
            failures.append("keychain.secureEnclaveCustodyHandle.\(failureCategory.rawValue)")
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
            failures.append("keychain.remaining.\(Self.keychainAccountKind(for: account)).\(String(describing: type(of: error)))")
            return []
        }
    }

    private func remainingSecureEnclaveCustodyHandleCount(failures: inout [String]) -> Int {
        guard let secureEnclaveCustodyHandleStore else {
            return 0
        }
        do {
            return try secureEnclaveCustodyHandleStore.remainingHandleCountForLocalDataReset()
        } catch let error as SecureEnclaveCustodyHandleError {
            failures.append("keychain.remaining.secureEnclaveCustodyHandle.\(error.failureCategory.rawValue)")
            return 0
        } catch {
            failures.append("keychain.remaining.secureEnclaveCustodyHandle.\(Self.failureName(for: error))")
            return 0
        }
    }

    private func removeTemporaryResetTargets(
        _ removedDirectoryCount: inout Int,
        failures: inout [String]
    ) {
        let temporaryCleanup = temporaryArtifactStore.cleanupTemporaryArtifacts()
        removedDirectoryCount += temporaryCleanup.removedItemCount
        failures.append(contentsOf: temporaryCleanup.failures.map { "temporary.\($0)" })

        let tutorialDefaultsCleanup = temporaryArtifactStore.cleanupTutorialSandboxDefaultsSuite()
        removedDirectoryCount += tutorialDefaultsCleanup.removedItemCount
        failures.append(contentsOf: tutorialDefaultsCleanup.failures.map { "tutorialDefaults.\($0)" })
    }

    private func temporaryResetTargetsRemaining() -> [String] {
        temporaryArtifactStore.remainingTemporaryArtifacts()
            + temporaryArtifactStore.remainingTutorialSandboxDefaultsSuites()
    }

    private static func isItemNotFound(_ error: Error) -> Bool {
        KeychainFailureClassifier.isItemNotFound(error)
    }

    private static func failureName(for error: Error) -> String {
        let nsError = error as NSError
        let domain = nsError.domain
            .replacingOccurrences(of: ".", with: "_")
            .replacingOccurrences(of: " ", with: "_")
        return "\(domain).\(nsError.code)"
    }

    /// Classifies a managed Keychain service string into a stable failure-key
    /// token so reset failures identify which item class could not be removed
    /// without exposing the raw service identifier.
    private static func keychainServiceKind(for service: String) -> String {
        if service.hasPrefix("\(SecureEnclaveCustodyHandleReference.servicePrefix).") {
            if service.hasSuffix(".signing") {
                return "secureEnclaveCustodySigningHandle"
            }
            if service.hasSuffix(".keyAgreement") {
                return "secureEnclaveCustodyKeyAgreementHandle"
            }
            return "secureEnclaveCustodyHandle"
        }
        if service.hasPrefix(KeychainConstants.protectedDataDomainKeyServicePrefix) {
            if service.hasPrefix("\(KeychainConstants.protectedDataDomainKeyServicePrefix)staged.") {
                return "protectedDataStagedDomainKey"
            }
            return "protectedDataDomainKey"
        }
        if service.hasPrefix("\(KeychainConstants.prefix).pending-privkey-envelope.") {
            return "pendingPrivateKeyEnvelope"
        }
        if service.hasPrefix("\(KeychainConstants.prefix).privkey-envelope.") {
            return "privateKeyEnvelope"
        }
        if service == ProtectedDataRightIdentifiers.productionSharedRightIdentifier {
            return "protectedDataRootSecret"
        }
        return "unknown"
    }

    private static func keychainAccountKind(for account: String) -> String {
        switch account {
        case KeychainConstants.defaultAccount:
            "default"
        default:
            "unknown"
        }
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
