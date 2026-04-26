import Foundation
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
    private let defaults: UserDefaults
    private let defaultsDomainName: String?
    private let config: AppConfiguration
    private let authManager: AuthenticationManager
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    private let appSessionOrchestrator: AppSessionOrchestrator
    private let fileManager: FileManager
    private let traceStore: AuthLifecycleTraceStore?

    init(
        keychain: any KeychainManageable,
        legacyRightStoreClient: (any ProtectedDataRightStoreClientProtocol)? = nil,
        protectedDataStorageRoot: ProtectedDataStorageRoot,
        contactsDirectory: URL,
        defaults: UserDefaults,
        defaultsDomainName: String?,
        config: AppConfiguration,
        authManager: AuthenticationManager,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        appSessionOrchestrator: AppSessionOrchestrator,
        fileManager: FileManager = .default,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.keychain = keychain
        self.legacyRightStoreClient = legacyRightStoreClient
        self.protectedDataStorageRoot = protectedDataStorageRoot
        self.contactsDirectory = contactsDirectory
        self.defaults = defaults
        self.defaultsDomainName = defaultsDomainName
        self.config = config
        self.authManager = authManager
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
        self.appSessionOrchestrator = appSessionOrchestrator
        self.fileManager = fileManager
        self.traceStore = traceStore
    }

    func resetAllLocalData() async throws -> LocalDataResetSummary {
        traceStore?.record(category: .operation, name: "localDataReset.start")
        await protectedDataSessionCoordinator.relockCurrentSession()

        var failures: [String] = []
        var deletedKeychainItemCount = 0
        var removedDirectoryCount = 0

        do {
            let services = try keychain.listItems(
                servicePrefix: KeychainConstants.prefix,
                account: KeychainConstants.defaultAccount
            )
            for service in services {
                do {
                    try keychain.delete(service: service, account: KeychainConstants.defaultAccount)
                    deletedKeychainItemCount += 1
                } catch where Self.isItemNotFound(error) {
                } catch {
                    failures.append("keychain.\(AuthTraceMetadata.keychainServiceKind(for: service)).\(String(describing: type(of: error)))")
                }
            }
        } catch {
            failures.append("keychain.list.\(String(describing: type(of: error)))")
        }

        do {
            try keychain.delete(
                service: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
                account: KeychainConstants.defaultAccount
            )
            deletedKeychainItemCount += 1
        } catch where Self.isItemNotFound(error) {
        } catch {
            failures.append("keychain.protectedDataRootSecret.\(String(describing: type(of: error)))")
        }

        do {
            try await legacyRightStoreClient?.removeRight(
                forIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier
            )
        } catch {
            failures.append("legacyRight.remove.\(String(describing: type(of: error)))")
        }

        for directory in resetDirectories {
            do {
                if fileManager.fileExists(atPath: directory.path) {
                    try fileManager.removeItem(at: directory)
                    removedDirectoryCount += 1
                }
            } catch {
                failures.append("directory.\(directory.lastPathComponent).\(String(describing: type(of: error)))")
            }
        }

        removeTemporaryResetTargets(&removedDirectoryCount, failures: &failures)

        if let defaultsDomainName {
            defaults.removePersistentDomain(forName: defaultsDomainName)
        }
        config.resetToFirstRunDefaults()
        authManager.clearCachedAuthenticationContextAfterLocalDataReset()
        keyManagement.resetInMemoryStateAfterLocalDataReset()
        contactService.resetInMemoryStateAfterLocalDataReset()
        appSessionOrchestrator.resetAfterLocalDataReset()

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
            contactsDirectory
        ]
    }

    private func removeTemporaryResetTargets(
        _ removedDirectoryCount: inout Int,
        failures: inout [String]
    ) {
        let temporaryDirectory = fileManager.temporaryDirectory
        let fixedDirectories = [
            temporaryDirectory.appendingPathComponent("decrypted", isDirectory: true),
            temporaryDirectory.appendingPathComponent("streaming", isDirectory: true)
        ]

        for directory in fixedDirectories {
            do {
                if fileManager.fileExists(atPath: directory.path) {
                    try fileManager.removeItem(at: directory)
                    removedDirectoryCount += 1
                }
            } catch {
                failures.append("temporary.\(directory.lastPathComponent).\(String(describing: type(of: error)))")
            }
        }

        guard let contents = try? fileManager.contentsOfDirectory(
            at: temporaryDirectory,
            includingPropertiesForKeys: nil
        ) else {
            return
        }

        for url in contents where shouldRemoveTemporaryItem(url) {
            do {
                try fileManager.removeItem(at: url)
                removedDirectoryCount += 1
            } catch {
                failures.append("temporary.\(url.lastPathComponent).\(String(describing: type(of: error)))")
            }
        }
    }

    private func shouldRemoveTemporaryItem(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        return name.hasPrefix("export-")
            || name.hasPrefix("CypherAirGuidedTutorial-")
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
