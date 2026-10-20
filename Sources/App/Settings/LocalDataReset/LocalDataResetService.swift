import Foundation
import SwiftUI

struct LocalDataResetError: LocalizedError, Equatable {
    var errorDescription: String? {
        String(
            localized: "settings.resetAll.error",
            defaultValue: "Some CypherAir X data could not be reset. Restart the app and try again."
        )
    }
}

/// Reset All Local Data: the vault and everything sealed under it, the
/// temporary artifacts, and every service's session state. The result is
/// verified before it is reported; the app restarts into first run afterwards.
final class LocalDataResetService {
    private let vault: AppVault
    private let appSettings: AppSettingsCoordinator
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let selfTestService: SelfTestService?
    private let appSessionOrchestrator: AppSessionOrchestrator
    private let appLockController: AppLockController
    private let temporaryArtifactStore: AppTemporaryArtifactStore

    init(
        vault: AppVault,
        appSettings: AppSettingsCoordinator,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        selfTestService: SelfTestService? = nil,
        appSessionOrchestrator: AppSessionOrchestrator,
        appLockController: AppLockController,
        temporaryArtifactStore: AppTemporaryArtifactStore
    ) {
        self.vault = vault
        self.appSettings = appSettings
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.selfTestService = selfTestService
        self.appSessionOrchestrator = appSessionOrchestrator
        self.appLockController = appLockController
        self.temporaryArtifactStore = temporaryArtifactStore
    }

    @MainActor
    func resetAllLocalData() async throws {
        var failures: [String] = []
        try? await keyManagement.relockVault()
        try? await contactService.relockVault()
        appSettings.relock()
        selfTestService?.clearLatestReport()
        do {
            try vault.reset()
        } catch {
            failures.append("vault.\(Self.failureName(for: error))")
        }
        let temporaryCleanup = temporaryArtifactStore.removeAllTemporaryArtifacts()
        failures.append(contentsOf: temporaryCleanup.failures.map { "temporary.\($0)" })
        keyManagement.resetInMemoryStateAfterLocalDataReset()
        contactService.resetInMemoryStateAfterLocalDataReset()
        appSessionOrchestrator.resetAfterLocalDataReset()
        appLockController.resetAfterLocalDataReset()

        failures.append(contentsOf: vault.residue().map { "vault.remaining.\($0)" })
        let remainingTemporary = temporaryArtifactStore.remainingTemporaryArtifacts()
        if !remainingTemporary.isEmpty {
            failures.append("temporary.remaining.\(remainingTemporary.count)")
        }
        if !keyManagement.keys.isEmpty {
            failures.append("memory.keys.remaining.\(keyManagement.keys.count)")
        }
        if contactService.runtimeContactCountForDiagnostics > 0 {
            failures.append("memory.contacts.remaining")
        }
        guard failures.isEmpty else {
            throw LocalDataResetError()
        }
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
