import Foundation

/// Startup workflow for loading persisted state and recovering interrupted operations.
struct AppStartupCoordinator {
    struct Result {
        let loadError: String?
    }

    struct AppStartupBootstrapSnapshot {
        let loadError: String?
        let bootstrapOutcome: ProtectedDataBootstrapOutcome
        let protectedDataFrameworkState: ProtectedDataFrameworkState
    }

    func performStartup(using container: AppContainer) -> Result {
        let snapshot = performPreAuthBootstrap(using: container)
        return Result(loadError: snapshot.loadError)
    }

    func performPreAuthBootstrap(using container: AppContainer) -> AppStartupBootstrapSnapshot {
        var errors: [String] = []
        var recoveryDiagnostics: [String] = []
        var bootstrapOutcome: ProtectedDataBootstrapOutcome = .frameworkRecoveryNeeded
        var protectedDataFrameworkState: ProtectedDataFrameworkState = .sessionLocked

        do {
            let protectedDataBootstrapResult = try container.protectedDomainRecoveryCoordinator
                .performPreAuthBootstrapClassification()
            bootstrapOutcome = protectedDataBootstrapResult.bootstrapOutcome
            protectedDataFrameworkState = protectedDataBootstrapResult.frameworkState
            if protectedDataBootstrapResult.frameworkState == .frameworkRecoveryNeeded {
                recoveryDiagnostics.append(
                    String(
                        localized: "startup.protectedData.recoveryNeeded",
                        defaultValue: "Protected app data is unavailable and may require recovery."
                    )
                )
            }
            if case .loadedRegistry(_, .continuePendingMutation) = protectedDataBootstrapResult.bootstrapOutcome {
                recoveryDiagnostics.append(
                    String(
                        localized: "startup.protectedData.pendingRecovery",
                        defaultValue: "Protected app data has pending recovery work that must complete before protected content can open."
                    )
                )
            }
        } catch {
            bootstrapOutcome = .frameworkRecoveryNeeded
            protectedDataFrameworkState = .frameworkRecoveryNeeded
            recoveryDiagnostics.append(
                String(
                    localized: "startup.protectedData.recoveryNeeded",
                    defaultValue: "Protected app data is unavailable and may require recovery."
                )
            )
        }

        do {
            try container.keyManagement.loadKeys()
        } catch {
            errors.append(error.localizedDescription)
        }

        let authRecovery = container.authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: container.keyManagement.keys.map(\.fingerprint)
        )
        recoveryDiagnostics.append(contentsOf: authRecovery?.startupDiagnostics ?? [])

        let modifyExpiryRecovery = container.keyManagement.checkAndRecoverFromInterruptedModifyExpiry()
        if let diagnostic = modifyExpiryRecovery?.startupDiagnostic {
            recoveryDiagnostics.append(diagnostic)
        }

        do {
            try container.contactService.loadContacts()
        } catch {
            errors.append(error.localizedDescription)
        }

        cleanupTemporaryFiles()

        return AppStartupBootstrapSnapshot(
            loadError: mergedStartupMessages(
                loadErrors: errors,
                recoveryDiagnostics: recoveryDiagnostics
            ),
            bootstrapOutcome: bootstrapOutcome,
            protectedDataFrameworkState: protectedDataFrameworkState
        )
    }

    func cleanupTemporaryFiles(fileManager: FileManager = .default) {
        let decryptedDir = fileManager.temporaryDirectory
            .appendingPathComponent("decrypted", isDirectory: true)
        if fileManager.fileExists(atPath: decryptedDir.path) {
            try? fileManager.removeItem(at: decryptedDir)
        }

        let streamingDir = fileManager.temporaryDirectory
            .appendingPathComponent("streaming", isDirectory: true)
        if fileManager.fileExists(atPath: streamingDir.path) {
            try? fileManager.removeItem(at: streamingDir)
        }
    }

    func mergedStartupMessages(
        loadErrors: [String],
        recoveryDiagnostics: [String]
    ) -> String? {
        var messages: [String] = []
        messages.append(contentsOf: loadErrors)

        for diagnostic in recoveryDiagnostics where !messages.contains(diagnostic) {
            messages.append(diagnostic)
        }

        return messages.isEmpty ? nil : messages.joined(separator: "\n")
    }
}
