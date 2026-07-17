import Foundation

/// Startup workflow for loading persisted state and recovering interrupted operations.
struct AppStartupCoordinator {
    struct AppStartupBootstrapSnapshot {
        let loadError: String?
        let bootstrapOutcome: ProtectedDataBootstrapOutcome
        let protectedDataFrameworkState: ProtectedDataFrameworkState
    }

    func performPreAuthBootstrap(using container: AppContainer) -> AppStartupBootstrapSnapshot {
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

        cleanupTemporaryFiles(
            temporaryArtifactStore: container.temporaryArtifactStore
        )

        let loadError = mergedStartupMessages(
            recoveryDiagnostics: recoveryDiagnostics
        )

        return AppStartupBootstrapSnapshot(
            loadError: loadError,
            bootstrapOutcome: bootstrapOutcome,
            protectedDataFrameworkState: protectedDataFrameworkState
        )
    }

    func cleanupTemporaryFiles(
        fileManager: FileManager = .default,
        temporaryArtifactStore: AppTemporaryArtifactStore? = nil
    ) {
        let artifactStore = temporaryArtifactStore ?? AppTemporaryArtifactStore(fileManager: fileManager)
        _ = artifactStore.cleanupTemporaryArtifacts()
        _ = artifactStore.cleanupTutorialSandboxDefaultsSuite()
    }

    func mergedStartupMessages(
        recoveryDiagnostics: [String]
    ) -> String? {
        var messages: [String] = []
        for diagnostic in recoveryDiagnostics where !messages.contains(diagnostic) {
            messages.append(diagnostic)
        }

        return messages.isEmpty ? nil : messages.joined(separator: "\n")
    }
}
