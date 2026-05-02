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
        let traceStore = container.authLifecycleTraceStore
        var errors: [String] = []
        var recoveryDiagnostics: [String] = []
        var bootstrapOutcome: ProtectedDataBootstrapOutcome = .frameworkRecoveryNeeded
        var protectedDataFrameworkState: ProtectedDataFrameworkState = .sessionLocked

        traceStore?.record(category: .lifecycle, name: "startup.protectedDataBootstrap.start")
        do {
            let protectedDataBootstrapResult = try container.protectedDomainRecoveryCoordinator
                .performPreAuthBootstrapClassification()
            bootstrapOutcome = protectedDataBootstrapResult.bootstrapOutcome
            protectedDataFrameworkState = protectedDataBootstrapResult.frameworkState
            traceStore?.record(
                category: .lifecycle,
                name: "startup.protectedDataBootstrap.finish",
                metadata: [
                    "result": "success",
                    "bootstrapOutcome": traceValue(for: bootstrapOutcome),
                    "frameworkState": traceValue(for: protectedDataFrameworkState)
                ]
            )
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
            traceStore?.record(
                category: .lifecycle,
                name: "startup.protectedDataBootstrap.finish",
                metadata: AuthTraceMetadata.errorMetadata(
                    error,
                    extra: ["result": "failed"]
                )
            )
            recoveryDiagnostics.append(
                String(
                    localized: "startup.protectedData.recoveryNeeded",
                    defaultValue: "Protected app data is unavailable and may require recovery."
                )
            )
        }

        traceStore?.record(
            category: .lifecycle,
            name: "startup.keyMetadata.load.deferred",
            metadata: [
                "reason": "protectedDataPostUnlock",
                "state": "\(container.keyManagement.metadataLoadState)"
            ]
        )

        traceStore?.record(category: .lifecycle, name: "startup.contacts.load.start")
        do {
            try container.contactService.loadContacts()
            traceStore?.record(
                category: .lifecycle,
                name: "startup.contacts.load.finish",
                metadata: ["result": "success", "contactCount": String(container.contactService.contacts.count)]
            )
        } catch {
            traceStore?.record(
                category: .lifecycle,
                name: "startup.contacts.load.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            errors.append(error.localizedDescription)
        }

        traceStore?.record(category: .lifecycle, name: "startup.temporaryCleanup.start")
        cleanupTemporaryFiles(
            legacySelfTestReportsDirectory: container.legacySelfTestReportsDirectory
        )
        traceStore?.record(category: .lifecycle, name: "startup.temporaryCleanup.finish")

        let loadError = mergedStartupMessages(
            loadErrors: errors,
            recoveryDiagnostics: recoveryDiagnostics
        )
        traceStore?.record(
            category: .lifecycle,
            name: "startup.loadWarning.computed",
            metadata: [
                "hasLoadWarning": loadError == nil ? "false" : "true",
                "loadErrorCount": String(errors.count),
                "recoveryDiagnosticCount": String(recoveryDiagnostics.count)
            ]
        )

        return AppStartupBootstrapSnapshot(
            loadError: loadError,
            bootstrapOutcome: bootstrapOutcome,
            protectedDataFrameworkState: protectedDataFrameworkState
        )
    }

    func cleanupTemporaryFiles(
        fileManager: FileManager = .default,
        documentDirectory: URL? = nil,
        legacySelfTestReportsDirectory: URL? = nil
    ) {
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

        let selfTestDir = legacySelfTestReportsDirectory
            ?? legacySelfTestReportDirectory(
                fileManager: fileManager,
                documentDirectory: documentDirectory
            )
        if fileManager.fileExists(atPath: selfTestDir.path) {
            try? fileManager.removeItem(at: selfTestDir)
        }
    }

    func legacySelfTestReportDirectory(
        fileManager: FileManager = .default,
        documentDirectory: URL? = nil
    ) -> URL {
        let documents = documentDirectory
            ?? fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return documents.appendingPathComponent("self-test", isDirectory: true)
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

    private func traceValue(for outcome: ProtectedDataBootstrapOutcome) -> String {
        switch outcome {
        case .emptySteadyState(_, let didBootstrap):
            didBootstrap ? "emptySteadyState.bootstrapped" : "emptySteadyState.existing"
        case .loadedRegistry(_, let recoveryDisposition):
            "loadedRegistry.\(traceValue(for: recoveryDisposition))"
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        }
    }

    private func traceValue(for recoveryDisposition: ProtectedDataRecoveryDisposition) -> String {
        switch recoveryDisposition {
        case .resumeSteadyState:
            "resumeSteadyState"
        case .continuePendingMutation:
            "continuePendingMutation"
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        }
    }

    private func traceValue(for state: ProtectedDataFrameworkState) -> String {
        switch state {
        case .sessionLocked:
            "sessionLocked"
        case .sessionAuthorized:
            "sessionAuthorized"
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        case .restartRequired:
            "restartRequired"
        }
    }
}
