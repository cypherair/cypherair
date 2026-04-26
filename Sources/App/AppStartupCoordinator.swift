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

        traceStore?.record(category: .lifecycle, name: "startup.keys.load.start")
        do {
            try container.keyManagement.loadKeys()
            traceStore?.record(
                category: .lifecycle,
                name: "startup.keys.load.finish",
                metadata: ["result": "success", "keyCount": String(container.keyManagement.keys.count)]
            )
        } catch {
            traceStore?.record(
                category: .lifecycle,
                name: "startup.keys.load.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            errors.append(error.localizedDescription)
        }

        traceStore?.record(category: .lifecycle, name: "startup.rewrapRecovery.start")
        let authRecovery = container.authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: container.keyManagement.keys.map(\.fingerprint)
        )
        traceStore?.record(
            category: .lifecycle,
            name: "startup.rewrapRecovery.finish",
            metadata: [
                "result": authRecovery == nil ? "none" : authRecovery!.shouldClearRecoveryFlag ? "recovered" : "needsAttention",
                "diagnosticCount": String(authRecovery?.startupDiagnostics.count ?? 0)
            ]
        )
        recoveryDiagnostics.append(contentsOf: authRecovery?.startupDiagnostics ?? [])

        traceStore?.record(category: .lifecycle, name: "startup.modifyExpiryRecovery.start")
        let modifyExpiryRecovery = container.keyManagement.checkAndRecoverFromInterruptedModifyExpiry()
        traceStore?.record(
            category: .lifecycle,
            name: "startup.modifyExpiryRecovery.finish",
            metadata: [
                "result": modifyExpiryRecovery == nil ? "none" : modifyExpiryRecovery!.shouldClearRecoveryFlag ? "recovered" : "needsAttention",
                "hasDiagnostic": modifyExpiryRecovery?.startupDiagnostic == nil ? "false" : "true"
            ]
        )
        if let diagnostic = modifyExpiryRecovery?.startupDiagnostic {
            recoveryDiagnostics.append(diagnostic)
        }

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
        cleanupTemporaryFiles()
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
