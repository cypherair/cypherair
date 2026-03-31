import Foundation

/// Startup workflow for loading persisted state and recovering interrupted operations.
struct AppStartupCoordinator {
    struct Result {
        let loadError: String?
    }

    func performStartup(using container: AppContainer) -> Result {
        var errors: [String] = []
        var recoveryDiagnostics: [String] = []

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

        return Result(
            loadError: mergedStartupMessages(
                loadErrors: errors,
                recoveryDiagnostics: recoveryDiagnostics
            )
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
