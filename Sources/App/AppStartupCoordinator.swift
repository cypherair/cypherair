import Foundation

/// Startup workflow for loading persisted state and recovering interrupted operations.
struct AppStartupCoordinator {
    struct Result {
        let loadError: String?
    }

    func performStartup(using container: AppContainer) -> Result {
        var errors: [String] = []

        do {
            try container.keyManagement.loadKeys()
        } catch {
            errors.append(error.localizedDescription)
        }

        container.authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: container.keyManagement.keys.map(\.fingerprint)
        )
        container.keyManagement.checkAndRecoverFromInterruptedModifyExpiry()

        do {
            try container.contactService.loadContacts()
        } catch {
            errors.append(error.localizedDescription)
        }

        cleanupTemporaryFiles()

        return Result(loadError: errors.isEmpty ? nil : errors.joined(separator: "\n"))
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
}
