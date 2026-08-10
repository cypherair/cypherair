import Foundation

/// `@unchecked Sendable`: every stored property is a `let`, and the only state
/// the store mutates is the filesystem. `FileManager` is not `Sendable`, but its
/// methods are safe to call concurrently as long as no delegate is attached, and
/// none is here. The launch sweep runs off the main actor and needs this.
final class AppTemporaryArtifactStore: @unchecked Sendable {
    struct CleanupResult: Equatable {
        var removedItemCount = 0
        var failures: [String] = []
    }

    static let tutorialSandboxDefaultsSuiteName = "com.cypherair.tutorial.sandbox"

    private static let decryptedRootName = "decrypted"
    private static let streamingRootName = "streaming"
    private static let operationRootNames = [decryptedRootName, streamingRootName]

    private let fileManager: FileManager
    private let temporaryDirectory: URL
    private let preferencesDirectory: URL

    init(
        fileManager: FileManager = .default,
        temporaryDirectory: URL? = nil,
        preferencesDirectory: URL? = nil
    ) {
        self.fileManager = fileManager
        self.temporaryDirectory = (temporaryDirectory ?? fileManager.temporaryDirectory).standardizedFileURL
        self.preferencesDirectory = (
            preferencesDirectory
                ?? fileManager.urls(for: .libraryDirectory, in: .userDomainMask)[0]
                    .appendingPathComponent("Preferences", isDirectory: true)
        ).standardizedFileURL
    }

    func makeStreamingArtifact(for inputURL: URL) throws -> AppTemporaryArtifact {
        let outputFilename = sanitizedFilename(inputURL.lastPathComponent, fallback: "file") + ".gpg"
        return try makeOperationArtifact(
            rootName: Self.streamingRootName,
            outputFilename: outputFilename
        )
    }

    func makeDecryptedArtifact(for inputFilename: String) throws -> AppTemporaryArtifact {
        try makeOperationArtifact(
            rootName: Self.decryptedRootName,
            outputFilename: Self.decryptedOutputFilename(for: inputFilename)
        )
    }

    func makeTutorialSandboxDirectory() throws -> URL {
        let directory = temporaryDirectory.appendingPathComponent(
            "CypherAirGuidedTutorial-\(UUID().uuidString)",
            isDirectory: true
        )
        try createProtectedDirectory(at: directory)
        return directory
    }

    func writeProtectedExportData(_ data: Data, suggestedFilename: String) throws -> URL {
        let sanitizedFilename = sanitizedFilename(suggestedFilename, fallback: "export.data")
        let temporaryURL = temporaryDirectory
            .appendingPathComponent("export-\(UUID().uuidString)-\(sanitizedFilename)")
        var shouldCleanup = true
        defer {
            if shouldCleanup {
                eraseTemporaryArtifact(at: temporaryURL)
            }
        }

        try data.write(to: temporaryURL, options: [.atomic, .completeFileProtection])
        try applyAndVerifyCompleteProtection(to: temporaryURL)
        shouldCleanup = false
        return temporaryURL
    }

    /// Erase an artifact this store handed out, for owners that hold the URL
    /// rather than an `AppTemporaryArtifact`.
    func eraseTemporaryArtifact(at url: URL) {
        try? TemporaryArtifactEraser.erase(at: url, fileManager: fileManager)
    }

    func applyAndVerifyCompleteProtection(to url: URL) throws {
        let resolvedURL = url.standardizedFileURL
        guard try supportsFileProtection(for: resolvedURL) else {
            throw AppTemporaryArtifactError.fileProtectionUnsupported(resolvedURL)
        }

        try fileManager.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: resolvedURL.path
        )
        let attributes = try fileManager.attributesOfItem(atPath: resolvedURL.path)
        guard attributes[.protectionKey] as? FileProtectionType == .complete else {
            throw AppTemporaryArtifactError.fileProtectionVerificationFailed(resolvedURL)
        }
    }

    func cleanupTemporaryArtifacts() -> CleanupResult {
        var result = CleanupResult()
        for directoryName in Self.operationRootNames {
            eraseOperationRootContents(named: directoryName, result: &result)
        }

        guard let contents = try? fileManager.contentsOfDirectory(
            at: temporaryDirectory,
            includingPropertiesForKeys: nil
        ) else {
            return result
        }

        for url in contents where shouldRemoveTemporaryItem(url) {
            eraseItem(url, result: &result)
        }
        return result
    }

    func remainingTemporaryArtifacts() -> [String] {
        var remaining: [String] = []
        for directoryName in Self.operationRootNames {
            let directory = temporaryDirectory.appendingPathComponent(directoryName, isDirectory: true)
            if fileManager.fileExists(atPath: directory.path) {
                remaining.append(directoryName)
            }
        }

        guard let contents = try? fileManager.contentsOfDirectory(
            at: temporaryDirectory,
            includingPropertiesForKeys: nil
        ) else {
            return remaining
        }

        remaining.append(contentsOf: contents.filter(shouldRemoveTemporaryItem).map(\.lastPathComponent))
        return remaining
    }

    func cleanupTutorialSandboxDefaultsSuite() -> CleanupResult {
        var result = CleanupResult()
        cleanupTutorialDefaultsSuite(
            named: Self.tutorialSandboxDefaultsSuiteName,
            result: &result
        )
        return result
    }

    func remainingTutorialSandboxDefaultsSuites() -> [String] {
        var suiteNames: [String] = []
        if fileManager.fileExists(
            atPath: tutorialDefaultsPlistURL(for: Self.tutorialSandboxDefaultsSuiteName).path
        ) {
            suiteNames.append(Self.tutorialSandboxDefaultsSuiteName)
        }
        return suiteNames
    }

    static func decryptedOutputFilename(for inputFilename: String) -> String {
        let sanitizedInputFilename = sanitizedFilename(inputFilename, fallback: "file")
        let ext = (sanitizedInputFilename as NSString).pathExtension.lowercased()
        if ["gpg", "pgp", "asc"].contains(ext) {
            let stripped = (sanitizedInputFilename as NSString).deletingPathExtension
            return stripped.isEmpty ? "file" : stripped
        }
        return sanitizedInputFilename + ".decrypted"
    }

    private func makeOperationArtifact(rootName: String, outputFilename: String) throws -> AppTemporaryArtifact {
        let rootDirectory = temporaryDirectory.appendingPathComponent(rootName, isDirectory: true)
        let ownerDirectory = rootDirectory.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true)
        try createProtectedDirectory(at: rootDirectory)
        try createProtectedDirectory(at: ownerDirectory)
        return AppTemporaryArtifact(
            fileURL: ownerDirectory.appendingPathComponent(
                sanitizedFilename(outputFilename, fallback: "file")
            ),
            ownerDirectoryURL: ownerDirectory
        )
    }

    private func createProtectedDirectory(at url: URL) throws {
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        try applyAndVerifyCompleteProtection(to: url)
    }

    /// Erase the per-operation directories under one root, then the root itself
    /// once it is empty.
    ///
    /// Per-operation rather than wholesale because the sweep runs off the launch
    /// path, concurrently with the rest of the app: a directory that appears
    /// after this snapshot belongs to a live operation, and taking the root out
    /// from under it would fail that operation. Leaving the root behind costs
    /// nothing — creating one is idempotent.
    private func eraseOperationRootContents(named name: String, result: inout CleanupResult) {
        let root = temporaryDirectory.appendingPathComponent(name, isDirectory: true)
        guard let contents = try? fileManager.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ) else {
            return
        }

        for url in contents {
            eraseItem(url, result: &result)
        }

        if (try? fileManager.contentsOfDirectory(atPath: root.path))?.isEmpty == true {
            eraseItem(root, result: &result)
        }
    }

    private func eraseItem(_ url: URL, result: inout CleanupResult) {
        do {
            try TemporaryArtifactEraser.erase(at: url, fileManager: fileManager)
            result.removedItemCount += 1
        } catch {
            result.failures.append("\(url.lastPathComponent).\(String(describing: type(of: error)))")
        }
    }

    private func shouldRemoveTemporaryItem(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        return name.hasPrefix("export-")
            || name.hasPrefix("CypherAirGuidedTutorial-")
    }

    private func cleanupTutorialDefaultsSuite(
        named suiteName: String,
        result: inout CleanupResult
    ) {
        if let defaults = UserDefaults(suiteName: suiteName) {
            defaults.removePersistentDomain(forName: suiteName)
            _ = defaults.synchronize()
        }

        let plistURL = tutorialDefaultsPlistURL(for: suiteName)
        if fileManager.fileExists(atPath: plistURL.path) {
            eraseItem(plistURL, result: &result)
        }
    }

    private func tutorialDefaultsPlistURL(for suiteName: String) -> URL {
        preferencesDirectory.appendingPathComponent("\(suiteName).plist")
    }

    private func supportsFileProtection(for url: URL) throws -> Bool {
        let probeURL: URL
        if fileManager.fileExists(atPath: url.path) {
            probeURL = url
        } else {
            probeURL = url.deletingLastPathComponent()
        }
        let values = try probeURL.resourceValues(forKeys: [.volumeSupportsFileProtectionKey])
        return values.allValues[.volumeSupportsFileProtectionKey] as? Bool ?? false
    }

    private func sanitizedFilename(_ filename: String, fallback: String) -> String {
        Self.sanitizedFilename(filename, fallback: fallback)
    }

    private static func sanitizedFilename(_ filename: String, fallback: String) -> String {
        let lastPathComponent = (filename as NSString).lastPathComponent
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return lastPathComponent.isEmpty ? fallback : lastPathComponent
    }
}
