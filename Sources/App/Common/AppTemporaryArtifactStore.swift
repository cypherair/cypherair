import Foundation

final class AppTemporaryArtifactStore {
    struct CleanupResult: Equatable {
        var removedItemCount = 0
        var failures: [String] = []
    }

    static let tutorialSandboxDefaultsSuiteName = "com.cypherair.tutorial.sandbox"
    static let legacyTutorialDefaultsSuitePrefix = "com.cypherair.tutorial."

    private let fileManager: FileManager
    private let temporaryDirectory: URL
    private let preferencesDirectory: URL
    private let legacyTutorialDefaultsSuitePrefix: String

    init(
        fileManager: FileManager = .default,
        temporaryDirectory: URL? = nil,
        preferencesDirectory: URL? = nil,
        legacyTutorialDefaultsSuitePrefix: String = AppTemporaryArtifactStore.legacyTutorialDefaultsSuitePrefix
    ) {
        self.fileManager = fileManager
        self.temporaryDirectory = (temporaryDirectory ?? fileManager.temporaryDirectory).standardizedFileURL
        self.preferencesDirectory = (
            preferencesDirectory
                ?? fileManager.urls(for: .libraryDirectory, in: .userDomainMask)[0]
                    .appendingPathComponent("Preferences", isDirectory: true)
        ).standardizedFileURL
        self.legacyTutorialDefaultsSuitePrefix = legacyTutorialDefaultsSuitePrefix
    }

    func makeStreamingArtifact(for inputURL: URL) throws -> AppTemporaryArtifact {
        let outputFilename = sanitizedFilename(inputURL.lastPathComponent, fallback: "file") + ".gpg"
        return try makeOperationArtifact(rootName: "streaming", outputFilename: outputFilename)
    }

    func makeDecryptedArtifact(for inputFilename: String) throws -> AppTemporaryArtifact {
        try makeOperationArtifact(
            rootName: "decrypted",
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
                try? fileManager.removeItem(at: temporaryURL)
            }
        }

        try data.write(to: temporaryURL, options: [.atomic, .completeFileProtection])
        try applyAndVerifyCompleteProtection(to: temporaryURL)
        shouldCleanup = false
        return temporaryURL
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
        for directoryName in ["decrypted", "streaming"] {
            removeTemporaryItemIfPresent(named: directoryName, isDirectory: true, result: &result)
        }

        guard let contents = try? fileManager.contentsOfDirectory(
            at: temporaryDirectory,
            includingPropertiesForKeys: nil
        ) else {
            return result
        }

        for url in contents where shouldRemoveTemporaryItem(url) {
            removeItem(url, result: &result)
        }
        return result
    }

    func remainingTemporaryArtifacts() -> [String] {
        var remaining: [String] = []
        for directoryName in ["decrypted", "streaming"] {
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

    func cleanupTutorialDefaultsSuites() -> CleanupResult {
        var result = CleanupResult()
        cleanupTutorialDefaultsSuite(
            named: Self.tutorialSandboxDefaultsSuiteName,
            result: &result
        )
        for suiteName in legacyTutorialDefaultsSuiteNames() {
            cleanupTutorialDefaultsSuite(named: suiteName, result: &result)
        }
        return result
    }

    func remainingTutorialDefaultsSuites() -> [String] {
        var suiteNames: [String] = []
        if fileManager.fileExists(
            atPath: tutorialDefaultsPlistURL(for: Self.tutorialSandboxDefaultsSuiteName).path
        ) {
            suiteNames.append(Self.tutorialSandboxDefaultsSuiteName)
        }
        suiteNames.append(contentsOf: legacyTutorialDefaultsSuiteNames())
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

    private func removeTemporaryItemIfPresent(
        named name: String,
        isDirectory: Bool,
        result: inout CleanupResult
    ) {
        let url = temporaryDirectory.appendingPathComponent(name, isDirectory: isDirectory)
        guard fileManager.fileExists(atPath: url.path) else { return }
        removeItem(url, result: &result)
    }

    private func removeItem(_ url: URL, result: inout CleanupResult) {
        do {
            try fileManager.removeItem(at: url)
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
            removeItem(plistURL, result: &result)
        }
    }

    private func tutorialDefaultsPlistURL(for suiteName: String) -> URL {
        preferencesDirectory.appendingPathComponent("\(suiteName).plist")
    }

    private func legacyTutorialDefaultsSuiteNames() -> [String] {
        guard let contents = try? fileManager.contentsOfDirectory(
            at: preferencesDirectory,
            includingPropertiesForKeys: nil
        ) else {
            return []
        }

        return contents.compactMap { url in
            guard url.pathExtension == "plist" else { return nil }
            let suiteName = url.deletingPathExtension().lastPathComponent
            guard suiteName.hasPrefix(legacyTutorialDefaultsSuitePrefix) else { return nil }
            guard suiteName != Self.tutorialSandboxDefaultsSuiteName else { return nil }
            let suffix = suiteName.dropFirst(legacyTutorialDefaultsSuitePrefix.count)
            guard UUID(uuidString: String(suffix)) != nil else { return nil }
            return suiteName
        }
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
