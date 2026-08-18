import Foundation

/// `@unchecked Sendable`, which the sweep needs because it runs off the main
/// actor alongside the session. The mutable state is the live-artifact set,
/// guarded by `liveArtifactLock`; everything else is a `let`. `FileManager` is
/// not `Sendable` and Apple documents concurrent use only for `FileManager
/// .default` — which is what the app passes everywhere. The parameter is a test
/// seam, and a test that supplies its own instance owns its confinement.
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

    /// Paths this process handed out. The sweep no longer finishes before the
    /// session starts, so "present in `tmp/`" stopped meaning "abandoned" and
    /// something has to carry the difference.
    ///
    /// Insert-only by design: artifact names are per-operation UUIDs and are
    /// never reused, so an entry left behind after its artifact is erased can
    /// only ever match a path that no longer exists.
    private let liveArtifactLock = NSLock()
    private var liveArtifactPaths: Set<String> = []

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
        try fileManager.createProtectedDirectory(at: directory)
        markLive(directory)
        return directory
    }

    /// Stage export data inside an owned directory born with the protection
    /// class, rather than as a loose file whose class would be its own.
    func writeProtectedExportData(_ data: Data, suggestedFilename: String) throws -> AppTemporaryArtifact {
        let ownerDirectory = temporaryDirectory
            .appendingPathComponent("export-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createProtectedDirectory(at: ownerDirectory)
        var shouldCleanup = true
        defer {
            if shouldCleanup {
                eraseTemporaryArtifact(at: ownerDirectory)
            }
        }

        let fileURL = ownerDirectory.appendingPathComponent(
            sanitizedFilename(suggestedFilename, fallback: "export.data")
        )
        try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
        markLive(ownerDirectory)
        shouldCleanup = false
        return AppTemporaryArtifact(fileURL: fileURL, ownerDirectoryURL: ownerDirectory)
    }

    /// Erase an artifact this store handed out, for owners that hold the URL
    /// rather than an `AppTemporaryArtifact`.
    func eraseTemporaryArtifact(at url: URL) {
        try? TemporaryArtifactEraser.erase(at: url, fileManager: fileManager)
    }

    /// Erase what a previous session left behind, sparing everything this one is
    /// still using.
    ///
    /// This is the launch sweep, and it no longer completes before the app
    /// starts working — so it has to be able to tell an abandoned artifact from
    /// a live one. `liveArtifactPaths` is that answer: without it the sweep
    /// would zero an export while the share sheet was offering it, or take the
    /// tutorial's store out from under the running tutorial.
    func sweepAbandonedArtifacts() -> CleanupResult {
        sweep(sparingLiveArtifacts: true)
    }

    /// Erase every temporary artifact, live ones included — the session they
    /// belong to is being destroyed along with them.
    func removeAllTemporaryArtifacts() -> CleanupResult {
        sweep(sparingLiveArtifacts: false)
    }

    private func sweep(sparingLiveArtifacts: Bool) -> CleanupResult {
        var result = CleanupResult()
        for directoryName in Self.operationRootNames {
            eraseOperationRootContents(
                named: directoryName,
                sparingLiveArtifacts: sparingLiveArtifacts,
                result: &result
            )
        }

        guard let contents = try? fileManager.contentsOfDirectory(
            at: temporaryDirectory,
            includingPropertiesForKeys: nil
        ) else {
            return result
        }

        for url in contents where shouldRemoveTemporaryItem(url) {
            guard !(sparingLiveArtifacts && isLive(url)) else { continue }
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
        let ownerDirectory = temporaryDirectory
            .appendingPathComponent(rootName, isDirectory: true)
            .appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createProtectedDirectory(at: ownerDirectory)
        markLive(ownerDirectory)
        return AppTemporaryArtifact(
            fileURL: ownerDirectory.appendingPathComponent(
                sanitizedFilename(outputFilename, fallback: "file")
            ),
            ownerDirectoryURL: ownerDirectory
        )
    }

    /// Erase the per-operation directories under one root, then the root itself
    /// if that emptied it.
    ///
    /// Per-operation rather than wholesale: a live operation's directory has to
    /// survive, and so does the root above it. Leaving a root behind costs
    /// nothing — creating one is idempotent — and once a root is genuinely
    /// empty it goes, which is what keeps `remainingTemporaryArtifacts()` and
    /// the local-data-reset post-condition meaning what they did.
    private func eraseOperationRootContents(
        named name: String,
        sparingLiveArtifacts: Bool,
        result: inout CleanupResult
    ) {
        let root = temporaryDirectory.appendingPathComponent(name, isDirectory: true)
        guard let contents = try? fileManager.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ) else {
            return
        }

        for url in contents {
            guard !(sparingLiveArtifacts && isLive(url)) else { continue }
            eraseItem(url, result: &result)
        }

        if (try? fileManager.contentsOfDirectory(atPath: root.path))?.isEmpty == true {
            eraseItem(root, result: &result)
        }
    }

    private func markLive(_ url: URL) {
        let path = url.standardizedFileURL.path
        liveArtifactLock.lock()
        liveArtifactPaths.insert(path)
        liveArtifactLock.unlock()
    }

    private func isLive(_ url: URL) -> Bool {
        let path = url.standardizedFileURL.path
        liveArtifactLock.lock()
        defer { liveArtifactLock.unlock() }
        return liveArtifactPaths.contains(path)
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

    private func sanitizedFilename(_ filename: String, fallback: String) -> String {
        Self.sanitizedFilename(filename, fallback: fallback)
    }

    private static func sanitizedFilename(_ filename: String, fallback: String) -> String {
        let lastPathComponent = (filename as NSString).lastPathComponent
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return lastPathComponent.isEmpty ? fallback : lastPathComponent
    }
}
