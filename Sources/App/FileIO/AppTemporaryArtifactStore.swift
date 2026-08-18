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

    private static let decryptedRootName = "decrypted"
    private static let streamingRootName = "streaming"
    private static let operationRootNames = [decryptedRootName, streamingRootName]

    private let fileManager: FileManager
    private let temporaryDirectory: URL

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
        temporaryDirectory: URL? = nil
    ) {
        self.fileManager = fileManager
        self.temporaryDirectory = (temporaryDirectory ?? fileManager.temporaryDirectory).standardizedFileURL
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
        markLive(temporaryURL)
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
        markLive(ownerDirectory)
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
        url.lastPathComponent.hasPrefix("export-")
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
