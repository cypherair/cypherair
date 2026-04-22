import Foundation

struct ProtectedDataStorageRoot {
    private let baseDirectory: URL
    private let fileManager: FileManager

    init(
        baseDirectory: URL? = nil,
        fileManager: FileManager = .default
    ) {
        self.baseDirectory = baseDirectory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.fileManager = fileManager
    }

    var rootURL: URL {
        baseDirectory.appendingPathComponent("ProtectedData", isDirectory: true)
    }

    var registryURL: URL {
        rootURL.appendingPathComponent("ProtectedDataRegistry.plist")
    }

    func domainDirectory(for domainID: ProtectedDataDomainID) -> URL {
        rootURL.appendingPathComponent(domainID.rawValue, isDirectory: true)
    }

    func bootstrapMetadataURL(for domainID: ProtectedDataDomainID) -> URL {
        domainDirectory(for: domainID).appendingPathComponent("bootstrap.plist")
    }

    func committedWrappedDomainMasterKeyURL(for domainID: ProtectedDataDomainID) -> URL {
        domainDirectory(for: domainID).appendingPathComponent("wrapped-dmk.plist")
    }

    func stagedWrappedDomainMasterKeyURL(for domainID: ProtectedDataDomainID) -> URL {
        domainDirectory(for: domainID).appendingPathComponent("wrapped-dmk.staged.plist")
    }

    func ensureRootDirectoryExists() throws {
        try createDirectoryIfNeeded(at: rootURL)
    }

    func ensureDomainDirectoryExists(for domainID: ProtectedDataDomainID) throws {
        try createDirectoryIfNeeded(at: domainDirectory(for: domainID))
    }

    func registryExists() -> Bool {
        fileManager.fileExists(atPath: registryURL.path)
    }

    func hasProtectedDataArtifacts() throws -> Bool {
        guard fileManager.fileExists(atPath: rootURL.path) else {
            return false
        }

        let contents = try fileManager.contentsOfDirectory(
            at: rootURL,
            includingPropertiesForKeys: nil
        )
        return !contents.isEmpty
    }

    func hasProtectedDataArtifactsExcludingRegistry() throws -> Bool {
        guard fileManager.fileExists(atPath: rootURL.path) else {
            return false
        }

        let contents = try fileManager.contentsOfDirectory(
            at: rootURL,
            includingPropertiesForKeys: nil
        )
        return contents.contains { $0.lastPathComponent != registryURL.lastPathComponent }
    }

    func writeProtectedData(_ data: Data, to url: URL) throws {
        try createDirectoryIfNeeded(at: url.deletingLastPathComponent())

        #if os(macOS)
        try data.write(to: url, options: .atomic)
        if try volumeSupportsFileProtection(for: url) {
            try applyFileProtection(to: url)
        }
        #else
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        try applyFileProtection(to: url)
        #endif
    }

    func promoteStagedFile(from stagedURL: URL, to committedURL: URL) throws {
        try createDirectoryIfNeeded(at: committedURL.deletingLastPathComponent())
        if fileManager.fileExists(atPath: committedURL.path) {
            try fileManager.removeItem(at: committedURL)
        }
        try fileManager.moveItem(at: stagedURL, to: committedURL)
        #if os(macOS)
        if try volumeSupportsFileProtection(for: committedURL) {
            try applyFileProtection(to: committedURL)
        }
        #else
        try applyFileProtection(to: committedURL)
        #endif
    }

    func removeItemIfPresent(at url: URL) throws {
        guard fileManager.fileExists(atPath: url.path) else {
            return
        }
        try fileManager.removeItem(at: url)
    }

    private func createDirectoryIfNeeded(at url: URL) throws {
        guard !fileManager.fileExists(atPath: url.path) else {
            return
        }

        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        #if os(macOS)
        if try volumeSupportsFileProtection(for: url) {
            try applyFileProtection(to: url)
        }
        #else
        try applyFileProtection(to: url)
        #endif
    }

    private func applyFileProtection(to url: URL) throws {
        try fileManager.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
    }

    private func volumeSupportsFileProtection(for url: URL) throws -> Bool {
        let values = try url.resourceValues(forKeys: [.volumeSupportsFileProtectionKey])
        return values.allValues[.volumeSupportsFileProtectionKey] as? Bool ?? false
    }
}
