import Foundation

enum ProtectedDataStorageValidationMode {
    case enforceAppSupportContainment
    case allowArbitraryBaseDirectoryForTesting
}

struct ProtectedDataStorageRoot {
    typealias FileProtectionCapabilityProvider = (URL) throws -> Bool

    private let baseDirectory: URL
    private let fileManager: FileManager
    private let validationMode: ProtectedDataStorageValidationMode
    private let fileProtectionCapabilityProvider: FileProtectionCapabilityProvider

    init(
        baseDirectory: URL? = nil,
        fileManager: FileManager = .default,
        validationMode: ProtectedDataStorageValidationMode? = nil,
        fileProtectionCapabilityProvider: @escaping FileProtectionCapabilityProvider = Self.defaultFileProtectionCapability(for:)
    ) {
        let resolvedBaseDirectory = baseDirectory ?? fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.baseDirectory = resolvedBaseDirectory.standardizedFileURL
        self.fileManager = fileManager
        self.validationMode = validationMode ?? {
            if baseDirectory == nil {
                return .enforceAppSupportContainment
            }
            return .allowArbitraryBaseDirectoryForTesting
        }()
        self.fileProtectionCapabilityProvider = fileProtectionCapabilityProvider
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

    func registryExists() throws -> Bool {
        try validatePersistentStorageContract()
        return fileManager.fileExists(atPath: registryURL.path)
    }

    func hasProtectedDataArtifacts() throws -> Bool {
        try validatePersistentStorageContract()

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
        try validatePersistentStorageContract()

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
        try validatePersistentStorageContract()
        try createDirectoryIfNeeded(at: url.deletingLastPathComponent())
        let scratchURL = temporaryProtectedWriteURL(for: url)
        var shouldCleanupScratch = true
        defer {
            if shouldCleanupScratch {
                try? fileManager.removeItem(at: scratchURL)
            }
        }

        try createProtectedFile(at: scratchURL, contents: data)
        try promoteProtectedFile(from: scratchURL, to: url)
        shouldCleanupScratch = false
    }

    func promoteStagedFile(from stagedURL: URL, to committedURL: URL) throws {
        try validatePersistentStorageContract()
        try createDirectoryIfNeeded(at: committedURL.deletingLastPathComponent())
        try promoteProtectedFile(from: stagedURL, to: committedURL)
    }

    func removeItemIfPresent(at url: URL) throws {
        guard fileManager.fileExists(atPath: url.path) else {
            return
        }
        try fileManager.removeItem(at: url)
    }

    func validatePersistentStorageContract() throws {
        switch validationMode {
        case .allowArbitraryBaseDirectoryForTesting:
            return
        case .enforceAppSupportContainment:
            try validateBaseDirectoryIsWithinApplicationSupport()
            guard try fileProtectionCapabilityProvider(baseDirectory) else {
                throw ProtectedDataError.fileProtectionUnsupported
            }
        }
    }

    private func createDirectoryIfNeeded(at url: URL) throws {
        try validatePersistentStorageContract()

        guard !fileManager.fileExists(atPath: url.path) else {
            try applyAndVerifyFileProtection(to: url)
            return
        }

        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        try applyAndVerifyFileProtection(to: url)
    }

    private func validateBaseDirectoryIsWithinApplicationSupport() throws {
        let applicationSupportDirectory = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .standardizedFileURL
        let standardizedBaseDirectory = baseDirectory.standardizedFileURL

        guard standardizedBaseDirectory == applicationSupportDirectory ||
                standardizedBaseDirectory.path.hasPrefix(applicationSupportDirectory.path + "/") else {
            throw ProtectedDataError.storageRootOutsideApplicationSupport
        }
    }

    private func createProtectedFile(at url: URL, contents: Data) throws {
        guard fileManager.createFile(
            atPath: url.path,
            contents: contents,
            attributes: [.protectionKey: FileProtectionType.complete]
        ) else {
            throw ProtectedDataError.protectedFileWriteFailed
        }

        try applyAndVerifyFileProtection(to: url)
    }

    private func promoteProtectedFile(from sourceURL: URL, to destinationURL: URL) throws {
        if fileManager.fileExists(atPath: destinationURL.path) {
            _ = try fileManager.replaceItemAt(
                destinationURL,
                withItemAt: sourceURL,
                backupItemName: nil
            )
        } else {
            try fileManager.moveItem(at: sourceURL, to: destinationURL)
        }

        try applyAndVerifyFileProtection(to: destinationURL)
    }

    private func temporaryProtectedWriteURL(for destinationURL: URL) -> URL {
        destinationURL.deletingLastPathComponent().appendingPathComponent(
            ".\(destinationURL.lastPathComponent).\(UUID().uuidString).protected-write"
        )
    }

    private func applyAndVerifyFileProtection(to url: URL) throws {
        guard try fileProtectionCapabilityProvider(url) else {
            throw ProtectedDataError.fileProtectionUnsupported
        }

        try applyFileProtection(to: url)
        try verifyFileProtection(at: url)
    }

    private func applyFileProtection(to url: URL) throws {
        try fileManager.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
    }

    private func verifyFileProtection(at url: URL) throws {
        let attributes = try fileManager.attributesOfItem(atPath: url.path)
        guard let protection = attributes[.protectionKey] as? FileProtectionType,
                protection == .complete else {
            throw ProtectedDataError.fileProtectionVerificationFailed
        }
    }

    private static func defaultFileProtectionCapability(for url: URL) throws -> Bool {
        let values = try url.resourceValues(forKeys: [.volumeSupportsFileProtectionKey])
        return values.allValues[.volumeSupportsFileProtectionKey] as? Bool ?? false
    }
}
