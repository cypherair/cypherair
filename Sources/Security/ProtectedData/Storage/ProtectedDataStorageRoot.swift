import Foundation

enum ProtectedDataStorageValidationMode {
    case enforceAppSupportContainment
    case allowArbitraryBaseDirectory
}

struct ProtectedDataStorageRoot {
    private struct ValidatedPersistentStorageContract {
        let applicationSupportDirectory: URL
        let baseDirectory: URL
        let rootURL: URL
    }

    private let baseDirectory: URL
    private let fileManager: FileManager
    private let validationMode: ProtectedDataStorageValidationMode

    init(
        baseDirectory: URL? = nil,
        fileManager: FileManager = .default,
        validationMode: ProtectedDataStorageValidationMode? = nil
    ) {
        let configuredBaseDirectory = baseDirectory ?? fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.baseDirectory = configuredBaseDirectory.standardizedFileURL
        self.fileManager = fileManager
        self.validationMode = validationMode ?? {
            if baseDirectory == nil {
                return .enforceAppSupportContainment
            }
            return .allowArbitraryBaseDirectory
        }()
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

    func domainEnvelopeURL(
        for domainID: ProtectedDataDomainID,
        slot: ProtectedDomainGenerationSlot
    ) -> URL {
        domainDirectory(for: domainID).appendingPathComponent("\(slot.rawValue).plist")
    }

    func contactsSQLCipherDatabaseURL(for domainID: ProtectedDataDomainID) -> URL {
        domainDirectory(for: domainID).appendingPathComponent("contacts.sqlite")
    }

    /// The database file plus the side-file its journaling mode produces — the
    /// erasure list for reset and recovery. The connection runs in SQLite's
    /// default rollback-journal mode, so an interrupted write can leave
    /// `-journal` behind; nothing else is ever created beside the database
    /// (temporary storage is compiled to memory).
    func contactsSQLCipherDatabaseFileURLs(for domainID: ProtectedDataDomainID) -> [URL] {
        let databaseURL = contactsSQLCipherDatabaseURL(for: domainID)
        return [
            databaseURL,
            databaseURL.deletingLastPathComponent()
                .appendingPathComponent("\(databaseURL.lastPathComponent)-journal"),
        ]
    }

    /// Creates the root directory if needed, and makes the one file-protection
    /// check in the app: the class the root came out with is the class
    /// intended. Everything beneath it is born inside a directory created with
    /// the class as a creation attribute and inherits it, so nothing below is
    /// ever verified after the fact.
    func ensureRootDirectoryExists() throws {
        let validatedContract = try validatedPersistentStorageContract()
        try createDirectoryIfNeeded(at: rootURL, validatedContract: validatedContract)

        let attributes = try fileManager.attributesOfItem(atPath: validatedContract.rootURL.path)
        guard attributes[.protectionKey] as? FileProtectionType == .complete else {
            throw ProtectedDataError.fileProtectionVerificationFailed
        }
    }

    func ensureDomainDirectoryExists(for domainID: ProtectedDataDomainID) throws {
        let validatedContract = try validatedPersistentStorageContract()
        try createDirectoryIfNeeded(
            at: domainDirectory(for: domainID),
            validatedContract: validatedContract
        )
    }

    func registryExists() throws -> Bool {
        try managedItemExists(at: registryURL)
    }

    func hasProtectedDataArtifacts() throws -> Bool {
        let validatedContract = try validatedPersistentStorageContract()
        let resolvedRootURL = try validateManagedPath(rootURL, within: validatedContract)

        guard fileManager.fileExists(atPath: resolvedRootURL.path) else {
            return false
        }

        let contents = try fileManager.contentsOfDirectory(
            at: resolvedRootURL,
            includingPropertiesForKeys: nil
        )
        return !contents.isEmpty
    }

    func hasProtectedDataArtifactsExcludingRegistry() throws -> Bool {
        let validatedContract = try validatedPersistentStorageContract()
        let resolvedRootURL = try validateManagedPath(rootURL, within: validatedContract)

        guard fileManager.fileExists(atPath: resolvedRootURL.path) else {
            return false
        }

        let contents = try fileManager.contentsOfDirectory(
            at: resolvedRootURL,
            includingPropertiesForKeys: nil
        )
        return contents.contains { $0.lastPathComponent != registryURL.lastPathComponent }
    }

    func writeProtectedData(_ data: Data, to url: URL) throws {
        let validatedContract = try validatedPersistentStorageContract()
        try createDirectoryIfNeeded(
            at: url.deletingLastPathComponent(),
            validatedContract: validatedContract
        )
        _ = try validateManagedPath(url, within: validatedContract)
        let scratchURL = temporaryProtectedWriteURL(for: url)
        _ = try validateManagedPath(scratchURL, within: validatedContract)
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
        let validatedContract = try validatedPersistentStorageContract()
        _ = try validateManagedPath(stagedURL, within: validatedContract)
        try createDirectoryIfNeeded(
            at: committedURL.deletingLastPathComponent(),
            validatedContract: validatedContract
        )
        _ = try validateManagedPath(committedURL, within: validatedContract)
        try promoteProtectedFile(from: stagedURL, to: committedURL)
    }

    func removeItemIfPresent(at url: URL) throws {
        let validatedContract = try validatedPersistentStorageContract()
        let resolvedURL = try validateManagedPath(url, within: validatedContract)
        guard fileManager.fileExists(atPath: resolvedURL.path) else {
            return
        }
        try fileManager.removeItem(at: url)
    }

    func removeContactsSQLCipherDatabaseFilesIfPresent(for domainID: ProtectedDataDomainID) throws {
        for url in contactsSQLCipherDatabaseFileURLs(for: domainID) {
            try removeItemIfPresent(at: url)
        }
    }

    func removeDomainDirectoryIfPresent(for domainID: ProtectedDataDomainID) throws {
        try removeItemIfPresent(at: domainDirectory(for: domainID))
    }

    func validatePersistentStorageContract() throws {
        _ = try validatedPersistentStorageContract()
    }

    func managedItemExists(at url: URL) throws -> Bool {
        let validatedContract = try validatedPersistentStorageContract()
        let resolvedURL = try validateManagedPath(url, within: validatedContract)
        return fileManager.fileExists(atPath: resolvedURL.path)
    }

    func readManagedData(at url: URL) throws -> Data {
        let validatedContract = try validatedPersistentStorageContract()
        let resolvedURL = try validateManagedPath(url, within: validatedContract)
        return try Data(contentsOf: resolvedURL)
    }

    private func createDirectoryIfNeeded(
        at url: URL,
        validatedContract: ValidatedPersistentStorageContract
    ) throws {
        _ = try validateManagedPath(url, within: validatedContract)

        guard !fileManager.fileExists(atPath: url.path) else {
            return
        }

        try fileManager.createProtectedDirectory(at: url)
    }

    private func validatedPersistentStorageContract() throws -> ValidatedPersistentStorageContract {
        let validatedContract = ValidatedPersistentStorageContract(
            applicationSupportDirectory: resolvedFileSystemURL(
                for: fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            ),
            baseDirectory: resolvedFileSystemURL(for: baseDirectory),
            rootURL: resolvedFileSystemURL(for: rootURL)
        )

        switch validationMode {
        case .allowArbitraryBaseDirectory:
            return validatedContract
        case .enforceAppSupportContainment:
            guard isContained(validatedContract.baseDirectory, within: validatedContract.applicationSupportDirectory),
                    isContained(validatedContract.rootURL, within: validatedContract.applicationSupportDirectory) else {
                throw ProtectedDataError.storageRootOutsideApplicationSupport
            }

            return validatedContract
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
    }

    private func temporaryProtectedWriteURL(for destinationURL: URL) -> URL {
        destinationURL.deletingLastPathComponent().appendingPathComponent(
            ".\(destinationURL.lastPathComponent).\(UUID().uuidString).protected-write"
        )
    }

    private func validateManagedPath(
        _ url: URL,
        within validatedContract: ValidatedPersistentStorageContract
    ) throws -> URL {
        let resolvedURL = resolvedFileSystemURL(for: url)
        guard isContained(resolvedURL, within: validatedContract.rootURL) else {
            throw ProtectedDataError.storageRootOutsideApplicationSupport
        }
        return resolvedURL
    }

    private func resolvedFileSystemURL(for url: URL) -> URL {
        let standardizedURL = url.standardizedFileURL
        if fileManager.fileExists(atPath: standardizedURL.path) || isSymbolicLink(at: standardizedURL) {
            return standardizedURL.resolvingSymlinksInPath().standardizedFileURL
        }

        let parentURL = standardizedURL.deletingLastPathComponent()
        guard parentURL != standardizedURL else {
            return standardizedURL
        }

        return resolvedFileSystemURL(for: parentURL).appendingPathComponent(
            standardizedURL.lastPathComponent,
            isDirectory: standardizedURL.hasDirectoryPath
        ).standardizedFileURL
    }

    private func isContained(_ candidateURL: URL, within parentURL: URL) -> Bool {
        candidateURL == parentURL || candidateURL.path.hasPrefix(parentURL.path + "/")
    }

    private func isSymbolicLink(at url: URL) -> Bool {
        (try? fileManager.destinationOfSymbolicLink(atPath: url.path)) != nil
    }
}
