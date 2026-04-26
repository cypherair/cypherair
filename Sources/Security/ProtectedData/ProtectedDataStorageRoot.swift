import Foundation

enum ProtectedDataStorageValidationMode {
    case enforceAppSupportContainment
    case allowArbitraryBaseDirectoryForTesting
}

struct ProtectedDataStorageRoot {
    typealias FileProtectionCapabilityProvider = (URL) throws -> Bool

    private struct ValidatedPersistentStorageContract {
        let applicationSupportDirectory: URL
        let baseDirectory: URL
        let rootURL: URL
    }

    private let baseDirectory: URL
    private let fileManager: FileManager
    private let validationMode: ProtectedDataStorageValidationMode
    private let fileProtectionCapabilityProvider: FileProtectionCapabilityProvider
    private let traceStore: AuthLifecycleTraceStore?

    init(
        baseDirectory: URL? = nil,
        fileManager: FileManager = .default,
        validationMode: ProtectedDataStorageValidationMode? = nil,
        fileProtectionCapabilityProvider: @escaping FileProtectionCapabilityProvider = Self.defaultFileProtectionCapability(for:),
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        let configuredBaseDirectory = baseDirectory ?? fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.baseDirectory = configuredBaseDirectory.standardizedFileURL
        self.fileManager = fileManager
        self.validationMode = validationMode ?? {
            if baseDirectory == nil {
                return .enforceAppSupportContainment
            }
            return .allowArbitraryBaseDirectoryForTesting
        }()
        self.fileProtectionCapabilityProvider = fileProtectionCapabilityProvider
        self.traceStore = traceStore
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

    func domainEnvelopeURL(
        for domainID: ProtectedDataDomainID,
        slot: ProtectedDomainGenerationSlot
    ) -> URL {
        domainDirectory(for: domainID).appendingPathComponent("\(slot.rawValue).plist")
    }

    func ensureRootDirectoryExists() throws {
        traceStorageContract(stage: "rootEnsure", result: "start")
        do {
            let validatedContract = try validatedPersistentStorageContract()
            try createDirectoryIfNeeded(at: rootURL, validatedContract: validatedContract)
            traceStorageContract(stage: "rootEnsure", result: "success")
        } catch {
            traceStorageContract(stage: "rootEnsure", result: "failed", error: error)
            throw error
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
            try applyAndVerifyFileProtection(to: url)
            return
        }

        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        try applyAndVerifyFileProtection(to: url)
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
        case .allowArbitraryBaseDirectoryForTesting:
            return validatedContract
        case .enforceAppSupportContainment:
            guard isContained(validatedContract.baseDirectory, within: validatedContract.applicationSupportDirectory),
                    isContained(validatedContract.rootURL, within: validatedContract.applicationSupportDirectory) else {
                let error = ProtectedDataError.storageRootOutsideApplicationSupport
                traceStorageContract(stage: "containmentCheck", result: "failed", error: error)
                throw error
            }
            traceStorageContract(stage: "containmentCheck", result: "success")

            let fileProtectionProbe = fileProtectionProbeURL(within: validatedContract)
            traceStorageContract(
                stage: "protectionProbe",
                result: "start",
                metadata: ["probeKind": fileProtectionProbe.kind]
            )

            let supportsFileProtection: Bool
            do {
                supportsFileProtection = try fileProtectionCapabilityProvider(fileProtectionProbe.url)
            } catch {
                traceStorageContract(
                    stage: "protectionProbe",
                    result: "failed",
                    metadata: ["probeKind": fileProtectionProbe.kind],
                    error: error
                )
                throw error
            }

            guard supportsFileProtection else {
                let error = ProtectedDataError.fileProtectionUnsupported
                traceStorageContract(
                    stage: "protectionProbe",
                    result: "unsupported",
                    metadata: ["probeKind": fileProtectionProbe.kind],
                    error: error
                )
                throw error
            }
            traceStorageContract(
                stage: "protectionProbe",
                result: "success",
                metadata: ["probeKind": fileProtectionProbe.kind]
            )

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
        let resolvedURL = resolvedFileSystemURL(for: url)

        guard try fileProtectionCapabilityProvider(resolvedURL) else {
            throw ProtectedDataError.fileProtectionUnsupported
        }

        try applyFileProtection(to: resolvedURL)
        try verifyFileProtection(at: resolvedURL)
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

    private func fileProtectionProbeURL(
        within validatedContract: ValidatedPersistentStorageContract
    ) -> (url: URL, kind: String) {
        if fileManager.fileExists(atPath: validatedContract.rootURL.path) || isSymbolicLink(at: validatedContract.rootURL) {
            return (validatedContract.rootURL, "root")
        }
        if fileManager.fileExists(atPath: validatedContract.baseDirectory.path) || isSymbolicLink(at: validatedContract.baseDirectory) {
            return (validatedContract.baseDirectory, "base")
        }
        if fileManager.fileExists(atPath: validatedContract.applicationSupportDirectory.path)
            || isSymbolicLink(at: validatedContract.applicationSupportDirectory) {
            return (validatedContract.applicationSupportDirectory, "applicationSupport")
        }
        return (nearestExistingAncestor(for: validatedContract.applicationSupportDirectory), "existingAncestor")
    }

    private func nearestExistingAncestor(for url: URL) -> URL {
        var candidate = url.standardizedFileURL
        while candidate != candidate.deletingLastPathComponent() {
            if fileManager.fileExists(atPath: candidate.path) || isSymbolicLink(at: candidate) {
                return resolvedFileSystemURL(for: candidate)
            }
            candidate = candidate.deletingLastPathComponent()
        }
        return candidate
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

    private func traceStorageContract(
        stage: String,
        result: String,
        metadata: [String: String] = [:],
        error: Error? = nil
    ) {
        var traceMetadata = metadata
        traceMetadata["stage"] = stage
        traceMetadata["result"] = result
        if let error {
            traceMetadata = AuthTraceMetadata.errorMetadata(error, extra: traceMetadata)
        }
        traceStore?.record(
            category: .operation,
            name: "protectedData.storageContract",
            metadata: traceMetadata
        )
    }
}
