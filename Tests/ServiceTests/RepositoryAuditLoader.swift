import Foundation

/// Loads build-time repository audit inputs from the test bundle.
enum RepositoryAuditLoader {
    private final class BundleMarker {}

    private static let bundle = Bundle(for: BundleMarker.self)
    private static let snapshotSubdirectory = "RepositoryAudit"
    private static let requiredRelativePaths = [
        "Sources/App/Encrypt/EncryptView.swift",
        "Sources/Resources/Localizable.xcstrings",
        "Sources/Resources/InfoPlist.xcstrings",
    ]

    static func sourcesRootURL() throws -> URL {
        try url(relativePath: "Sources")
    }

    static func url(relativePath: String) throws -> URL {
        let snapshotRootURL = try validatedSnapshotRootURL()
        let normalizedPath = relativePath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let targetURL = snapshotRootURL.appending(path: normalizedPath)

        guard FileManager.default.fileExists(atPath: targetURL.path) else {
            throw RepositoryAuditError.missingResource(normalizedPath)
        }

        return targetURL
    }

    static func loadData(relativePath: String) throws -> Data {
        try Data(contentsOf: url(relativePath: relativePath))
    }

    static func loadString(relativePath: String) throws -> String {
        let data = try loadData(relativePath: relativePath)
        guard let string = String(data: data, encoding: .utf8) else {
            throw RepositoryAuditError.invalidEncoding(relativePath)
        }
        return string
    }

    private static func validatedSnapshotRootURL() throws -> URL {
        guard let resourceURL = bundle.resourceURL else {
            throw RepositoryAuditError.missingBundleResourceURL
        }

        let snapshotRootURL = resourceURL.appending(path: snapshotSubdirectory, directoryHint: .isDirectory)
        for requiredPath in requiredRelativePaths {
            let requiredURL = snapshotRootURL.appending(path: requiredPath)
            guard FileManager.default.fileExists(atPath: requiredURL.path) else {
                throw RepositoryAuditError.missingSnapshot(requiredPath)
            }
        }

        return snapshotRootURL
    }

    enum RepositoryAuditError: Error, CustomStringConvertible {
        case missingBundleResourceURL
        case missingSnapshot(String)
        case missingResource(String)
        case invalidEncoding(String)

        var description: String {
            switch self {
            case .missingBundleResourceURL:
                return "CypherAirTests bundle is missing a resource URL for RepositoryAudit inputs"
            case .missingSnapshot(let requiredPath):
                return "RepositoryAudit snapshot is missing required input: \(requiredPath)"
            case .missingResource(let relativePath):
                return "RepositoryAudit resource not found: \(relativePath)"
            case .invalidEncoding(let relativePath):
                return "RepositoryAudit resource is not valid UTF-8: \(relativePath)"
            }
        }
    }
}
