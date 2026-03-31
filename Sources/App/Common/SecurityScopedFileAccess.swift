import Foundation

/// Abstracts `startAccessingSecurityScopedResource()` for easier testing.
protocol SecurityScopedResource {
    func startAccessingSecurityScopedResource() -> Bool
    func stopAccessingSecurityScopedResource()
}

extension URL: SecurityScopedResource {}

struct SecurityScopedAccessRequest<Resource: SecurityScopedResource> {
    let resource: Resource
    let failure: CypherAirError

    init(resource: Resource, failure: CypherAirError) {
        self.resource = resource
        self.failure = failure
    }
}

/// Executes work while holding one or more security-scoped resources.
enum SecurityScopedFileAccess {
    static func withAccess<Resource: SecurityScopedResource, T>(
        to requests: [SecurityScopedAccessRequest<Resource>],
        operation: () async throws -> T
    ) async throws -> T {
        var startedResources: [Resource] = []

        for request in requests {
            guard request.resource.startAccessingSecurityScopedResource() else {
                startedResources.reversed().forEach { $0.stopAccessingSecurityScopedResource() }
                throw request.failure
            }
            startedResources.append(request.resource)
        }

        defer {
            startedResources.reversed().forEach { $0.stopAccessingSecurityScopedResource() }
        }

        return try await operation()
    }
}

/// Tracks an imported text file whose original bytes should remain authoritative
/// until the user edits the visible text.
struct ImportedTextInputState {
    private(set) var rawData: Data?
    private(set) var fileName: String?
    private(set) var textSnapshot: String?

    var hasImportedFile: Bool {
        rawData != nil && fileName != nil
    }

    mutating func setImportedFile(data: Data, fileName: String, text: String) {
        rawData = data
        self.fileName = fileName
        textSnapshot = text
    }

    @discardableResult
    mutating func invalidateIfEditedTextDiffers(_ text: String) -> Bool {
        guard let textSnapshot, rawData != nil else {
            return false
        }

        guard text != textSnapshot else {
            return false
        }

        clear()
        return true
    }

    mutating func clear() {
        rawData = nil
        fileName = nil
        textSnapshot = nil
    }
}

enum ArmoredTextMessageClassification: Equatable {
    case encryptedTextMessage
    case other
}

enum ArmoredTextMessageClassifier {
    static let maxInspectableFileSize = 256 * 1024

    static func classify(fileSize: Int, data: Data) -> ArmoredTextMessageClassification {
        guard fileSize <= maxInspectableFileSize else {
            return .other
        }

        guard let text = String(data: data, encoding: .utf8) else {
            return .other
        }

        return normalizedLeadingText(text).hasPrefix("-----BEGIN PGP MESSAGE-----")
            ? .encryptedTextMessage
            : .other
    }

    private static func normalizedLeadingText(_ text: String) -> String {
        var normalized = text
        if normalized.hasPrefix("\u{FEFF}") {
            normalized.removeFirst()
        }
        return String(normalized.drop(while: { $0.isWhitespace }))
    }
}
