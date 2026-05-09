import Foundation

struct ContactTag: Codable, Equatable, Identifiable, Sendable {
    var id: String { tagId }

    let tagId: String
    var displayName: String
    var normalizedName: String
    var createdAt: Date
    var updatedAt: Date

    static func displayName(for rawName: String) -> String {
        rawName
            .split(whereSeparator: { $0.isWhitespace })
            .joined(separator: " ")
    }

    static func normalizedName(for displayName: String) -> String {
        Self.displayName(for: displayName)
            .lowercased()
    }
}
