import Foundation

struct ContactTag: Codable, Equatable, Identifiable, Sendable {
    var id: String { tagId }

    let tagId: String
    var displayName: String
    var normalizedName: String
    var createdAt: Date
    var updatedAt: Date

    static func normalizedName(for displayName: String) -> String {
        displayName
            .split(whereSeparator: { $0.isWhitespace })
            .joined(separator: " ")
            .lowercased()
    }
}
