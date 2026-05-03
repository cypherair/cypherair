import Foundation

struct RecipientList: Codable, Equatable, Identifiable, Sendable {
    var id: String { recipientListId }

    let recipientListId: String
    var name: String
    var memberContactIds: [String]
    var createdAt: Date
    var updatedAt: Date
}
