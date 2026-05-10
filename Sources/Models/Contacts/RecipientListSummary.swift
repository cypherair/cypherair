import Foundation

struct RecipientListSummary: Identifiable, Hashable, Sendable {
    var id: String { recipientListId }

    let recipientListId: String
    let name: String
    let memberContactIds: [String]
    let memberCount: Int
    let canEncryptToAll: Bool
    let missingPreferredContactIds: [String]
}
