import Foundation

struct ContactIdentity: Codable, Equatable, Identifiable, Sendable {
    var id: String { contactId }

    let contactId: String
    var displayName: String
    var primaryEmail: String?
    var tagIds: [String]
    var notes: String?
    var createdAt: Date
    var updatedAt: Date
}
