import Foundation

struct ContactRecipientSummary: Identifiable, Hashable, Sendable {
    var id: String { contactId }

    let contactId: String
    let displayName: String
    let primaryEmail: String?
    let tagIds: [String]
    let preferredKey: ContactKeySummary

    var isPreferredKeyVerified: Bool {
        preferredKey.isVerified
    }
}
