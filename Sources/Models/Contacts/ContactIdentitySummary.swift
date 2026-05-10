import Foundation

struct ContactIdentitySummary: Identifiable, Hashable, Sendable {
    var id: String { contactId }

    let contactId: String
    let displayName: String
    let primaryEmail: String?
    let tagIds: [String]
    let tags: [ContactTagSummary]
    let notes: String?
    let keys: [ContactKeySummary]

    var preferredKey: ContactKeySummary? {
        keys.first { $0.usageState == .preferred }
    }

    var additionalActiveKeys: [ContactKeySummary] {
        keys.filter { $0.usageState == .additionalActive }
    }

    var historicalKeys: [ContactKeySummary] {
        keys.filter { $0.usageState == .historical }
    }

    var canEncryptTo: Bool {
        preferredKey?.canEncryptTo == true
    }

    var hasUnverifiedKeys: Bool {
        keys.contains { !$0.isVerified }
    }

    var keyCountDescription: String {
        String.localizedStringWithFormat(
            String(localized: "contacts.keyCount", defaultValue: "%d keys"),
            keys.count
        )
    }
}
