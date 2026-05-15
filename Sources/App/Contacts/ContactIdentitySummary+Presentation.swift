import Foundation

extension ContactIdentitySummary {
    var keyCountDescription: String {
        String.localizedStringWithFormat(
            String(localized: "contacts.keyCount", defaultValue: "%d keys"),
            keys.count
        )
    }
}
