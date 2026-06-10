import Foundation

enum IdentityDisplayPresentation {
    static func displayName(from userId: String?) -> String {
        IdentityPresentation.parsedDisplayName(from: userId)
            ?? String(localized: "contact.unknown", defaultValue: "Unknown")
    }

    static func displayName(_ displayName: String) -> String {
        guard !displayName.isEmpty else {
            return String(localized: "contact.unknown", defaultValue: "Unknown")
        }
        return displayName
    }
}
