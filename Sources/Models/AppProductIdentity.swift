import Foundation

enum AppProductIdentity {
    static let displayNameFallback = "CypherAir X"

    static var displayName: String {
        String(localized: "app.name", defaultValue: "CypherAir X")
    }
}
