import Foundation

enum AppProductLine {
    case cypherAir
    case cypherAirX
}

enum AppProductIdentity {
    static let displayNameFallback = "CypherAir X"
    static let productLine: AppProductLine = .cypherAirX

    static var showsCypherAirXAboutCopy: Bool {
        productLine == .cypherAirX
    }

    static var displayName: String {
        String(localized: "app.name", defaultValue: "CypherAir X")
    }
}
