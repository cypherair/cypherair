import Foundation

enum AppProductIdentity {
    enum ProductLine {
        case cypherAir
        case cypherAirX
    }

    private static let displayNameFallback = "CypherAir X"
    private static let productLine: ProductLine = .cypherAirX

    static var localizedDisplayName: String {
        bundleString(forKey: "CFBundleDisplayName") ?? displayNameFallback
    }

    static var showsProductLineAboutContext: Bool {
        productLine == .cypherAirX
    }

    private static func bundleString(forKey key: String, in bundle: Bundle = .main) -> String? {
        stringValue(forKey: key, in: bundle.localizedInfoDictionary)
            ?? stringValue(forKey: key, in: bundle.infoDictionary)
    }

    private static func stringValue(forKey key: String, in dictionary: [String: Any]?) -> String? {
        guard let value = dictionary?[key] as? String,
              !value.isEmpty else {
            return nil
        }
        return value
    }
}
