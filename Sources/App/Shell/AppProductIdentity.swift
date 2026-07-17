import Foundation

enum AppProductIdentity {
    /// Canonical first-party repository, shown and copied on the About page.
    static let repositoryURLString = "https://github.com/cypherair/cypherair"

    private static let displayNameFallback = "CypherAir X"
    private static let copyrightFallback = "© 2026 CypherAir"

    static var localizedDisplayName: String {
        bundleString(forKey: "CFBundleDisplayName") ?? displayNameFallback
    }

    static var localizedCopyright: String {
        bundleString(forKey: "NSHumanReadableCopyright") ?? copyrightFallback
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
