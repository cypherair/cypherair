import Foundation

extension PGPKeyProfile {
    /// User-facing display name for the profile.
    var displayName: String {
        switch self {
        case .universal:
            String(localized: "profile.universal.name", defaultValue: "Universal Compatible")
        case .advanced:
            String(localized: "profile.advanced.name", defaultValue: "Advanced Security")
        }
    }

    /// Short description for profile selection UI.
    var shortDescription: String {
        switch self {
        case .universal:
            String(
                localized: "profile.universal.description",
                defaultValue: "Works with all PGP tools including GnuPG."
            )
        case .advanced:
            String(
                localized: "profile.advanced.description",
                defaultValue: "Uses the latest encryption standard (RFC 9580) with stronger algorithms. Not compatible with GnuPG."
            )
        }
    }

    /// Security level description.
    var securityLevel: String {
        switch self {
        case .universal:
            String(localized: "profile.universal.securityLevel", defaultValue: "~128 bit")
        case .advanced:
            String(localized: "profile.advanced.securityLevel", defaultValue: "~224 bit")
        }
    }
}
