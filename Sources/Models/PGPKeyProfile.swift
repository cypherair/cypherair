import Foundation

/// App-owned encryption profile vocabulary.
///
/// Raw values intentionally match the historical generated `KeyProfile`
/// Codable representation so persisted key metadata and Contacts payloads
/// remain schema-compatible.
enum PGPKeyProfile: String, CaseIterable, Codable, Hashable, Sendable {
    case universal
    case advanced

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

    /// Key version produced by this profile.
    var keyVersion: UInt8 {
        switch self {
        case .universal: 4
        case .advanced: 6
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
