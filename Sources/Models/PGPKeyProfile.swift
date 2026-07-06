import Foundation

/// App-owned encryption profile vocabulary.
///
/// Raw values intentionally match the historical generated `KeyProfile`
/// Codable representation so persisted key metadata and Contacts payloads
/// remain schema-compatible.
enum PGPKeyProfile: String, CaseIterable, Codable, Hashable, Sendable {
    case universal
    case modern
    case advanced
    case postQuantum
    case postQuantumHigh

    /// Key version produced by this profile.
    var keyVersion: UInt8 {
        switch self {
        case .universal: 4
        case .modern, .advanced, .postQuantum, .postQuantumHigh: 6
        }
    }

    var openPGPConfiguration: PGPKeyConfiguration {
        switch self {
        case .universal:
            .compatibleSoftwareV4
        case .modern:
            .modernSoftwareV6
        case .advanced:
            // `advanced` is the Ed448/X448 tier, presented as "Modern · High".
            .modernHighSoftwareV6
        case .postQuantum:
            .postQuantumSoftwareV6
        case .postQuantumHigh:
            .postQuantumHighSoftwareV6
        }
    }
}
