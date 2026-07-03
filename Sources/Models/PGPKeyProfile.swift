import Foundation

/// App-owned encryption profile vocabulary.
///
/// Raw values intentionally match the historical generated `KeyProfile`
/// Codable representation so persisted key metadata and Contacts payloads
/// remain schema-compatible.
enum PGPKeyProfile: String, CaseIterable, Codable, Hashable, Sendable {
    case universal
    case advanced
    case postQuantum

    /// Key version produced by this profile.
    var keyVersion: UInt8 {
        switch self {
        case .universal: 4
        case .advanced, .postQuantum: 6
        }
    }

    var openPGPConfiguration: PGPKeyConfiguration {
        switch self {
        case .universal:
            .compatibleSoftwareV4
        case .advanced:
            .modernSoftwareV6
        case .postQuantum:
            .postQuantumSoftwareV6
        }
    }
}
