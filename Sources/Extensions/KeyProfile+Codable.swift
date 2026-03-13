import Foundation

/// Codable conformance for the UniFFI-generated KeyProfile enum.
/// This extension must not be added to the generated pgp_mobile.swift
/// since that file is overwritten by uniffi-bindgen.
extension KeyProfile: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        switch rawValue {
        case "universal": self = .universal
        case "advanced": self = .advanced
        default:
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unknown KeyProfile value: \(rawValue)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .universal: try container.encode("universal")
        case .advanced: try container.encode("advanced")
        }
    }
}
