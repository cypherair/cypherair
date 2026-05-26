import Foundation

/// App-owned OpenPGP configuration vocabulary, independent from private-key custody.
struct PGPKeyConfiguration: Codable, Equatable, Hashable, Sendable {
    enum Identity: String, CaseIterable, Codable, Hashable, Sendable {
        case compatibleSoftwareV4
        case modernSoftwareV6
        case compatibleP256V4
        case modernP256V6
    }

    enum AlgorithmSuite: String, CaseIterable, Codable, Hashable, Sendable {
        case ed25519X25519
        case ed448X448
        case p256
    }

    enum CompatibilityTarget: String, CaseIterable, Codable, Hashable, Sendable {
        case gnupgOriented
        case rfc9580Oriented
    }

    enum MessageFormatPreference: String, CaseIterable, Codable, Hashable, Sendable {
        case seipdV1
        case seipdV2Aead
    }

    enum SoftwareExportProtection: String, CaseIterable, Codable, Hashable, Sendable {
        case iteratedSaltedS2K
        case argon2idS2K
        case notAvailable
    }

    let identity: Identity
    let keyVersion: UInt8
    let algorithmSuite: AlgorithmSuite
    let compatibilityTarget: CompatibilityTarget
    let messageFormatPreference: MessageFormatPreference
    let softwareExportProtection: SoftwareExportProtection

    static let compatibleSoftwareV4 = PGPKeyConfiguration(
        identity: .compatibleSoftwareV4,
        keyVersion: 4,
        algorithmSuite: .ed25519X25519,
        compatibilityTarget: .gnupgOriented,
        messageFormatPreference: .seipdV1,
        softwareExportProtection: .iteratedSaltedS2K
    )

    static let modernSoftwareV6 = PGPKeyConfiguration(
        identity: .modernSoftwareV6,
        keyVersion: 6,
        algorithmSuite: .ed448X448,
        compatibilityTarget: .rfc9580Oriented,
        messageFormatPreference: .seipdV2Aead,
        softwareExportProtection: .argon2idS2K
    )

    static let compatibleP256V4 = PGPKeyConfiguration(
        identity: .compatibleP256V4,
        keyVersion: 4,
        algorithmSuite: .p256,
        compatibilityTarget: .gnupgOriented,
        messageFormatPreference: .seipdV1,
        softwareExportProtection: .notAvailable
    )

    static let modernP256V6 = PGPKeyConfiguration(
        identity: .modernP256V6,
        keyVersion: 6,
        algorithmSuite: .p256,
        compatibilityTarget: .rfc9580Oriented,
        messageFormatPreference: .seipdV2Aead,
        softwareExportProtection: .notAvailable
    )
}
