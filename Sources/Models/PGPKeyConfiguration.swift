import Foundation

/// App-owned OpenPGP configuration vocabulary, independent from private-key custody.
struct PGPKeyConfiguration: Codable, Equatable, Hashable, Sendable {
    enum Identity: String, CaseIterable, Codable, Hashable, Sendable {
        case compatibleSoftwareV4
        /// Portable Modern: v6 Ed25519+X25519 (RFC 9580). The baseline v6
        /// classical family — the plain "Modern" tier.
        case modernSoftwareV6
        /// Portable Modern · High: v6 Ed448+X448 (RFC 9580). Historically named
        /// `modernSoftwareV6`; re-keyed in issue #591 Phase 2 when the baseline
        /// Ed25519 Modern family took that name.
        case modernHighSoftwareV6
        case postQuantumSoftwareV6
        /// Portable Post-Quantum · High: v6 RFC 9980 composite ML-DSA-87+Ed448 /
        /// ML-KEM-1024+X448 (NIST level 5).
        case postQuantumHighSoftwareV6
        case compatibleP256V4
        case modernP256V6
        case deviceBoundPostQuantumV6
        /// Device-Bound Post-Quantum · High: v6 RFC 9980 composite
        /// ML-DSA-87+Ed448 / ML-KEM-1024+X448 under split custody. The ML-DSA/ML-KEM
        /// halves live in the Secure Enclave, the Ed448/X448 classical halves under
        /// the fixed-access envelope; the private key is never exportable.
        case deviceBoundPostQuantumHighV6

        var configuration: PGPKeyConfiguration {
            switch self {
            case .compatibleSoftwareV4:
                .compatibleSoftwareV4
            case .modernSoftwareV6:
                .modernSoftwareV6
            case .modernHighSoftwareV6:
                .modernHighSoftwareV6
            case .postQuantumSoftwareV6:
                .postQuantumSoftwareV6
            case .postQuantumHighSoftwareV6:
                .postQuantumHighSoftwareV6
            case .compatibleP256V4:
                .compatibleP256V4
            case .modernP256V6:
                .modernP256V6
            case .deviceBoundPostQuantumV6:
                .deviceBoundPostQuantumV6
            case .deviceBoundPostQuantumHighV6:
                .deviceBoundPostQuantumHighV6
            }
        }
    }

    enum AlgorithmSuite: String, CaseIterable, Codable, Hashable, Sendable {
        case ed25519X25519
        case ed448X448
        case mldsa65Ed25519Mlkem768X25519
        case mldsa87Ed448Mlkem1024X448
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

    /// Portable Modern: v6 Ed25519+X25519 (RFC 9580). Same Curve25519 family as
    /// the v4 Legacy configuration, but the dedicated v6 algorithm ids
    /// (Ed25519 / X25519) under the modern format.
    static let modernSoftwareV6 = PGPKeyConfiguration(
        identity: .modernSoftwareV6,
        keyVersion: 6,
        algorithmSuite: .ed25519X25519,
        compatibilityTarget: .rfc9580Oriented,
        messageFormatPreference: .seipdV2Aead,
        softwareExportProtection: .argon2idS2K
    )

    /// Portable Modern · High: v6 Ed448+X448 (RFC 9580).
    static let modernHighSoftwareV6 = PGPKeyConfiguration(
        identity: .modernHighSoftwareV6,
        keyVersion: 6,
        algorithmSuite: .ed448X448,
        compatibilityTarget: .rfc9580Oriented,
        messageFormatPreference: .seipdV2Aead,
        softwareExportProtection: .argon2idS2K
    )

    static let postQuantumSoftwareV6 = PGPKeyConfiguration(
        identity: .postQuantumSoftwareV6,
        keyVersion: 6,
        algorithmSuite: .mldsa65Ed25519Mlkem768X25519,
        compatibilityTarget: .rfc9580Oriented,
        messageFormatPreference: .seipdV2Aead,
        softwareExportProtection: .argon2idS2K
    )

    /// Portable Post-Quantum · High: the higher RFC 9980 composite tier
    /// (ML-DSA-87+Ed448 / ML-KEM-1024+X448, NIST level 5). Portable software
    /// key; the private key can be exported and backed up.
    static let postQuantumHighSoftwareV6 = PGPKeyConfiguration(
        identity: .postQuantumHighSoftwareV6,
        keyVersion: 6,
        algorithmSuite: .mldsa87Ed448Mlkem1024X448,
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

    /// Device-Bound Post-Quantum: the RFC 9980 composite suite under split
    /// custody. The ML-DSA/ML-KEM components live in the Secure Enclave, the
    /// classical components under the fixed-access envelope; the private key
    /// is never exportable (docs/POST_QUANTUM.md Section 3).
    static let deviceBoundPostQuantumV6 = PGPKeyConfiguration(
        identity: .deviceBoundPostQuantumV6,
        keyVersion: 6,
        algorithmSuite: .mldsa65Ed25519Mlkem768X25519,
        compatibilityTarget: .rfc9580Oriented,
        messageFormatPreference: .seipdV2Aead,
        softwareExportProtection: .notAvailable
    )

    /// Device-Bound Post-Quantum · High: the higher RFC 9980 composite tier
    /// (ML-DSA-87+Ed448 / ML-KEM-1024+X448, NIST level 5) under split custody.
    /// The ML-DSA/ML-KEM components live in the Secure Enclave, the classical
    /// components under the fixed-access envelope; the private key is never
    /// exportable (docs/POST_QUANTUM.md Section 3).
    static let deviceBoundPostQuantumHighV6 = PGPKeyConfiguration(
        identity: .deviceBoundPostQuantumHighV6,
        keyVersion: 6,
        algorithmSuite: .mldsa87Ed448Mlkem1024X448,
        compatibilityTarget: .rfc9580Oriented,
        messageFormatPreference: .seipdV2Aead,
        softwareExportProtection: .notAvailable
    )
}

extension PGPKeyConfiguration.Identity {
    /// The historical software profile this configuration identity maps onto,
    /// or nil for Secure Enclave custody configurations.
    var equivalentSoftwareProfile: PGPKeyProfile? {
        switch self {
        case .compatibleSoftwareV4:
            .universal
        case .modernSoftwareV6:
            .modern
        case .modernHighSoftwareV6:
            .advanced
        case .postQuantumSoftwareV6:
            .postQuantum
        case .postQuantumHighSoftwareV6:
            .postQuantumHigh
        case .compatibleP256V4, .modernP256V6, .deviceBoundPostQuantumV6,
             .deviceBoundPostQuantumHighV6:
            nil
        }
    }
}
