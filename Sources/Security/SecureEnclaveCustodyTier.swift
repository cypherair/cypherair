import Foundation

/// The parameter-set tier of a device-bound Secure Enclave custody key set. It
/// selects which CryptoKit Secure Enclave key types back the two role handles,
/// their public-key byte shapes, and the keychain service namespace — so tiers
/// never collide.
enum SecureEnclaveCustodyTier: String, CaseIterable, Hashable, Sendable {
    /// P-256 ECDSA + ECDH (Device-Bound Legacy v4 and Device-Bound Modern v6).
    case classicalP256 = "p256"
    /// ML-DSA-65 + ML-KEM-768 components (Device-Bound Post-Quantum).
    case postQuantum = "post-quantum"
    /// ML-DSA-87 + ML-KEM-1024 components (Device-Bound Post-Quantum · High).
    case postQuantumHigh = "post-quantum-high"

    /// Public-key byte length for this tier's signing handle: an uncompressed
    /// X9.63 P-256 point, or the FIPS 204 ML-DSA verification key.
    var signingPublicKeyLength: Int {
        switch self {
        case .classicalP256: 65
        case .postQuantum: 1952
        case .postQuantumHigh: 2592
        }
    }

    /// Public-key byte length for this tier's key-agreement handle: an
    /// uncompressed X9.63 P-256 point, or the FIPS 203 ML-KEM encapsulation key.
    var keyAgreementPublicKeyLength: Int {
        switch self {
        case .classicalP256: 65
        case .postQuantum: 1184
        case .postQuantumHigh: 1568
        }
    }

    /// Raw byte lengths of the classical component secrets Rust generates and
    /// the classical-component store seals for the split-custody (post-quantum)
    /// tiers: Ed25519+X25519 for the base tier, Ed448+X448 for · High. Nil for
    /// `.classicalP256`, whose single P-256 key pair is entirely
    /// enclave-resident and has no sealed classical component.
    var splitCustodyClassicalSecretLengths: (signing: Int, keyAgreement: Int)? {
        switch self {
        case .classicalP256: nil
        case .postQuantum: (signing: 32, keyAgreement: 32)
        case .postQuantumHigh: (signing: 57, keyAgreement: 56)
        }
    }

    /// Keychain service namespace segment for this tier's handle rows.
    var serviceNamespaceSegment: String {
        rawValue
    }
}

extension PGPKeyConfiguration.Identity {
    /// The Secure Enclave custody tier this key family runs on, or nil for
    /// every software-custody family. This is the single dispatch key for
    /// routing, generation, recovery, and deletion of device-bound keys: an
    /// exhaustive switch, so adding a family forces the author to classify it
    /// (a missing arm fails to compile), and the software families deliberately
    /// map to nil so they never reach the Secure Enclave custody paths.
    var deviceBoundCustodyTier: SecureEnclaveCustodyTier? {
        switch self {
        case .compatibleP256V4, .modernP256V6:
            return .classicalP256
        case .deviceBoundPostQuantumV6:
            return .postQuantum
        case .deviceBoundPostQuantumHighV6:
            return .postQuantumHigh
        case .compatibleSoftwareV4, .modernSoftwareV6, .modernHighSoftwareV6,
             .postQuantumSoftwareV6, .postQuantumHighSoftwareV6:
            return nil
        }
    }
}
