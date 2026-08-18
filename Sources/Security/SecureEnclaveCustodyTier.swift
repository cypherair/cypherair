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

    /// Raw public-key byte lengths for the split-custody (post-quantum) tiers'
    /// handles: the FIPS 204 ML-DSA verification key and the FIPS 203 ML-KEM
    /// encapsulation key. Nil for `.classicalP256`, whose handles are validated
    /// structurally as uncompressed X9.63 points rather than by length.
    var postQuantumPublicKeyLengths: (signing: Int, keyAgreement: Int)? {
        switch self {
        case .classicalP256: nil
        case .postQuantum: (signing: 1952, keyAgreement: 1184)
        case .postQuantumHigh: (signing: 2592, keyAgreement: 1568)
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

extension PGPKeyFamily {
    /// The Secure Enclave custody tier this key family runs on, or nil for
    /// every portable family. This is the single dispatch key for routing,
    /// generation, recovery, and deletion of device-bound keys, and it follows
    /// from custody and tier rather than being tabulated per family: the tier
    /// switch is exhaustive, so a new tier fails to compile until classified,
    /// and a new family classifies itself through the tier it declares.
    var deviceBoundCustodyTier: SecureEnclaveCustodyTier? {
        guard custody == .deviceBound else {
            return nil
        }
        switch tier {
        case .legacy, .modern:
            return .classicalP256
        case .postQuantum:
            return .postQuantum
        case .postQuantumHigh:
            return .postQuantumHigh
        case .modernHigh:
            // No Secure Enclave parameter set exists for Ed448 (CryptoKit's
            // enclave implements no classical curve but P-256), so no
            // device-bound Modern · High family can exist; every Secure
            // Enclave entry point fails closed on nil.
            return nil
        }
    }
}
