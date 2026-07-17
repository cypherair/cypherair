import Foundation

/// The nine key families a locally owned identity can belong to, chosen at key
/// generation and immutable per key. The family is the app's single source of
/// truth for key version, custody, tier, and the software generation suite.
///
/// Naming rule, stated once: every token in a case name is an RFC 9580/9980
/// registered algorithm name; unmarked names are the current v6 forms, and a
/// trailing `V4` marks the v4-certificate interop family. The 25519 v4 family
/// needs no marker because RFC 9580 registered dedicated Legacy curve names
/// (`Ed25519Legacy`/`Curve25519Legacy`); the P-256 pair shares algorithm
/// ids 18/19 across certificate versions, so the key version is the
/// discriminator.
enum PGPKeyFamily: String, CaseIterable, Codable, Hashable, Sendable {
    case portableEd25519LegacyCurve25519Legacy
    case portableEd25519X25519
    case portableEd448X448
    case portableMlDsa65Ed25519MlKem768X25519
    case portableMlDsa87Ed448MlKem1024X448
    case deviceBoundEcdsaNistP256EcdhNistP256V4
    case deviceBoundEcdsaNistP256EcdhNistP256
    case deviceBoundMlDsa65Ed25519MlKem768X25519
    case deviceBoundMlDsa87Ed448MlKem1024X448

    /// Where a family's private key lives — the dispatch axis between the
    /// portable software paths and the Secure Enclave custody paths.
    enum Custody: String, CaseIterable, Hashable, Sendable {
        case portable
        case deviceBound
    }

    /// Security tier within a custody column, ordered by ascending capability.
    /// Not every tier exists in every custody — Modern · High is portable-only
    /// because a pure Ed448/X448 key cannot live in the Secure Enclave,
    /// whereas Post-Quantum · High exists in both custodies (device-bound
    /// split custody keeps only the ML-DSA-87 / ML-KEM-1024 halves in the
    /// enclave and software-seals the Ed448/X448 classical halves).
    enum Tier: Int, CaseIterable, Hashable, Sendable {
        case legacy
        case modern
        case modernHigh
        case postQuantum
        case postQuantumHigh
    }

    /// OpenPGP key version of this family's certificates.
    var keyVersion: UInt8 {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy,
             .deviceBoundEcdsaNistP256EcdhNistP256V4:
            4
        case .portableEd25519X25519,
             .portableEd448X448,
             .portableMlDsa65Ed25519MlKem768X25519,
             .portableMlDsa87Ed448MlKem1024X448,
             .deviceBoundEcdsaNistP256EcdhNistP256,
             .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            6
        }
    }

    /// Private-key custody model of this family.
    var custody: Custody {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy,
             .portableEd25519X25519,
             .portableEd448X448,
             .portableMlDsa65Ed25519MlKem768X25519,
             .portableMlDsa87Ed448MlKem1024X448:
            .portable
        case .deviceBoundEcdsaNistP256EcdhNistP256V4,
             .deviceBoundEcdsaNistP256EcdhNistP256,
             .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            .deviceBound
        }
    }

    /// Security tier of this family.
    var tier: Tier {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy,
             .deviceBoundEcdsaNistP256EcdhNistP256V4:
            .legacy
        case .portableEd25519X25519,
             .deviceBoundEcdsaNistP256EcdhNistP256:
            .modern
        case .portableEd448X448:
            .modernHigh
        case .portableMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa65Ed25519MlKem768X25519:
            .postQuantum
        case .portableMlDsa87Ed448MlKem1024X448,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            .postQuantumHigh
        }
    }

    /// The software suite this portable family generates with, or nil for the
    /// device-bound families, whose certificates are built through the Secure
    /// Enclave custody paths instead.
    var softwareGenerationSuite: PGPKeySuite? {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy:
            .ed25519LegacyCurve25519Legacy
        case .portableEd25519X25519:
            .ed25519X25519
        case .portableEd448X448:
            .ed448X448
        case .portableMlDsa65Ed25519MlKem768X25519:
            .mlDsa65Ed25519MlKem768X25519
        case .portableMlDsa87Ed448MlKem1024X448:
            .mlDsa87Ed448MlKem1024X448
        case .deviceBoundEcdsaNistP256EcdhNistP256V4,
             .deviceBoundEcdsaNistP256EcdhNistP256,
             .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            nil
        }
    }
}

extension PGPKeySuite {
    /// The portable family generated from this software suite — the inverse of
    /// `PGPKeyFamily.softwareGenerationSuite`, used when an imported or
    /// generated software certificate is admitted into the catalog.
    var portableFamily: PGPKeyFamily {
        switch self {
        case .ed25519LegacyCurve25519Legacy:
            .portableEd25519LegacyCurve25519Legacy
        case .ed25519X25519:
            .portableEd25519X25519
        case .ed448X448:
            .portableEd448X448
        case .mlDsa65Ed25519MlKem768X25519:
            .portableMlDsa65Ed25519MlKem768X25519
        case .mlDsa87Ed448MlKem1024X448:
            .portableMlDsa87Ed448MlKem1024X448
        }
    }
}
