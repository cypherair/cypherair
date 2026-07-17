import Foundation

/// App-owned software key-generation suite vocabulary, named by RFC 9580/9980
/// registered algorithms and ordered by ascending security tier. Cases map
/// 1:1 onto the generated FFI `KeySuite`; raw values persist in the contacts
/// database key records.
enum PGPKeySuite: String, CaseIterable, Codable, Hashable, Sendable {
    case ed25519LegacyCurve25519Legacy
    case ed25519X25519
    case ed448X448
    case mlDsa65Ed25519MlKem768X25519
    case mlDsa87Ed448MlKem1024X448

    /// Key version produced by this suite.
    var keyVersion: UInt8 {
        switch self {
        case .ed25519LegacyCurve25519Legacy:
            4
        case .ed25519X25519, .ed448X448, .mlDsa65Ed25519MlKem768X25519,
             .mlDsa87Ed448MlKem1024X448:
            6
        }
    }
}
