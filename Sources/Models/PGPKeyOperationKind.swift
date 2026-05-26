import Foundation

/// App-owned private-operation and material-operation vocabulary.
enum PGPKeyOperationKind: String, CaseIterable, Codable, Hashable, Sendable {
    case generate
    case sign
    case decrypt
    case certify
    case revoke
    case modifyExpiry
    case refreshBinding
    case exportPublicMaterial
    case exportPrivateMaterial
    case exportRevocationArtifact
}
