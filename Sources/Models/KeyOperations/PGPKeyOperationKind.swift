import Foundation

/// App-owned key-operation vocabulary: key generation plus the private-key
/// operation classes custody routing dispatches on.
enum PGPKeyOperationKind: String, CaseIterable, Codable, Hashable, Sendable {
    case generate
    case sign
    case decrypt
    case certify
    case revoke
    case modifyExpiry
}
