import Foundation

enum OpenPGPCertificationKind: String, CaseIterable, Codable, Equatable, Hashable, Sendable {
    case generic
    case persona
    case casual
    case positive
}
