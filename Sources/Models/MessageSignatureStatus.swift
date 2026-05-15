import Foundation

enum MessageSignatureStatus: Equatable, Hashable, Sendable {
    case valid
    case unknownSigner
    case bad
    case notSigned
    case expired
}
