import Foundation

/// Coarse operation support vocabulary; detailed failure categories are defined later.
enum PGPKeyOperationSupport: String, CaseIterable, Codable, Hashable, Sendable {
    case supported
    case unsupported
    case notImplemented
    case unavailable
}
