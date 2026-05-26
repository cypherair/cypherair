import Foundation

/// Coarse operation support vocabulary; detailed failure categories travel in `PGPKeyOperationResolution`.
enum PGPKeyOperationSupport: String, CaseIterable, Codable, Hashable, Sendable {
    case supported
    case unsupported
    case notImplemented
    case unavailable
}
