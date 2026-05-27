import Foundation

enum SecureEnclaveCustodyHandleAvailability: Equatable, Sendable {
    case available
    case unavailable(PGPKeyOperationFailureCategory)
}
