import Foundation

enum ContactsDomainValidationError: Error, Equatable, Sendable {
    case invalidPayload(reason: String)

    var reason: String {
        switch self {
        case .invalidPayload(let reason):
            reason
        }
    }
}
