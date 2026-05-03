import Foundation

enum ContactsAvailability: String, Codable, Equatable, Sendable {
    case availableLegacyCompatibility
    case availableProtectedDomain
    case opening
    case locked
    case recoveryNeeded
    case frameworkUnavailable
    case restartRequired
}
