import Foundation

enum ContactsAvailability: String, Codable, Equatable, Sendable {
    case availableProtectedDomain
    case opening
    case locked
    case recoveryNeeded
    case frameworkUnavailable
    case restartRequired
}

extension ContactsAvailability {
    var isAvailable: Bool {
        switch self {
        case .availableProtectedDomain:
            true
        case .opening, .locked, .recoveryNeeded, .frameworkUnavailable, .restartRequired:
            false
        }
    }

    var allowsContactsVerification: Bool {
        isAvailable
    }

    var allowsProtectedCertificationPersistence: Bool {
        self == .availableProtectedDomain
    }
}
