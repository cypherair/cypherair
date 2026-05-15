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

extension ContactsAvailability {
    var isAvailable: Bool {
        switch self {
        case .availableLegacyCompatibility, .availableProtectedDomain:
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

    var requiresUnlock: Bool {
        switch self {
        case .locked:
            true
        case .availableLegacyCompatibility, .availableProtectedDomain,
             .opening, .recoveryNeeded, .frameworkUnavailable, .restartRequired:
            false
        }
    }

    var blocksMutations: Bool {
        !isAvailable
    }
}
