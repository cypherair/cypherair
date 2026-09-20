import Foundation

enum ContactsAvailability: String, Codable, Equatable, Sendable {
    case available
    case opening
    case locked
    case damaged
}

extension ContactsAvailability {
    var isAvailable: Bool {
        self == .available
    }

    var allowsContactsVerification: Bool {
        isAvailable
    }

    var allowsProtectedCertificationPersistence: Bool {
        isAvailable
    }
}
