import Foundation

extension ContactsAvailability {
    var unavailableTitle: String {
        switch self {
        case .availableLegacyCompatibility, .availableProtectedDomain:
            String(localized: "contacts.availability.available.title", defaultValue: "Contacts Available")
        case .opening:
            String(localized: "contacts.availability.opening.title", defaultValue: "Opening Contacts")
        case .locked:
            String(localized: "contacts.availability.locked.title", defaultValue: "Contacts Locked")
        case .recoveryNeeded:
            String(localized: "contacts.availability.recovery.title", defaultValue: "Contacts Need Recovery")
        case .frameworkUnavailable:
            String(localized: "contacts.availability.framework.title", defaultValue: "Protected Data Unavailable")
        case .restartRequired:
            String(localized: "contacts.availability.restart.title", defaultValue: "Restart Required")
        }
    }

    var unavailableDescription: String {
        switch self {
        case .availableLegacyCompatibility, .availableProtectedDomain:
            String(localized: "contacts.availability.available.description", defaultValue: "Contacts are ready.")
        case .opening:
            String(localized: "contacts.availability.opening.description", defaultValue: "Contacts are opening after app authentication.")
        case .locked:
            String(localized: "contacts.availability.locked.description", defaultValue: "Unlock CypherAir to use contacts.")
        case .recoveryNeeded:
            String(localized: "contacts.availability.recovery.description", defaultValue: "Contacts could not be loaded safely. Recovery is required before contact data can be used.")
        case .frameworkUnavailable:
            String(localized: "contacts.availability.framework.description", defaultValue: "Protected app data is unavailable. Contacts remain locked.")
        case .restartRequired:
            String(localized: "contacts.availability.restart.description", defaultValue: "Restart CypherAir before using protected contact data.")
        }
    }

    var unavailableSystemImage: String {
        switch self {
        case .opening:
            "lock.open"
        case .locked:
            "lock"
        case .recoveryNeeded:
            "exclamationmark.triangle"
        case .frameworkUnavailable:
            "externaldrive.badge.exclamationmark"
        case .restartRequired:
            "arrow.clockwise"
        case .availableLegacyCompatibility, .availableProtectedDomain:
            "person.2"
        }
    }
}
