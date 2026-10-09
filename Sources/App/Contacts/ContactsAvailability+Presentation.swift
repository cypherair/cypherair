import Foundation

extension ContactsAvailability {
    var unavailableTitle: String {
        switch self {
        case .available:
            String(localized: "contacts.availability.available.title", defaultValue: "Contacts Available")
        case .opening:
            String(localized: "contacts.availability.opening.title", defaultValue: "Opening Contacts")
        case .locked:
            String(localized: "contacts.availability.locked.title", defaultValue: "Contacts Locked")
        case .damaged:
            String(localized: "contacts.availability.damaged.title", defaultValue: "Contacts Damaged")
        }
    }

    var unavailableDescription: String {
        switch self {
        case .available:
            String(localized: "contacts.availability.available.description", defaultValue: "Contacts are ready.")
        case .opening:
            String(localized: "contacts.availability.opening.description", defaultValue: "Contacts are opening after unlock.")
        case .locked:
            String(localized: "contacts.availability.locked.description", defaultValue: "Unlock CypherAir X to use contacts.")
        case .damaged:
            String(localized: "contacts.availability.damaged.description", defaultValue: "The contacts data on this device could not be opened. Reset All Local Data is the only remedy.")
        }
    }
}
