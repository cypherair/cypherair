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
}

struct ContactsPostAuthGateResult: Equatable, Sendable {
    let postUnlockOutcome: ProtectedDataPostUnlockOutcome
    let frameworkState: ProtectedDataFrameworkState
    let availability: ContactsAvailability
    let allowsLegacyCompatibilityLoad: Bool
    let allowsProtectedDomainOpen: Bool
    let clearsRuntime: Bool

    init(
        postUnlockOutcome: ProtectedDataPostUnlockOutcome,
        frameworkState: ProtectedDataFrameworkState
    ) {
        self.postUnlockOutcome = postUnlockOutcome
        self.frameworkState = frameworkState
        clearsRuntime = true

        if frameworkState == .restartRequired {
            availability = .restartRequired
            allowsLegacyCompatibilityLoad = false
            allowsProtectedDomainOpen = false
            return
        }

        if frameworkState == .frameworkRecoveryNeeded {
            availability = .frameworkUnavailable
            allowsLegacyCompatibilityLoad = false
            allowsProtectedDomainOpen = false
            return
        }

        switch (postUnlockOutcome, frameworkState) {
        case (.opened(_), .sessionAuthorized),
             (.noRegisteredDomainPresent, .sessionAuthorized),
             (.noRegisteredOpeners, .sessionAuthorized):
            availability = .opening
            allowsLegacyCompatibilityLoad = true
            allowsProtectedDomainOpen = true

        case (.pendingMutationRecoveryRequired, _),
             (.frameworkRecoveryNeeded, _),
             (.domainOpenFailed(_), _):
            availability = .frameworkUnavailable
            allowsLegacyCompatibilityLoad = false
            allowsProtectedDomainOpen = false

        case (_, .restartRequired):
            availability = .restartRequired
            allowsLegacyCompatibilityLoad = false
            allowsProtectedDomainOpen = false

        case (_, .frameworkRecoveryNeeded):
            availability = .frameworkUnavailable
            allowsLegacyCompatibilityLoad = false
            allowsProtectedDomainOpen = false

        case (.noProtectedDomainPresent, _),
             (.noAuthenticatedContext, _),
             (.authorizationDenied, _),
             (_, .sessionLocked):
            availability = .locked
            allowsLegacyCompatibilityLoad = false
            allowsProtectedDomainOpen = false

        case (_, .sessionAuthorized):
            availability = .locked
            allowsLegacyCompatibilityLoad = false
            allowsProtectedDomainOpen = false
        }
    }
}
