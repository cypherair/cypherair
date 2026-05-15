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
