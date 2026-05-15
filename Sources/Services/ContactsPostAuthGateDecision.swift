import Foundation

struct ContactsPostAuthGateDecision: Equatable, Sendable {
    let availability: ContactsAvailability
    let allowsLegacyCompatibilityLoad: Bool
    let allowsProtectedDomainOpen: Bool
    let clearsRuntime: Bool

    init(
        postUnlockOutcome: ProtectedDataPostUnlockOutcome,
        frameworkState: ProtectedDataFrameworkState
    ) {
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
