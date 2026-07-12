import Foundation

struct ContactsPostAuthGateDecision: Equatable, Sendable {
    let availability: ContactsAvailability
    let allowsProtectedDomainOpen: Bool

    init(
        postUnlockOutcome: ProtectedDataPostUnlockOutcome,
        frameworkState: ProtectedDataFrameworkState
    ) {
        if frameworkState == .restartRequired {
            availability = .restartRequired
            allowsProtectedDomainOpen = false
            return
        }

        if frameworkState == .frameworkRecoveryNeeded {
            availability = .frameworkUnavailable
            allowsProtectedDomainOpen = false
            return
        }

        switch (postUnlockOutcome, frameworkState) {
        case (.opened(_), .sessionAuthorized),
             (.noRegisteredDomainPresent, .sessionAuthorized),
             (.noRegisteredOpeners, .sessionAuthorized):
            availability = .opening
            allowsProtectedDomainOpen = true

        case (.pendingMutationRecoveryRequired, _),
             (.frameworkRecoveryNeeded, _),
             (.domainOpenFailed(_), _):
            availability = .frameworkUnavailable
            allowsProtectedDomainOpen = false

        case (_, .restartRequired):
            availability = .restartRequired
            allowsProtectedDomainOpen = false

        case (_, .frameworkRecoveryNeeded):
            availability = .frameworkUnavailable
            allowsProtectedDomainOpen = false

        case (.noProtectedDomainPresent, _),
             (.noAuthenticatedContext, _),
             (.authorizationDenied, _),
             (_, .sessionLocked):
            availability = .locked
            allowsProtectedDomainOpen = false

        case (_, .sessionAuthorized):
            availability = .locked
            allowsProtectedDomainOpen = false
        }
    }
}
