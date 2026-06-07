import Foundation

struct LoadWarningPresentationState: Equatable {
    let isAppLocked: Bool
    let isAuthenticating: Bool
    let isLockCoverVisible: Bool
    let hasAuthenticatedSession: Bool
    let allowsPreAuthenticationPresentation: Bool
}

enum LoadWarningPresentationGate {
    static func canPresent(_ state: LoadWarningPresentationState) -> Bool {
        guard !state.isAppLocked,
              !state.isAuthenticating,
              !state.isLockCoverVisible else {
            return false
        }
        return state.hasAuthenticatedSession || state.allowsPreAuthenticationPresentation
    }
}

@Observable
final class AppLoadWarningCoordinator {
    private(set) var presentedWarning: String?
    private var pendingWarning: String?

    init(initialWarning: String? = nil) {
        self.pendingWarning = initialWarning
    }

    func enqueue(_ warning: String?) {
        guard let warning else { return }
        pendingWarning = warning
    }

    func dismissPresentedWarning() {
        presentedWarning = nil
    }

    func presentPendingIfPossible(
        source: String,
        presentationState: LoadWarningPresentationState,
        isRestartRequiredAfterLocalDataReset: Bool,
        traceStore: AuthLifecycleTraceStore?
    ) {
        guard !isRestartRequiredAfterLocalDataReset else { return }
        guard presentedWarning == nil, let pendingWarning else { return }
        guard LoadWarningPresentationGate.canPresent(presentationState) else {
            traceStore?.record(
                category: .lifecycle,
                name: "loadWarning.pending",
                metadata: [
                    "source": source,
                    "appLocked": presentationState.isAppLocked ? "true" : "false",
                    "isAuthenticating": presentationState.isAuthenticating ? "true" : "false",
                    "lockCoverVisible": presentationState.isLockCoverVisible ? "true" : "false",
                    "hasAuthenticatedSession": presentationState.hasAuthenticatedSession ? "true" : "false",
                    "allowsPreAuthenticationPresentation": presentationState.allowsPreAuthenticationPresentation ? "true" : "false"
                ]
            )
            return
        }

        self.pendingWarning = nil
        presentedWarning = pendingWarning
    }
}
