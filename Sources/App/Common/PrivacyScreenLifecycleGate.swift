import Foundation

/// Filters transient resign/activate cycles caused by system biometric prompts
/// so privacy re-auth runs only for real app resume events.
///
/// The next activation can be suppressed either because an authentication
/// attempt has just started, or because the system reported resign/inactive
/// while the auth prompt was already in progress.
struct PrivacyScreenLifecycleGate {
    private var suppressNextActivation = false

    mutating func armForAuthenticationAttempt() {
        suppressNextActivation = true
    }

    mutating func shouldHandleResignActive(
        isAuthenticating: Bool,
        isSystemAuthenticationPromptInProgress: Bool = false
    ) -> Bool {
        if isAuthenticating || isSystemAuthenticationPromptInProgress {
            armForAuthenticationAttempt()
            return false
        }

        return !suppressNextActivation
    }

    mutating func shouldHandleBecomeActive(
        isAuthenticating: Bool,
        isSystemAuthenticationPromptInProgress: Bool = false
    ) -> Bool {
        if suppressNextActivation {
            suppressNextActivation = false
            return false
        }

        return !(isAuthenticating || isSystemAuthenticationPromptInProgress)
    }
}
