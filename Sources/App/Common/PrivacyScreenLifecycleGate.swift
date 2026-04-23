import Foundation

/// Filters transient resign/activate cycles caused by system biometric prompts
/// so privacy re-auth runs only for real app resume events.
///
/// The next activation can be suppressed either because an authentication
/// attempt has just started, or because the system reported resign/inactive
/// while the auth prompt was already in progress.
struct PrivacyScreenLifecycleGate {
    private var suppressNextSettledActivation = false

    mutating func armForAuthenticationAttempt() {
        suppressNextSettledActivation = true
    }

    mutating func shouldHandleInactive(
        isAuthenticating: Bool,
        isOperationPromptInProgress: Bool = false
    ) -> Bool {
        if isAuthenticating || isOperationPromptInProgress {
            armForAuthenticationAttempt()
            return false
        }

        return !suppressNextSettledActivation
    }

    mutating func shouldHandleBackground() -> Bool {
        suppressNextSettledActivation = false
        return true
    }

    mutating func shouldHandleResignActive(
        isAuthenticating: Bool,
        isOperationPromptInProgress: Bool = false
    ) -> Bool {
        shouldHandleInactive(
            isAuthenticating: isAuthenticating,
            isOperationPromptInProgress: isOperationPromptInProgress
        )
    }

    mutating func shouldHandleBecomeActive(
        isAuthenticating: Bool,
        isOperationPromptInProgress: Bool = false
    ) -> Bool {
        if isAuthenticating || isOperationPromptInProgress {
            return false
        }

        if suppressNextSettledActivation {
            suppressNextSettledActivation = false
            return false
        }

        return true
    }
}
