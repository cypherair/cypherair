import Foundation

/// Filters transient resign/activate cycles caused by system biometric prompts
/// so privacy re-auth runs only for real app resume events.
///
/// The next activation can be suppressed either because an authentication
/// attempt has just started, or because the system reported resign/inactive
/// while the auth prompt was already in progress.
struct PrivacyScreenLifecycleGate {
    private var traceStore: AuthLifecycleTraceStore?
    private var suppressNextSettledActivation = false
    private var lastObservedOperationAuthenticationAttemptGeneration: UInt64 = 0

    init(traceStore: AuthLifecycleTraceStore? = nil) {
        self.traceStore = traceStore
    }

    mutating func attachTraceStore(_ traceStore: AuthLifecycleTraceStore?) {
        self.traceStore = traceStore
    }

    mutating func armForAuthenticationAttempt() {
        suppressNextSettledActivation = true
        traceStore?.record(
            category: .lifecycle,
            name: "gate.armForAuthenticationAttempt",
            metadata: ["suppressed": "true"]
        )
    }

    mutating func syncOperationAuthenticationAttemptGeneration(_ generation: UInt64) {
        guard generation > lastObservedOperationAuthenticationAttemptGeneration else {
            return
        }

        lastObservedOperationAuthenticationAttemptGeneration = generation
        traceStore?.record(
            category: .lifecycle,
            name: "gate.observeOperationAuthenticationAttempt",
            metadata: ["generation": String(generation)]
        )
        armForAuthenticationAttempt()
    }

    mutating func shouldHandleInactive(
        isAuthenticating: Bool,
        isOperationPromptInProgress: Bool = false
    ) -> Bool {
        if isAuthenticating || isOperationPromptInProgress {
            armForAuthenticationAttempt()
            traceStore?.record(
                category: .lifecycle,
                name: "gate.inactive",
                metadata: [
                    "decision": "suppressed",
                    "isAuthenticating": isAuthenticating ? "true" : "false",
                    "appSessionAuthenticating": isAuthenticating ? "true" : "false",
                    "operationPrompt": isOperationPromptInProgress ? "true" : "false",
                    "suppressionArmed": suppressNextSettledActivation ? "true" : "false"
                ]
            )
            return false
        }

        let shouldHandle = !suppressNextSettledActivation
        traceStore?.record(
            category: .lifecycle,
            name: "gate.inactive",
            metadata: [
                "decision": shouldHandle ? "handled" : "suppressedForSettledActivation",
                "suppressed": suppressNextSettledActivation ? "true" : "false",
                "suppressionArmed": suppressNextSettledActivation ? "true" : "false",
                "isAuthenticating": isAuthenticating ? "true" : "false",
                "appSessionAuthenticating": isAuthenticating ? "true" : "false",
                "operationPrompt": isOperationPromptInProgress ? "true" : "false"
            ]
        )
        return shouldHandle
    }

    mutating func shouldHandleBackground() -> Bool {
        suppressNextSettledActivation = false
        traceStore?.record(
            category: .lifecycle,
            name: "gate.background",
            metadata: ["decision": "handled", "suppressed": "false"]
        )
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
            traceStore?.record(
                category: .lifecycle,
                name: "gate.active",
                metadata: [
                    "decision": "suppressed",
                    "isAuthenticating": isAuthenticating ? "true" : "false",
                    "appSessionAuthenticating": isAuthenticating ? "true" : "false",
                    "operationPrompt": isOperationPromptInProgress ? "true" : "false",
                    "suppressionArmed": suppressNextSettledActivation ? "true" : "false"
                ]
            )
            return false
        }

        if suppressNextSettledActivation {
            suppressNextSettledActivation = false
            traceStore?.record(
                category: .lifecycle,
                name: "gate.active",
                metadata: [
                    "decision": "consumeSuppression",
                    "suppressed": "false",
                    "suppressionArmed": "true",
                    "isAuthenticating": "false",
                    "appSessionAuthenticating": "false",
                    "operationPrompt": "false"
                ]
            )
            return false
        }

        traceStore?.record(
            category: .lifecycle,
            name: "gate.active",
            metadata: [
                "decision": "handled",
                "suppressed": "false",
                "suppressionArmed": "false",
                "isAuthenticating": "false",
                "appSessionAuthenticating": "false",
                "operationPrompt": "false"
            ]
        )
        return true
    }
}
