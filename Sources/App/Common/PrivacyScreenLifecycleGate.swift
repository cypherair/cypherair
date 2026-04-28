import Foundation

enum PrivacyScreenLifecycleDecision: String, Equatable {
    case handle = "handled"
    case blurOnly
    case settleTransientBlur
    case suppress = "suppressed"
}

private enum PrivacyScreenLifecycleSuppressionScope: String {
    case appSessionCompletion
    case promptLifecycle
}

/// Filters transient resign/activate cycles caused by system biometric prompts
/// so privacy re-auth runs only for real app resume events.
///
/// The next activation can be suppressed either because an authentication
/// attempt has just started, or because the system reported resign/inactive
/// while the auth prompt was already in progress.
struct PrivacyScreenLifecycleGate {
    private var traceStore: AuthLifecycleTraceStore?
    private var suppressionScope: PrivacyScreenLifecycleSuppressionScope?
    private var lastObservedOperationAuthenticationAttemptGeneration: UInt64 = 0

    init(traceStore: AuthLifecycleTraceStore? = nil) {
        self.traceStore = traceStore
    }

    mutating func attachTraceStore(_ traceStore: AuthLifecycleTraceStore?) {
        self.traceStore = traceStore
    }

    mutating func armForAuthenticationAttempt() {
        armSuppression(scope: .appSessionCompletion)
    }

    private mutating func armPromptLifecycleSuppression() {
        armSuppression(scope: .promptLifecycle)
    }

    private mutating func armSuppression(scope: PrivacyScreenLifecycleSuppressionScope) {
        suppressionScope = scope
        traceStore?.record(
            category: .lifecycle,
            name: "gate.armForAuthenticationAttempt",
            metadata: [
                "suppressed": "true",
                "suppressionScope": scope.rawValue
            ]
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
        armPromptLifecycleSuppression()
    }

    mutating func shouldHandleInactive(
        isAuthenticating: Bool,
        isOperationPromptInProgress: Bool = false
    ) -> PrivacyScreenLifecycleDecision {
        if isAuthenticating || isOperationPromptInProgress {
            armPromptLifecycleSuppression()
            traceLifecycleDecision(
                name: "gate.inactive",
                decision: .suppress,
                isAuthenticating: isAuthenticating,
                isOperationPromptInProgress: isOperationPromptInProgress
            )
            return .suppress
        }

        let decision: PrivacyScreenLifecycleDecision
        switch suppressionScope {
        case .appSessionCompletion:
            decision = .blurOnly
        case .promptLifecycle:
            decision = .suppress
        case nil:
            decision = .handle
        }
        traceLifecycleDecision(
            name: "gate.inactive",
            decision: decision,
            isAuthenticating: isAuthenticating,
            isOperationPromptInProgress: isOperationPromptInProgress
        )
        return decision
    }

    mutating func shouldHandleBackground() -> Bool {
        suppressionScope = nil
        traceStore?.record(
            category: .lifecycle,
            name: "gate.background",
            metadata: [
                "decision": PrivacyScreenLifecycleDecision.handle.rawValue,
                "suppressed": "false",
                "suppressionArmed": "false",
                "suppressionScope": "none"
            ]
        )
        return true
    }

    mutating func shouldHandleResignActive(
        isAuthenticating: Bool,
        isOperationPromptInProgress: Bool = false
    ) -> PrivacyScreenLifecycleDecision {
        shouldHandleInactive(
            isAuthenticating: isAuthenticating,
            isOperationPromptInProgress: isOperationPromptInProgress
        )
    }

    mutating func shouldHandleBecomeActive(
        isAuthenticating: Bool,
        isOperationPromptInProgress: Bool = false
    ) -> PrivacyScreenLifecycleDecision {
        if isAuthenticating || isOperationPromptInProgress {
            traceLifecycleDecision(
                name: "gate.active",
                decision: .suppress,
                isAuthenticating: isAuthenticating,
                isOperationPromptInProgress: isOperationPromptInProgress
            )
            return .suppress
        }

        if let suppressionScope {
            self.suppressionScope = nil
            let decision: PrivacyScreenLifecycleDecision = switch suppressionScope {
            case .appSessionCompletion:
                .settleTransientBlur
            case .promptLifecycle:
                .suppress
            }
            traceLifecycleDecision(
                name: "gate.active",
                decision: decision,
                isAuthenticating: false,
                isOperationPromptInProgress: false,
                consumedSuppressionScope: suppressionScope
            )
            return decision
        }

        traceLifecycleDecision(
            name: "gate.active",
            decision: .handle,
            isAuthenticating: false,
            isOperationPromptInProgress: false
        )
        return .handle
    }

    private func traceLifecycleDecision(
        name: String,
        decision: PrivacyScreenLifecycleDecision,
        isAuthenticating: Bool,
        isOperationPromptInProgress: Bool,
        consumedSuppressionScope: PrivacyScreenLifecycleSuppressionScope? = nil
    ) {
        let activeSuppressionScope = consumedSuppressionScope ?? suppressionScope
        traceStore?.record(
            category: .lifecycle,
            name: name,
            metadata: [
                "decision": decision.rawValue,
                "suppressed": decision == .handle || decision == .blurOnly || decision == .settleTransientBlur ? "false" : "true",
                "suppressionArmed": activeSuppressionScope == nil ? "false" : "true",
                "suppressionScope": activeSuppressionScope?.rawValue ?? "none",
                "isAuthenticating": isAuthenticating ? "true" : "false",
                "appSessionAuthenticating": isAuthenticating ? "true" : "false",
                "operationPrompt": isOperationPromptInProgress ? "true" : "false"
            ]
        )
    }
}
