import Foundation

enum PrivacyScreenLifecycleDecision: String, Equatable {
    case handle = "handled"
    case blurOnly
    case settleTransientBlur
    case suppress = "suppressed"
}

private enum PrivacyScreenLifecycleSuppressionScope: String {
    case appSessionCompletion
    case operationPromptActive
    case operationPromptSettle
}

/// Filters transient resign/activate cycles caused by system biometric prompts
/// so privacy re-auth runs only for real app resume events.
///
/// Operation-prompt lifecycle suppression is deliberately bounded: a completed
/// operation prompt can only influence lifecycle decisions during a short
/// settle window, and real background transitions always win.
struct PrivacyScreenLifecycleGate {
    private struct OperationPromptSettleState {
        let generation: UInt64
        let sessionGeneration: UInt64
        let expiresAt: Date
        var didApplyTransientBlur: Bool
    }

    private var traceStore: AuthLifecycleTraceStore?
    private var appSessionCompletionPending = false
    private var operationPromptSettle: OperationPromptSettleState?
    private var operationPromptSettleEligibleSessionGeneration: UInt64?
    private var lastObservedOperationAuthenticationAttemptGeneration: UInt64 = 0
    private var ignoredOperationGenerationThrough: UInt64 = 0
    private let operationPromptSettleWindow: TimeInterval
    private let now: () -> Date

    init(
        traceStore: AuthLifecycleTraceStore? = nil,
        operationPromptSettleWindow: TimeInterval = 1.0,
        now: @escaping () -> Date = Date.init
    ) {
        self.traceStore = traceStore
        self.operationPromptSettleWindow = operationPromptSettleWindow
        self.now = now
    }

    mutating func attachTraceStore(_ traceStore: AuthLifecycleTraceStore?) {
        self.traceStore = traceStore
    }

    mutating func armForAuthenticationAttempt() {
        armAppSessionCompletion()
    }

    private mutating func armAppSessionCompletion() {
        appSessionCompletionPending = true
        traceStore?.record(
            category: .lifecycle,
            name: "gate.armForAuthenticationAttempt",
            metadata: [
                "suppressed": "true",
                "suppressionScope": PrivacyScreenLifecycleSuppressionScope.appSessionCompletion.rawValue
            ]
        )
    }

    @discardableResult
    private mutating func refreshOperationPromptState(
        _ snapshot: AuthenticationPromptCoordinator.OperationAuthenticationPromptSnapshot
    ) -> Bool {
        guard snapshot.generation > 0, snapshot.sessionGeneration > 0 else {
            operationPromptSettle = nil
            operationPromptSettleEligibleSessionGeneration = nil
            return false
        }

        recordObservedOperationPromptIfNeeded(snapshot)
        clearOperationSettleIfSuperseded(by: snapshot)

        if snapshot.generation <= ignoredOperationGenerationThrough {
            clearOperationSettleIfCurrent(snapshot.generation)
            clearOperationSettleEligibilityIfCurrentSession(snapshot.sessionGeneration)
            return false
        }

        if snapshot.isInProgress {
            clearOperationSettleIfCurrent(snapshot.generation)
            return true
        }

        guard let lastEndedAt = snapshot.lastEndedAt else {
            clearOperationSettleIfCurrent(snapshot.generation)
            return false
        }

        guard operationPromptSettleEligibleSessionGeneration == snapshot.sessionGeneration else {
            clearOperationSettleIfCurrent(snapshot.generation)
            return false
        }

        let expiresAt = lastEndedAt.addingTimeInterval(operationPromptSettleWindow)
        guard now() <= expiresAt else {
            clearOperationSettleIfCurrent(snapshot.generation)
            clearOperationSettleEligibilityIfCurrentSession(snapshot.sessionGeneration)
            ignoredOperationGenerationThrough = max(
                ignoredOperationGenerationThrough,
                snapshot.generation
            )
            traceStore?.record(
                category: .lifecycle,
                name: "gate.operationPromptSettle.expired",
                metadata: [
                    "generation": String(snapshot.generation),
                    "sessionGeneration": String(snapshot.sessionGeneration),
                    "ignoredThrough": String(ignoredOperationGenerationThrough)
                ]
            )
            return false
        }

        if operationPromptSettle?.generation != snapshot.generation
            || operationPromptSettle?.sessionGeneration != snapshot.sessionGeneration {
            operationPromptSettle = OperationPromptSettleState(
                generation: snapshot.generation,
                sessionGeneration: snapshot.sessionGeneration,
                expiresAt: expiresAt,
                didApplyTransientBlur: false
            )
            traceStore?.record(
                category: .lifecycle,
                name: "gate.operationPromptSettle.arm",
                metadata: [
                    "generation": String(snapshot.generation),
                    "sessionGeneration": String(snapshot.sessionGeneration),
                    "expiresInSeconds": String(format: "%.3f", expiresAt.timeIntervalSince(now()))
                ]
            )
        }
        return false
    }

    mutating func shouldHandleInactive(
        isAuthenticating: Bool,
        operationPrompt: AuthenticationPromptCoordinator.OperationAuthenticationPromptSnapshot = .idle
    ) -> PrivacyScreenLifecycleDecision {
        let operationPromptActive = refreshOperationPromptState(operationPrompt)

        if operationPromptActive {
            operationPromptSettleEligibleSessionGeneration = operationPrompt.sessionGeneration
        }

        if isAuthenticating {
            armAppSessionCompletion()
            traceLifecycleDecision(
                name: "gate.inactive",
                decision: .suppress,
                isAuthenticating: isAuthenticating,
                isOperationPromptInProgress: operationPrompt.isInProgress,
                suppressionScope: .appSessionCompletion
            )
            return .suppress
        }

        if operationPromptActive {
            traceLifecycleDecision(
                name: "gate.inactive",
                decision: .suppress,
                isAuthenticating: isAuthenticating,
                isOperationPromptInProgress: true,
                suppressionScope: .operationPromptActive
            )
            return .suppress
        }

        if var settle = operationPromptSettle {
            settle.didApplyTransientBlur = true
            operationPromptSettle = settle
            traceLifecycleDecision(
                name: "gate.inactive",
                decision: .blurOnly,
                isAuthenticating: isAuthenticating,
                isOperationPromptInProgress: false,
                suppressionScope: .operationPromptSettle
            )
            return .blurOnly
        }

        if appSessionCompletionPending {
            traceLifecycleDecision(
                name: "gate.inactive",
                decision: .blurOnly,
                isAuthenticating: isAuthenticating,
                isOperationPromptInProgress: false,
                suppressionScope: .appSessionCompletion
            )
            return .blurOnly
        }

        traceLifecycleDecision(
            name: "gate.inactive",
            decision: .handle,
            isAuthenticating: isAuthenticating,
            isOperationPromptInProgress: false
        )
        return .handle
    }

    mutating func shouldHandleBackground(
        operationPrompt: AuthenticationPromptCoordinator.OperationAuthenticationPromptSnapshot = .idle
    ) -> Bool {
        recordObservedOperationPromptIfNeeded(operationPrompt)
        if operationPrompt.generation > 0 {
            ignoredOperationGenerationThrough = max(
                ignoredOperationGenerationThrough,
                operationPrompt.generation
            )
        }
        operationPromptSettle = nil
        operationPromptSettleEligibleSessionGeneration = nil
        appSessionCompletionPending = false
        traceStore?.record(
            category: .lifecycle,
            name: "gate.background",
            metadata: [
                "decision": PrivacyScreenLifecycleDecision.handle.rawValue,
                "suppressed": "false",
                "suppressionArmed": "false",
                "suppressionScope": "none",
                "operationSessionGeneration": String(operationPrompt.sessionGeneration),
                "ignoredOperationGenerationThrough": String(ignoredOperationGenerationThrough)
            ]
        )
        return true
    }

    mutating func shouldHandleResignActive(
        isAuthenticating: Bool,
        operationPrompt: AuthenticationPromptCoordinator.OperationAuthenticationPromptSnapshot = .idle
    ) -> PrivacyScreenLifecycleDecision {
        shouldHandleInactive(
            isAuthenticating: isAuthenticating,
            operationPrompt: operationPrompt
        )
    }

    mutating func shouldHandleBecomeActive(
        isAuthenticating: Bool,
        operationPrompt: AuthenticationPromptCoordinator.OperationAuthenticationPromptSnapshot = .idle
    ) -> PrivacyScreenLifecycleDecision {
        let operationPromptActive = refreshOperationPromptState(operationPrompt)

        if isAuthenticating {
            traceLifecycleDecision(
                name: "gate.active",
                decision: .suppress,
                isAuthenticating: isAuthenticating,
                isOperationPromptInProgress: operationPrompt.isInProgress,
                suppressionScope: .appSessionCompletion
            )
            return .suppress
        }

        if operationPromptActive {
            traceLifecycleDecision(
                name: "gate.active",
                decision: .suppress,
                isAuthenticating: isAuthenticating,
                isOperationPromptInProgress: true,
                suppressionScope: .operationPromptActive
            )
            return .suppress
        }

        if let settle = operationPromptSettle {
            let decision: PrivacyScreenLifecycleDecision = settle.didApplyTransientBlur
                ? .settleTransientBlur
                : .suppress
            consumeOperationPromptSettle(settle)
            traceLifecycleDecision(
                name: "gate.active",
                decision: decision,
                isAuthenticating: false,
                isOperationPromptInProgress: false,
                suppressionScope: .operationPromptSettle
            )
            return decision
        }

        if appSessionCompletionPending {
            appSessionCompletionPending = false
            traceLifecycleDecision(
                name: "gate.active",
                decision: .settleTransientBlur,
                isAuthenticating: false,
                isOperationPromptInProgress: false,
                suppressionScope: .appSessionCompletion
            )
            return .settleTransientBlur
        }

        traceLifecycleDecision(
            name: "gate.active",
            decision: .handle,
            isAuthenticating: false,
            isOperationPromptInProgress: false
        )
        return .handle
    }

    private mutating func recordObservedOperationPromptIfNeeded(
        _ snapshot: AuthenticationPromptCoordinator.OperationAuthenticationPromptSnapshot
    ) {
        guard snapshot.generation > lastObservedOperationAuthenticationAttemptGeneration else {
            return
        }

        lastObservedOperationAuthenticationAttemptGeneration = snapshot.generation
        traceStore?.record(
            category: .lifecycle,
            name: "gate.observeOperationAuthenticationAttempt",
            metadata: [
                "generation": String(snapshot.generation),
                "sessionGeneration": String(snapshot.sessionGeneration),
                "depth": String(snapshot.depth),
                "inProgress": snapshot.isInProgress ? "true" : "false",
                "hasLastEndedAt": snapshot.lastEndedAt == nil ? "false" : "true"
            ]
        )
    }

    private mutating func clearOperationSettleIfCurrent(_ generation: UInt64) {
        guard operationPromptSettle?.generation == generation else {
            return
        }
        operationPromptSettle = nil
    }

    private mutating func clearOperationSettleIfSuperseded(
        by snapshot: AuthenticationPromptCoordinator.OperationAuthenticationPromptSnapshot
    ) {
        guard let settle = operationPromptSettle,
              snapshot.generation > settle.generation,
              snapshot.sessionGeneration != settle.sessionGeneration else {
            return
        }
        operationPromptSettle = nil
    }

    private mutating func clearOperationSettleEligibilityIfCurrentSession(_ sessionGeneration: UInt64) {
        guard operationPromptSettleEligibleSessionGeneration == sessionGeneration else {
            return
        }
        operationPromptSettleEligibleSessionGeneration = nil
    }

    private mutating func consumeOperationPromptSettle(_ settle: OperationPromptSettleState) {
        ignoredOperationGenerationThrough = max(ignoredOperationGenerationThrough, settle.generation)
        operationPromptSettle = nil
        clearOperationSettleEligibilityIfCurrentSession(settle.sessionGeneration)
    }

    private func traceLifecycleDecision(
        name: String,
        decision: PrivacyScreenLifecycleDecision,
        isAuthenticating: Bool,
        isOperationPromptInProgress: Bool,
        suppressionScope: PrivacyScreenLifecycleSuppressionScope? = nil
    ) {
        let activeSuppressionScope = suppressionScope ?? currentSuppressionScope
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

    private var currentSuppressionScope: PrivacyScreenLifecycleSuppressionScope? {
        if operationPromptSettle != nil {
            return .operationPromptSettle
        }
        if appSessionCompletionPending {
            return .appSessionCompletion
        }
        return nil
    }
}
