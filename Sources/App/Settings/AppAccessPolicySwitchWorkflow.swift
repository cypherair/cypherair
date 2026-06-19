import Foundation
import LocalAuthentication

/// Owns the App Access Protection policy-switch action (previously an inline
/// closure in `CypherAirApp`, untestable there). Only the app-session
/// authentication and immediate root-secret re-protection window is enrolled in
/// an operation-prompt session; the rest of the policy switch remains a normal
/// action so genuine macOS away events still lock immediately at grace period 0.
@MainActor
final class AppAccessPolicySwitchWorkflow {
    private let currentPolicy: () -> AppSessionAuthenticationPolicy
    private let hasPersistedRootSecret: () -> Bool
    private let canEvaluate: (AppSessionAuthenticationPolicy) -> Bool
    private let evaluateAppSession: (
        AppSessionAuthenticationPolicy,
        String,
        String
    ) async throws -> AppSessionAuthenticationResult
    private let reprotectPersistedRootSecret: (
        AppSessionAuthenticationPolicy,
        AppSessionAuthenticationPolicy,
        LAContext?
    ) throws -> Void
    private let discardHandoffContextForPolicyChange: () -> Void
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let traceStore: AuthLifecycleTraceStore?

    init(
        currentPolicy: @escaping () -> AppSessionAuthenticationPolicy,
        hasPersistedRootSecret: @escaping () -> Bool,
        canEvaluate: @escaping (AppSessionAuthenticationPolicy) -> Bool,
        evaluateAppSession: @escaping (
            AppSessionAuthenticationPolicy,
            String,
            String
        ) async throws -> AppSessionAuthenticationResult,
        reprotectPersistedRootSecret: @escaping (
            AppSessionAuthenticationPolicy,
            AppSessionAuthenticationPolicy,
            LAContext?
        ) throws -> Void,
        discardHandoffContextForPolicyChange: @escaping () -> Void,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        traceStore: AuthLifecycleTraceStore?
    ) {
        self.currentPolicy = currentPolicy
        self.hasPersistedRootSecret = hasPersistedRootSecret
        self.canEvaluate = canEvaluate
        self.evaluateAppSession = evaluateAppSession
        self.reprotectPersistedRootSecret = reprotectPersistedRootSecret
        self.discardHandoffContextForPolicyChange = discardHandoffContextForPolicyChange
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.traceStore = traceStore
    }

    func run(to newPolicy: AppSessionAuthenticationPolicy) async throws {
        let currentPolicy = currentPolicy()
        guard newPolicy != currentPolicy else {
            return
        }

        try await performSwitch(from: currentPolicy, to: newPolicy)
    }

    private func performSwitch(
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy
    ) async throws {
        var didTraceFinish = false
        do {
            if hasPersistedRootSecret() {
                let authenticationPolicy = AppSessionAuthenticationPolicy
                    .strictestPolicyForRootSecretReprotection(
                        from: currentPolicy,
                        to: newPolicy
                    )
                traceStore?.record(
                    category: .operation,
                    name: "appAccessPolicy.switch.start",
                    metadata: [
                        "currentPolicy": currentPolicy.rawValue,
                        "newPolicy": newPolicy.rawValue,
                        "authPolicy": authenticationPolicy.rawValue,
                        "hasRootSecret": "true"
                    ]
                )
                let result = try await authenticateAndReprotectRootSecret(
                    currentPolicy: currentPolicy,
                    newPolicy: newPolicy,
                    authenticationPolicy: authenticationPolicy
                )
                defer {
                    result.context?.invalidate()
                }

                discardHandoffContextForPolicyChange()
                traceStore?.record(
                    category: .operation,
                    name: "appAccessPolicy.switch.finish",
                    metadata: ["result": "success", "newPolicy": newPolicy.rawValue, "hasRootSecret": "true"]
                )
                didTraceFinish = true
            } else {
                traceStore?.record(
                    category: .operation,
                    name: "appAccessPolicy.switch.start",
                    metadata: [
                        "currentPolicy": currentPolicy.rawValue,
                        "newPolicy": newPolicy.rawValue,
                        "authPolicy": newPolicy.rawValue,
                        "hasRootSecret": "false"
                    ]
                )
                guard canEvaluate(newPolicy) else {
                    traceStore?.record(
                        category: .operation,
                        name: "appAccessPolicy.switch.finish",
                        metadata: [
                            "result": "biometricsUnavailable",
                            "newPolicy": newPolicy.rawValue,
                            "hasRootSecret": "false"
                        ]
                    )
                    didTraceFinish = true
                    throw AuthenticationError.appAccessBiometricsUnavailable
                }
                discardHandoffContextForPolicyChange()
                traceStore?.record(
                    category: .operation,
                    name: "appAccessPolicy.switch.finish",
                    metadata: ["result": "success", "newPolicy": newPolicy.rawValue, "hasRootSecret": "false"]
                )
                didTraceFinish = true
            }
        } catch {
            if !didTraceFinish {
                traceStore?.record(
                    category: .operation,
                    name: "appAccessPolicy.switch.finish",
                    metadata: [
                        "result": "error",
                        "newPolicy": newPolicy.rawValue,
                        "errorType": String(describing: type(of: error))
                    ]
                )
            }
            throw error
        }
    }

    private func authenticateAndReprotectRootSecret(
        currentPolicy: AppSessionAuthenticationPolicy,
        newPolicy: AppSessionAuthenticationPolicy,
        authenticationPolicy: AppSessionAuthenticationPolicy
    ) async throws -> AppSessionAuthenticationResult {
        try await authenticationPromptCoordinator.withOperationPrompt(
            source: "appAccessPolicy.switch.authenticate"
        ) {
            let result = try await evaluateAppSession(
                authenticationPolicy,
                String(
                    localized: "settings.appAccessPolicy.change.reason",
                    defaultValue: "Authenticate to change App Access Protection."
                ),
                "appAccessPolicy.switch"
            )
            guard result.isAuthenticated else {
                throw AuthenticationError.failed
            }
            do {
                try reprotectPersistedRootSecret(currentPolicy, newPolicy, result.context)
            } catch {
                result.context?.invalidate()
                throw error
            }
            return result
        }
    }
}
