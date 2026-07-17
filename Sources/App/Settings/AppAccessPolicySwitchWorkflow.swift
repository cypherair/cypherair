import Foundation
import LocalAuthentication

/// Owns the App Access Protection policy-switch action. Only the app-session
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
        String
    ) async throws -> AppSessionAuthenticationResult
    private let reprotectPersistedRootSecret: (
        AppSessionAuthenticationPolicy,
        AppSessionAuthenticationPolicy,
        LAContext?
    ) throws -> Void
    private let discardHandoffContextForPolicyChange: () -> Void
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator

    init(
        currentPolicy: @escaping () -> AppSessionAuthenticationPolicy,
        hasPersistedRootSecret: @escaping () -> Bool,
        canEvaluate: @escaping (AppSessionAuthenticationPolicy) -> Bool,
        evaluateAppSession: @escaping (
            AppSessionAuthenticationPolicy,
            String
        ) async throws -> AppSessionAuthenticationResult,
        reprotectPersistedRootSecret: @escaping (
            AppSessionAuthenticationPolicy,
            AppSessionAuthenticationPolicy,
            LAContext?
        ) throws -> Void,
        discardHandoffContextForPolicyChange: @escaping () -> Void,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator
    ) {
        self.currentPolicy = currentPolicy
        self.hasPersistedRootSecret = hasPersistedRootSecret
        self.canEvaluate = canEvaluate
        self.evaluateAppSession = evaluateAppSession
        self.reprotectPersistedRootSecret = reprotectPersistedRootSecret
        self.discardHandoffContextForPolicyChange = discardHandoffContextForPolicyChange
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
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
        if hasPersistedRootSecret() {
            let authenticationPolicy = AppSessionAuthenticationPolicy
                .strictestPolicyForRootSecretReprotection(
                    from: currentPolicy,
                    to: newPolicy
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
        } else {
            guard canEvaluate(newPolicy) else {
                throw AuthenticationError.appAccessBiometricsUnavailable
            }
            discardHandoffContextForPolicyChange()
        }
    }

    private func authenticateAndReprotectRootSecret(
        currentPolicy: AppSessionAuthenticationPolicy,
        newPolicy: AppSessionAuthenticationPolicy,
        authenticationPolicy: AppSessionAuthenticationPolicy
    ) async throws -> AppSessionAuthenticationResult {
        try await authenticationPromptCoordinator.withOperationPrompt {
            let result = try await evaluateAppSession(
                authenticationPolicy,
                String(
                    localized: "settings.appAccessPolicy.change.reason",
                    defaultValue: "Authenticate to change App Access Protection."
                )
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
