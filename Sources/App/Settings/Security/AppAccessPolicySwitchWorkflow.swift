import Foundation
import LocalAuthentication

/// Owns the App Access Protection policy-switch action. Only the app-session
/// authentication and immediate root-secret re-protection window is enrolled in
/// an operation-prompt session; the rest of the policy switch remains a normal
/// action so genuine macOS away events still lock immediately at grace period 0.
///
/// The switch is a two-store transaction — the persisted root secret's Keychain
/// access control and the App Access Protection preference — and this workflow
/// is its single owner. It journals the target before the Keychain gate moves
/// and commits the preference once the gate is confirmed, so a process death
/// anywhere in between is recoverable rather than a silent disagreement
/// (issue #747; the recovery half is `AppAccessPolicySwitchRecovery`).
@MainActor
final class AppAccessPolicySwitchWorkflow {
    private let currentPolicy: () -> AppSessionAuthenticationPolicy
    private let hasPersistedRootSecret: () -> Bool
    private let canEvaluate: (AppSessionAuthenticationPolicy) -> Bool
    private let evaluateAppSession: (
        AppSessionAuthenticationPolicy,
        String
    ) async throws -> AppSessionAuthenticationResult
    private let beginPolicySwitchJournal: (AppSessionAuthenticationPolicy) -> Void
    private let reprotectPersistedRootSecret: (
        AppSessionAuthenticationPolicy,
        AppSessionAuthenticationPolicy,
        LAContext?
    ) throws -> Void
    private let commitPolicySwitch: (AppSessionAuthenticationPolicy) -> Void
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
        beginPolicySwitchJournal: @escaping (AppSessionAuthenticationPolicy) -> Void,
        reprotectPersistedRootSecret: @escaping (
            AppSessionAuthenticationPolicy,
            AppSessionAuthenticationPolicy,
            LAContext?
        ) throws -> Void,
        commitPolicySwitch: @escaping (AppSessionAuthenticationPolicy) -> Void,
        discardHandoffContextForPolicyChange: @escaping () -> Void,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator
    ) {
        self.currentPolicy = currentPolicy
        self.hasPersistedRootSecret = hasPersistedRootSecret
        self.canEvaluate = canEvaluate
        self.evaluateAppSession = evaluateAppSession
        self.beginPolicySwitchJournal = beginPolicySwitchJournal
        self.reprotectPersistedRootSecret = reprotectPersistedRootSecret
        self.commitPolicySwitch = commitPolicySwitch
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
            // No persisted root secret means no Keychain gate to disagree with,
            // so the preference is the whole state and needs no journal.
            commitPolicySwitch(newPolicy)
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
            // SECURITY-CRITICAL: the journal opens here — after authentication
            // (which mutates nothing, so a cancelled prompt must not leave an
            // intent behind) and before the Keychain access control moves.
            beginPolicySwitchJournal(newPolicy)
            do {
                try reprotectPersistedRootSecret(currentPolicy, newPolicy, result.context)
            } catch {
                // The journal deliberately stays open. A re-protection failure
                // cannot say whether the access-control update landed before it
                // threw, so the pair is treated as possibly-disagreeing: the
                // effective policy stays the stricter of the two and the next
                // authenticated launch converges them.
                result.context?.invalidate()
                throw error
            }
            commitPolicySwitch(newPolicy)
            return result
        }
    }
}

/// Launch-time convergence for a policy switch the process died inside of
/// (issue #747). Runs after an app-session authentication, on that
/// authentication's context.
enum AppAccessPolicySwitchRecovery {
    /// Re-drive an unconfirmed switch to its recorded target and commit it.
    ///
    /// SECURITY-CRITICAL: an open journal always re-protects. Nothing in the
    /// persisted pair reveals which access control the root secret actually
    /// carries, so the gate state must never be *inferred* — in particular
    /// `committed == target` does not mean the gate already matches. A second
    /// switch attempt overwrites the journal
    /// (`beginAppSessionAuthenticationPolicySwitch`) and the workflow's source
    /// policy is the *effective* one, so reverting a failed switch legitimately
    /// journals a target equal to the committed value while the gate still
    /// carries the old target. Re-protecting unconditionally is safe because it
    /// is idempotent: writing an access control the item already carries is a
    /// no-op that still round-trip verifies the secret.
    ///
    /// On failure the journal is left open so the next authenticated launch
    /// retries — never cleared blind, which would make the disagreement
    /// permanent and silent.
    static func recover(
        config: AppConfiguration,
        authenticationContext: LAContext?,
        reprotectPersistedRootSecretIfPresent: (
            AppSessionAuthenticationPolicy,
            AppSessionAuthenticationPolicy,
            LAContext?
        ) throws -> Bool
    ) {
        guard let target = config.pendingAppSessionAuthenticationPolicySwitch else {
            return
        }

        do {
            _ = try reprotectPersistedRootSecretIfPresent(
                config.committedAppSessionAuthenticationPolicy,
                target,
                authenticationContext
            )
            config.completeAppSessionAuthenticationPolicySwitch(to: target)
        } catch {
            // Leave the journal open. The authenticated context may have been
            // satisfied by a credential the current gate does not accept (the
            // effective policy is only as strict as the recorded pair, which an
            // overwritten journal can understate), so a failure here means "not
            // converged yet", never "nothing to converge".
        }
    }
}
