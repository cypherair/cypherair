import Foundation
import LocalAuthentication

/// Why a flow is requesting in-window authentication presentation.
///
/// On macOS this drives *where* the host mounts the `LAAuthenticationView` (P3 of the
/// auth-lifecycle redesign — see AUTH_LIFECYCLE_REDESIGN_TARGET_DESIGN.md §2.C / §4).
/// On iOS / iPadOS / visionOS it is informational only (the system prompt renders).
enum AuthenticationPresentationPurpose: Sendable {
    /// App unlock (subsystem A — `AppSessionAuthenticationPolicy`). The prompt renders
    /// inside the lock surface.
    case appSessionUnlock

    /// A per-operation private-key authorization (subsystem B — `AuthenticationMode`):
    /// signing, decryption, certification, revocation, key-expiry.
    case perOperation

    /// A one-time, user-initiated macOS authentication migration.
    case migration
}

/// A request to present an authentication prompt for the duration of a single
/// evaluation. The `localizedReason` is shown to the user; `purpose` and `source`
/// are used for placement and tracing.
struct AuthenticationPresentationRequest: Sendable {
    let localizedReason: String
    let purpose: AuthenticationPresentationPurpose
    let source: String

    init(localizedReason: String, purpose: AuthenticationPresentationPurpose, source: String) {
        self.localizedReason = localizedReason
        self.purpose = purpose
        self.source = source
    }
}

/// The authentication-presentation seam (P3 of the auth-lifecycle redesign; TARGET §2.C).
///
/// On macOS the conforming presenter renders the biometric prompt **inside the app
/// window** via `LAAuthenticationView`, then drives the evaluation on the paired
/// `LAContext` so the app does not resign active. On iOS / iPadOS / visionOS the
/// passthrough presenter simply runs the evaluation and the system prompt renders as
/// today.
///
/// Both entry points are callback-shaped and the **caller owns the `LAContext`** it
/// passes in (and is responsible for `invalidate()`): the policy entry point matches
/// `AuthenticationManager.localAuthenticationPolicyEvaluator`, and the access-control
/// entry point reports success/failure so the caller can thread the same satisfied
/// context into the Secure Enclave operation. This avoids handing a non-`Sendable`
/// `LAContext` back across an actor boundary.
///
/// PR-1 introduces this seam **dormant** — no production caller routes through it yet;
/// the per-surface wiring lands in later P3 PRs.
protocol AuthenticationPresenting: Sendable {
    /// Evaluate `policy` on `context`, rendering the prompt in-window on macOS.
    /// Mirrors `AuthenticationManager.localAuthenticationPolicyEvaluator` so it can be
    /// injected there directly. `reply` is delivered exactly once.
    func evaluatePolicyInWindow(
        _ context: LAContext,
        policy: LAPolicy,
        localizedReason: String,
        reply: @escaping @Sendable (Bool, Error?) -> Void
    )

    /// Authorize `accessControl` for `operation` on `context`, rendering the prompt
    /// in-window on macOS. On success the same `context` is satisfied for the Secure
    /// Enclave operation the caller is about to perform. `reply` is delivered exactly once.
    func authorizeAccessControlInWindow(
        _ context: LAContext,
        accessControl: SecAccessControl,
        operation: LAAccessControlOperation,
        localizedReason: String,
        purpose: AuthenticationPresentationPurpose,
        reply: @escaping @Sendable (Bool, Error?) -> Void
    )
}
