import Foundation
import LocalAuthentication

/// What an in-window authentication presentation is for. Distinct purposes map to
/// distinct mount points / chrome in the host (TARGET §2.C); they never change the
/// evaluation mechanism, which the caller owns.
enum AuthenticationPresentationPurpose: String, Sendable {
    /// App-session unlock (subsystem A, `evaluatePolicy`).
    case appSessionUnlock
    /// A per-operation private-key authorization (subsystem B, `evaluateAccessControl`).
    case perOperation
    /// One of the two one-time macOS migrations (P3; wired in a later PR).
    case migration
}

/// Caller-supplied description of an authentication presentation. Carries no key
/// material and no `LAContext` — only what the host needs to render chrome and what
/// the trace needs to attribute the prompt.
struct AuthenticationPresentationRequest: Sendable {
    let localizedReason: String
    let purpose: AuthenticationPresentationPurpose
    let source: String
}

/// The authentication *presentation* seam (P3 of the auth-lifecycle redesign;
/// TARGET §2.C / §4, roadmap §3 P3). It is **mechanism-shaped, not policy-shaped**:
/// the caller builds the `LAContext`, chooses the evaluation
/// (`evaluatePolicy` / `evaluateAccessControl`), and keeps ownership of the context
/// after return (for threading into a Secure Enclave operation, and for
/// `invalidate()`). The presenter only wraps the in-window prompt's lifetime around
/// the evaluation:
///
/// - macOS (`MacAuthenticationPresenter`): mounts an `LAAuthenticationView` paired
///   with `context` inside the app window for the duration of `evaluation`, so the
///   prompt renders in-window and the app never resigns active to authenticate.
/// - iOS / iPadOS / visionOS (`PassthroughAuthenticationPresenter`): runs
///   `evaluation` directly — the system prompt renders exactly as today.
///
/// The app-unlock context (subsystem A) is never reused to authorize a private-key
/// operation (subsystem B); this seam presents prompts, it does not move contexts
/// between subsystems.
protocol AuthenticationPresenting: Sendable {
    /// Run `evaluation(context)` with the platform's authentication presentation
    /// wrapped around it, returning the evaluation's result. The caller retains
    /// `context` after return and owns its `invalidate()`.
    func presentingEvaluation<T: Sendable>(
        context: LAContext,
        request: AuthenticationPresentationRequest,
        _ evaluation: @Sendable @escaping (LAContext) async throws -> T
    ) async throws -> T
}
