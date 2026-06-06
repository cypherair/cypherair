#if DEBUG && os(macOS)
import AppKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// P0 PoC (throwaway `poc/auth-lifecycle-macos` branch): in-window authentication presenter.
///
/// Implements the candidate production (P4/P5) mechanism the PoC validates: an
/// `LAAuthenticationView` (LocalAuthenticationEmbeddedUI, macOS 12+) paired with a fresh
/// per-operation `LAContext`. When `evaluateAccessControl` / `evaluatePolicy` is called on
/// that context, the biometric renders **inside the app window** instead of the detached
/// system alert — so the app does not resign active.
///
/// The presenter is the seam through which the harness drives the real Secure Enclave
/// operations: it returns the authenticated `LAContext`, which the real
/// `SecureEnclaveManager.reconstructKey(authenticationContext:)` and custody
/// `kSecUseAuthenticationContext` paths then consume with no second prompt.
@MainActor
@Observable
final class AuthPoCPresenter {
    /// When non-nil, the harness renders an `LAAuthenticationView` bound to this context.
    private(set) var activeContext: LAContext?

    /// Resumed by the hosted view once its `NSView` is mounted, so `evaluate*` is only
    /// called after the view is actually in the hierarchy (LAAuthenticationView requires
    /// the paired view to exist before the context evaluates).
    private var readyContinuation: CheckedContinuation<Void, Never>?

    enum PresenterError: Error { case authenticationFailed }

    /// Authenticate `accessControl` for `operation` in-window; returns the authenticated
    /// context (reuse-duration 0). The caller consumes it for exactly one Secure Enclave op.
    func authenticate(
        accessControl: SecAccessControl,
        operation: LAAccessControlOperation,
        localizedReason: String
    ) async throws -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        try await present(context)
        defer { activeContext = nil }
        try await context.evaluateAccessControl(accessControl, operation: operation, localizedReason: localizedReason)
        return context
    }

    /// Authenticate a policy in-window (app-unlock / rewrap measurement); returns the context.
    func authenticate(policy: LAPolicy, localizedReason: String) async throws -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        try await present(context)
        defer { activeContext = nil }
        let success = try await context.evaluatePolicy(policy, localizedReason: localizedReason)
        guard success else { throw PresenterError.authenticationFailed }
        return context
    }

    /// Drives `AuthenticationManager.localAuthenticationPolicyEvaluator`: render the
    /// manager-supplied context in-window, then evaluate the manager's policy there.
    /// Used to run the REAL rewrap / app-session auth through the in-window presenter.
    func inWindowPolicyEvaluator(
        _ context: LAContext,
        _ policy: LAPolicy,
        _ reason: String,
        _ reply: @escaping (Bool, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                try await present(context)
                context.evaluatePolicy(policy, localizedReason: reason) { success, error in
                    Task { @MainActor in self.activeContext = nil }
                    reply(success, error)
                }
            } catch {
                self.activeContext = nil
                reply(false, error)
            }
        }
    }

    private func present(_ context: LAContext) async throws {
        activeContext = context
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            readyContinuation = continuation
        }
    }

    /// Called by the hosted view once its `NSView` is in the hierarchy.
    func viewDidMount() {
        readyContinuation?.resume()
        readyContinuation = nil
    }
}

/// Hosts the AppKit `LAAuthenticationView` for `context` inside SwiftUI.
struct LAAuthenticationViewHost: NSViewRepresentable {
    let context: LAContext
    let onReady: () -> Void

    func makeNSView(context _: Context) -> LAAuthenticationView {
        let view = LAAuthenticationView(context: self.context)
        DispatchQueue.main.async { onReady() }
        return view
    }

    func updateNSView(_: LAAuthenticationView, context _: Context) {}
}
#endif
