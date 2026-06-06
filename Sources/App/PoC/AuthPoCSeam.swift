#if DEBUG
import Foundation
import LocalAuthentication

// P0 PoC (throwaway `poc/auth-lifecycle-macos` branch) — DEBUG-only injection holders the macOS auth
// harness sets at runtime. They let the harness drive the REAL Secure Enclave operations with an
// in-window-authenticated `LAContext` without changing production service signatures. Both are
// nil/inert unless the PoC harness is active (`CYPHERAIR_POC_HARNESS=1`), so production and normal
// DEBUG runs are byte-for-byte unaffected. (Same module; the lower-layer readers reference these
// types directly — acceptable for a throwaway validation branch.)

/// Per-operation authenticated `LAContext`. The harness authenticates in-window (via its presenter),
/// sets `context` (with `interactionNotAllowed = true`), drives one real operation, then clears it.
/// Read by `PrivateKeyAccessService.unwrapPrivateKey` (software path) and
/// `SystemSecureEnclaveCustodyKeyStore.loadKeys` (custody path).
final class AuthPoCContextBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: LAContext?

    var context: LAContext? {
        get { lock.withLock { stored } }
        set { lock.withLock { stored = newValue } }
    }
}

/// In-window `LAContext` policy evaluator. Forwarded as `AuthenticationManager`'s existing
/// `localAuthenticationPolicyEvaluator`. The harness sets `evaluator` to its presenter's in-window
/// evaluator so the REAL `switchMode` / app-session authentication renders inside the window; when
/// unset, `evaluate` falls back to the standard system sheet (unchanged behavior).
final class AuthPoCEvaluatorBox: @unchecked Sendable {
    typealias Evaluator = (LAContext, LAPolicy, String, @escaping (Bool, Error?) -> Void) -> Void

    private let lock = NSLock()
    private var stored: Evaluator?

    var evaluator: Evaluator? {
        get { lock.withLock { stored } }
        set { lock.withLock { stored = newValue } }
    }

    func evaluate(
        _ context: LAContext,
        _ policy: LAPolicy,
        _ reason: String,
        _ reply: @escaping (Bool, Error?) -> Void
    ) {
        if let evaluator {
            evaluator(context, policy, reason, reply)
        } else {
            context.evaluatePolicy(policy, localizedReason: reason, reply: reply)
        }
    }
}
#endif
