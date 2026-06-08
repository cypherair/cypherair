import Foundation
import LocalAuthentication

/// The non-macOS `AuthenticationPresenting` implementation: a pure pass-through.
///
/// On iOS / iPadOS / visionOS there is no embedded in-window authentication view, so
/// the evaluation runs directly against the `LAContext` and the **system** prompt
/// renders — byte-for-byte the current behavior. (Per-operation private-key flows on
/// those platforms do not pre-authorize through this seam at all; the Secure Enclave
/// reconstruction triggers the system prompt at use time. This conformance exists so
/// the seam type is uniform across platforms.)
struct PassthroughAuthenticationPresenter: AuthenticationPresenting {
    init() {}

    func evaluatePolicyInWindow(
        _ context: LAContext,
        policy: LAPolicy,
        localizedReason: String,
        reply: @escaping @Sendable (Bool, Error?) -> Void
    ) {
        context.evaluatePolicy(policy, localizedReason: localizedReason, reply: reply)
    }

    func authorizeAccessControlInWindow(
        _ context: LAContext,
        accessControl: SecAccessControl,
        operation: LAAccessControlOperation,
        localizedReason: String,
        purpose: AuthenticationPresentationPurpose,
        reply: @escaping @Sendable (Bool, Error?) -> Void
    ) {
        context.evaluateAccessControl(
            accessControl,
            operation: operation,
            localizedReason: localizedReason,
            reply: reply
        )
    }
}
