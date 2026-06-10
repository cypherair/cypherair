import Foundation
import LocalAuthentication

/// iOS / iPadOS / visionOS implementation of `AuthenticationPresenting`: a pure
/// pass-through. These platforms keep the system authentication prompt (TARGET §5),
/// so the seam adds nothing — the evaluation runs directly and the system UI renders
/// exactly as it does today, byte-for-byte.
///
/// Also the protocol-typed default wherever a concrete macOS presenter is not wired
/// (e.g. direct `AppContainer(...)` test construction).
struct PassthroughAuthenticationPresenter: AuthenticationPresenting {
    func presentingEvaluation<T: Sendable>(
        context: LAContext,
        request _: AuthenticationPresentationRequest,
        _ evaluation: @Sendable @escaping (LAContext) async throws -> T
    ) async throws -> T {
        try await evaluation(context)
    }
}
