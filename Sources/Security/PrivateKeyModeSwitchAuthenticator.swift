import Foundation
import LocalAuthentication

private enum PrivateKeyModeSwitchAuthStrings {
    static let reason = String(
        localized: "auth.switchMode.reason",
        defaultValue: "Authenticate to change security mode"
    )
}

final class PrivateKeyModeSwitchAuthenticator {
    /// Authenticate under the mode the keys are currently wrapped in, and hand
    /// back the authenticated context for the caller to own.
    ///
    /// - Returns: The context the re-wrap threads into every Secure Enclave
    ///   operation of this switch, or `nil` where the evaluator has no real
    ///   context (UI-test bypass, test doubles) and each operation authenticates
    ///   implicitly. The caller invalidates it when the switch ends.
    func authenticateCurrentMode(
        _ currentMode: AuthenticationMode,
        authenticator: any AuthenticationEvaluable
    ) async throws -> LAContext? {
        let result = try await authenticator.evaluate(
            mode: currentMode,
            reason: PrivateKeyModeSwitchAuthStrings.reason
        )

        guard result.isAuthenticated else {
            throw AuthenticationError.failed
        }

        return result.context
    }
}
