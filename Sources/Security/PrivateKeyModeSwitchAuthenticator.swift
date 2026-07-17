import Foundation
import LocalAuthentication

private enum PrivateKeyModeSwitchAuthStrings {
    static let reason = String(
        localized: "auth.switchMode.reason",
        defaultValue: "Authenticate to change security mode"
    )
}

final class PrivateKeyModeSwitchAuthenticator {
    func authenticateCurrentMode(
        _ currentMode: AuthenticationMode,
        authenticator: any AuthenticationEvaluable
    ) async throws {
        let authenticated = try await authenticator.evaluate(
            mode: currentMode,
            reason: PrivateKeyModeSwitchAuthStrings.reason
        )

        guard authenticated else {
            throw AuthenticationError.failed
        }
    }
}
