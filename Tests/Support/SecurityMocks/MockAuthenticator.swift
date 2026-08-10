import Foundation
import LocalAuthentication
@testable import CypherAir

/// Mock authenticator for testing authentication flows.
/// Controls whether authentication succeeds and whether biometrics are available.
///
/// - Warning: Not thread-safe. Only use from test methods on a single actor.
final class MockAuthenticator: AuthenticationEvaluable, @unchecked Sendable {
    /// Whether the next authentication attempt should succeed.
    var shouldSucceed = true

    /// Whether biometrics are available on this (mock) device.
    var biometricsAvailable = true

    var isBiometricsAvailable: Bool { biometricsAvailable }

    func canEvaluate(mode: AuthenticationMode) -> Bool {
        switch mode {
        case .standard:
            // Standard mode: always available (passcode fallback)
            return true
        case .highSecurity:
            // High Security: only if biometrics available
            return biometricsAvailable
        }
    }

    /// The mock has no real `LAContext`, so an authenticated result carries a nil
    /// context: Secure Enclave call sites then authenticate implicitly.
    func evaluate(
        mode: AuthenticationMode,
        reason: String
    ) async throws -> PrivateKeyAuthenticationResult {
        // High Security mode with no biometrics → always fail
        if mode == .highSecurity && !biometricsAvailable {
            throw AuthenticationError.biometricsUnavailable
        }

        if shouldSucceed {
            return .authenticated(context: nil)
        } else {
            throw AuthenticationError.failed
        }
    }
}


