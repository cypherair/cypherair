import Foundation

/// Mock authenticator for testing authentication flows.
/// Controls whether authentication succeeds and whether biometrics are available.
final class MockAuthenticator: AuthenticationEvaluable {
    /// Whether the next authentication attempt should succeed.
    var shouldSucceed = true

    /// Whether biometrics are available on this (mock) device.
    var biometricsAvailable = true

    /// Track calls for test verification.
    private(set) var evaluateCallCount = 0
    private(set) var lastEvaluatedMode: AuthenticationMode?
    private(set) var lastReason: String?

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

    func evaluate(mode: AuthenticationMode, reason: String) async throws -> Bool {
        evaluateCallCount += 1
        lastEvaluatedMode = mode
        lastReason = reason

        // High Security mode with no biometrics → always fail
        if mode == .highSecurity && !biometricsAvailable {
            throw MockAuthError.biometricsUnavailable
        }

        if shouldSucceed {
            return true
        } else {
            throw MockAuthError.authenticationFailed
        }
    }

    /// Reset all state for clean test setup.
    func reset() {
        shouldSucceed = true
        biometricsAvailable = true
        evaluateCallCount = 0
        lastEvaluatedMode = nil
        lastReason = nil
    }
}

enum MockAuthError: Error {
    case authenticationFailed
    case biometricsUnavailable
}
