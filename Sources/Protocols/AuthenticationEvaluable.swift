import Foundation

/// Authentication mode for the app.
/// Determines the SecAccessControl flags used for SE key wrapping.
enum AuthenticationMode: String {
    /// Face ID / Touch ID with device passcode fallback.
    /// Flags: [.privateKeyUsage, .biometryAny, .or, .devicePasscode]
    case standard

    /// Face ID / Touch ID only. No passcode fallback.
    /// Flags: [.privateKeyUsage, .biometryAny]
    /// If biometrics unavailable, all private-key operations are blocked.
    case highSecurity
}

/// Protocol for authentication evaluation.
/// Production: LAContext.
/// Test: Mock with configurable behavior.
protocol AuthenticationEvaluable {
    /// Check if a given authentication policy can be evaluated.
    /// For High Security mode, this checks if biometrics are available.
    func canEvaluate(mode: AuthenticationMode) -> Bool

    /// Evaluate authentication for the given mode.
    /// - Standard: Face ID / Touch ID with passcode fallback.
    /// - High Security: Face ID / Touch ID only.
    ///
    /// - Parameters:
    ///   - mode: The authentication mode to use.
    ///   - reason: The localized reason string shown to the user.
    /// - Returns: true if authentication succeeded.
    func evaluate(mode: AuthenticationMode, reason: String) async throws -> Bool

    /// Check if biometrics are currently available.
    var isBiometricsAvailable: Bool { get }
}

/// UserDefaults keys for authentication preferences.
enum AuthPreferences {
    /// Current authentication mode ("standard" or "highSecurity").
    static let authModeKey = "com.cypherair.preference.authMode"

    /// Grace period in seconds (0, 60, 180, 300).
    static let gracePeriodKey = "com.cypherair.preference.gracePeriod"

    /// Flag indicating an interrupted mode switch (crash recovery).
    static let rewrapInProgressKey = "com.cypherair.internal.rewrapInProgress"

    /// Default grace period: 3 minutes (180 seconds).
    static let defaultGracePeriod = 180
}
