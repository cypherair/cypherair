import Foundation
import Security

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

    /// Create a SecAccessControl appropriate for this authentication mode.
    ///
    /// - Standard: [.privateKeyUsage, .biometryAny, .or, .devicePasscode]
    /// - High Security: [.privateKeyUsage, .biometryAny]
    ///
    /// This includes `.privateKeyUsage` and is intended for SE key creation
    /// (`SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl:)`).
    /// The SE key's `dataRepresentation` stored in the Keychain uses
    /// `accessControl: nil` because `.privateKeyUsage` is only valid for
    /// `kSecClassKey` items; the SE-level access control is the primary
    /// enforcement mechanism.
    ///
    /// SECURITY-CRITICAL: These flags must match SECURITY.md Section 4.
    /// Any change requires human review.
    func createAccessControl() throws -> SecAccessControl {
        let flags: SecAccessControlCreateFlags = switch self {
        case .standard:
            [.privateKeyUsage, .biometryAny, .or, .devicePasscode]
        case .highSecurity:
            [.privateKeyUsage, .biometryAny]
        }

        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            throw AuthenticationError.accessControlCreationFailed
        }

        return accessControl
    }
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

    /// The target mode of an in-progress mode switch (crash recovery).
    /// Stored alongside `rewrapInProgressKey` so crash recovery can create
    /// correct access control flags and update the mode preference.
    static let rewrapTargetModeKey = "com.cypherair.internal.rewrapTargetMode"

    /// Flag indicating an interrupted modifyExpiry operation (crash recovery).
    static let modifyExpiryInProgressKey = "com.cypherair.internal.modifyExpiryInProgress"

    /// The fingerprint of the key being modified during an interrupted modifyExpiry.
    static let modifyExpiryFingerprintKey = "com.cypherair.internal.modifyExpiryFingerprint"

    /// Default grace period: 3 minutes (180 seconds).
    static let defaultGracePeriod = 180
}
