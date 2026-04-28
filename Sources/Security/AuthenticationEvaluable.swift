import Foundation
import LocalAuthentication
import Security

/// Authentication policy for app launch/resume and App Data root-secret access.
///
/// This policy is intentionally separate from `AuthenticationMode`, which is
/// only for Secure Enclave private-key operations.
enum AppSessionAuthenticationPolicy: String, CaseIterable {
    /// Face ID / Touch ID with device passcode fallback.
    case userPresence

    /// Face ID / Touch ID only. No passcode fallback.
    case biometricsOnly

    var localAuthenticationPolicy: LAPolicy {
        switch self {
        case .userPresence:
            .deviceOwnerAuthentication
        case .biometricsOnly:
            .deviceOwnerAuthenticationWithBiometrics
        }
    }

    func configure(_ context: LAContext) {
        if self == .biometricsOnly {
            context.localizedFallbackTitle = ""
        }
    }

    func createRootSecretAccessControl() throws -> SecAccessControl {
        let flags: SecAccessControlCreateFlags = switch self {
        case .userPresence:
            [.userPresence]
        case .biometricsOnly:
            [.biometryAny]
        }

        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            _ = error?.takeRetainedValue()
            throw AuthenticationError.accessControlCreationFailed
        }

        return accessControl
    }

    static func strictestPolicyForRootSecretReprotection(
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy
    ) -> AppSessionAuthenticationPolicy {
        if currentPolicy == .biometricsOnly || newPolicy == .biometricsOnly {
            return .biometricsOnly
        }
        return .userPresence
    }
}

struct AppSessionAuthenticationResult {
    let isAuthenticated: Bool
    let context: LAContext?

    static func authenticated(context: LAContext?) -> AppSessionAuthenticationResult {
        AppSessionAuthenticationResult(isAuthenticated: true, context: context)
    }

    static var failed: AppSessionAuthenticationResult {
        AppSessionAuthenticationResult(isAuthenticated: false, context: nil)
    }
}

enum AppSessionAuthenticationFailureReason: String, Equatable, Sendable {
    case authenticationFailed
    case biometricsLockedOut
}

/// Authentication mode for the app.
/// Determines the SecAccessControl flags used for SE key wrapping.
enum AuthenticationMode: String, Codable, Sendable {
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
            // SecAccessControlCreateWithFlags follows the CF Create Rule:
            // on failure, the error output is an owned reference that must be released.
            _ = error?.takeRetainedValue()
            throw AuthenticationError.accessControlCreationFailed
        }

        return accessControl
    }
}

enum PrivateKeyControlState: Equatable, Sendable {
    case locked
    case unlocked(AuthenticationMode)
    case recoveryNeeded

    var authMode: AuthenticationMode? {
        guard case .unlocked(let mode) = self else {
            return nil
        }
        return mode
    }

    var isUnlocked: Bool {
        authMode != nil
    }
}

struct ModifyExpiryRecoveryEntry: Codable, Equatable, Sendable {
    var fingerprint: String?
}

enum PrivateKeyControlRewrapPhase: String, Codable, Equatable, Sendable {
    case preparing
    case commitRequired
}

struct PrivateKeyControlRecoveryJournal: Codable, Equatable, Sendable {
    var rewrapTargetMode: AuthenticationMode?
    var rewrapPhase: PrivateKeyControlRewrapPhase?
    var modifyExpiry: ModifyExpiryRecoveryEntry?

    init(
        rewrapTargetMode: AuthenticationMode? = nil,
        rewrapPhase: PrivateKeyControlRewrapPhase? = nil,
        modifyExpiry: ModifyExpiryRecoveryEntry? = nil
    ) {
        self.rewrapTargetMode = rewrapTargetMode
        self.rewrapPhase = rewrapTargetMode == nil ? nil : (rewrapPhase ?? .preparing)
        self.modifyExpiry = modifyExpiry
    }

    static let empty = PrivateKeyControlRecoveryJournal(
        rewrapTargetMode: nil,
        rewrapPhase: nil,
        modifyExpiry: nil
    )

    private enum CodingKeys: String, CodingKey {
        case rewrapTargetMode
        case rewrapPhase
        case modifyExpiry
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rewrapTargetMode = try container.decodeIfPresent(AuthenticationMode.self, forKey: .rewrapTargetMode)
        let decodedRewrapPhase = try container.decodeIfPresent(
            PrivateKeyControlRewrapPhase.self,
            forKey: .rewrapPhase
        )
        self.init(
            rewrapTargetMode: rewrapTargetMode,
            rewrapPhase: decodedRewrapPhase,
            modifyExpiry: try container.decodeIfPresent(ModifyExpiryRecoveryEntry.self, forKey: .modifyExpiry)
        )
    }
}

enum PrivateKeyControlError: Error, LocalizedError, Equatable {
    case locked
    case recoveryNeeded
    case missingStore
    case invalidLegacyAuthMode(String)

    var errorDescription: String? {
        switch self {
        case .locked:
            String(
                localized: "error.privateKeyControl.locked",
                defaultValue: "Private key protection settings are locked. Unlock CypherAir and try again."
            )
        case .recoveryNeeded:
            String(
                localized: "error.privateKeyControl.recoveryNeeded",
                defaultValue: "Private key protection settings need recovery before private-key operations can continue."
            )
        case .missingStore:
            String(
                localized: "error.privateKeyControl.unavailable",
                defaultValue: "Private key protection settings are unavailable."
            )
        case .invalidLegacyAuthMode:
            String(
                localized: "error.privateKeyControl.invalidLegacyAuthMode",
                defaultValue: "Saved private key protection settings are invalid and need recovery."
            )
        }
    }
}

protocol PrivateKeyControlStoreProtocol: AnyObject, Sendable {
    var privateKeyControlState: PrivateKeyControlState { get }

    func requireUnlockedAuthMode() throws -> AuthenticationMode
    func recoveryJournal() throws -> PrivateKeyControlRecoveryJournal
    func beginRewrap(targetMode: AuthenticationMode) throws
    func markRewrapCommitRequired() throws
    func completeRewrap(targetMode: AuthenticationMode) throws
    func clearRewrapJournal() throws
    func beginModifyExpiry(fingerprint: String) throws
    func clearModifyExpiryJournal() throws
    func clearModifyExpiryJournalIfMatches(fingerprint: String) throws
}

final class InMemoryPrivateKeyControlStore: PrivateKeyControlStoreProtocol, @unchecked Sendable {
    private var mode: AuthenticationMode?
    private var journal: PrivateKeyControlRecoveryJournal
    private var isRecoveryNeeded: Bool

    init(
        mode: AuthenticationMode? = nil,
        journal: PrivateKeyControlRecoveryJournal = .empty,
        isRecoveryNeeded: Bool = false
    ) {
        self.mode = mode
        self.journal = journal
        self.isRecoveryNeeded = isRecoveryNeeded
    }

    var privateKeyControlState: PrivateKeyControlState {
        if isRecoveryNeeded {
            return .recoveryNeeded
        }
        guard let mode else {
            return .locked
        }
        return .unlocked(mode)
    }

    func requireUnlockedAuthMode() throws -> AuthenticationMode {
        if isRecoveryNeeded {
            throw PrivateKeyControlError.recoveryNeeded
        }
        guard let mode else {
            throw PrivateKeyControlError.locked
        }
        if journal.rewrapPhase == .commitRequired,
           let targetMode = journal.rewrapTargetMode,
           targetMode != mode {
            throw PrivateKeyControlError.recoveryNeeded
        }
        return mode
    }

    func recoveryJournal() throws -> PrivateKeyControlRecoveryJournal {
        if isRecoveryNeeded {
            throw PrivateKeyControlError.recoveryNeeded
        }
        guard mode != nil else {
            throw PrivateKeyControlError.locked
        }
        return journal
    }

    func beginRewrap(targetMode: AuthenticationMode) throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapTargetMode = targetMode
        journal.rewrapPhase = .preparing
    }

    func markRewrapCommitRequired() throws {
        _ = try requireUnlockedAuthMode()
        guard journal.rewrapTargetMode != nil else {
            throw PrivateKeyControlError.recoveryNeeded
        }
        journal.rewrapPhase = .commitRequired
    }

    func completeRewrap(targetMode: AuthenticationMode) throws {
        if isRecoveryNeeded {
            throw PrivateKeyControlError.recoveryNeeded
        }
        guard mode != nil else {
            throw PrivateKeyControlError.locked
        }
        mode = targetMode
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func clearRewrapJournal() throws {
        if isRecoveryNeeded {
            throw PrivateKeyControlError.recoveryNeeded
        }
        guard mode != nil else {
            throw PrivateKeyControlError.locked
        }
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func beginModifyExpiry(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        journal.modifyExpiry = ModifyExpiryRecoveryEntry(fingerprint: fingerprint)
    }

    func clearModifyExpiryJournal() throws {
        if isRecoveryNeeded {
            throw PrivateKeyControlError.recoveryNeeded
        }
        guard mode != nil else {
            throw PrivateKeyControlError.locked
        }
        journal.modifyExpiry = nil
    }

    func clearModifyExpiryJournalIfMatches(fingerprint: String) throws {
        if isRecoveryNeeded {
            throw PrivateKeyControlError.recoveryNeeded
        }
        guard mode != nil else {
            throw PrivateKeyControlError.locked
        }
        guard journal.modifyExpiry?.fingerprint == fingerprint else {
            return
        }
        journal.modifyExpiry = nil
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

    /// The LAContext from the most recent successful evaluate() call.
    /// Used by switchMode to pass a pre-authenticated context to SE key
    /// reconstruction, avoiding repeated Face ID prompts.
    /// Production: returns the authenticated LAContext.
    /// Test mock: returns nil.
    var lastEvaluatedContext: LAContext? { get }
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
