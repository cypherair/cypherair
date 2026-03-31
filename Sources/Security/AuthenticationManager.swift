import Foundation
import LocalAuthentication
import Security

// MARK: - Localized Strings

private enum AuthStrings {
    static let switchModeReason = String(localized: "auth.switchMode.reason", defaultValue: "Authenticate to change security mode")
}

/// Errors from authentication and mode switching operations.
enum AuthenticationError: Error, LocalizedError {
    /// Biometric authentication is not available (sensor damaged, locked out, etc.).
    case biometricsUnavailable
    /// The user cancelled the authentication prompt.
    case cancelled
    /// Authentication failed (wrong biometric, wrong passcode, etc.).
    case failed
    /// Failed to create SecAccessControl for the requested mode.
    case accessControlCreationFailed
    /// Mode switch failed: one or more keys could not be re-wrapped.
    /// Original keys remain intact.
    case modeSwitchFailed(underlying: Error)
    /// No private key identities found to re-wrap during mode switch.
    case noIdentities
    /// High Security mode requires at least one backed-up key.
    /// The user must back up a key before enabling High Security mode.
    case backupRequired

    var errorDescription: String? {
        switch self {
        case .biometricsUnavailable:
            String(localized: "error.auth.biometricsUnavailable",
                   defaultValue: "Biometric authentication is currently unavailable. In High Security mode, all private key operations are blocked until biometric authentication is restored.")
        case .cancelled:
            String(localized: "error.auth.cancelled",
                   defaultValue: "Authentication was cancelled.")
        case .failed:
            String(localized: "error.auth.failed",
                   defaultValue: "Authentication failed.")
        case .accessControlCreationFailed:
            String(localized: "error.auth.accessControlFailed",
                   defaultValue: "Failed to configure security access controls.")
        case .modeSwitchFailed:
            String(localized: "error.auth.modeSwitchFailed",
                   defaultValue: "Failed to switch authentication mode. Your keys remain safely protected under the previous mode.")
        case .noIdentities:
            String(localized: "error.auth.noIdentities",
                   defaultValue: "No private keys found. Generate or import a key first.")
        case .backupRequired:
            String(localized: "error.auth.backupRequired",
                   defaultValue: "High Security mode requires at least one backed-up key. Please back up a key before enabling this mode.")
        }
    }
}

/// Manages device authentication (Face ID / Touch ID) and auth mode switching.
///
/// Responsibilities:
/// - Evaluate authentication using LAContext (Standard or High Security mode).
/// - Switch between Standard and High Security modes by re-wrapping all SE keys.
/// - Recover from interrupted mode switches (crash recovery) on app launch.
///
/// SECURITY-CRITICAL: Changes to this file require human review.
/// See SECURITY.md Section 4 and Section 7.
@Observable
final class AuthenticationManager: AuthenticationEvaluable {

    // MARK: - Dependencies

    private let secureEnclave: any SecureEnclaveManageable
    private let keychain: any KeychainManageable
    private let defaults: UserDefaults
    private let bundleStore: KeyBundleStore
    private let migrationCoordinator: KeyMigrationCoordinator

    // MARK: - State

    /// The LAContext from the most recent successful evaluate() call.
    /// Used by switchMode to pass a pre-authenticated context to SE key
    /// reconstruction, avoiding repeated Face ID prompts.
    private(set) var lastEvaluatedContext: LAContext?

    /// The current authentication mode, persisted in UserDefaults.
    var currentMode: AuthenticationMode {
        let raw = defaults.string(forKey: AuthPreferences.authModeKey) ?? AuthenticationMode.standard.rawValue
        return AuthenticationMode(rawValue: raw) ?? .standard
    }

    /// The current grace period in seconds, persisted in UserDefaults.
    var gracePeriod: Int {
        let value = defaults.integer(forKey: AuthPreferences.gracePeriodKey)
        // If never set (returns 0 but user hasn't configured it), use default.
        if !defaults.contains(key: AuthPreferences.gracePeriodKey) {
            return AuthPreferences.defaultGracePeriod
        }
        return value
    }

    // MARK: - Init

    init(
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        defaults: UserDefaults = .standard
    ) {
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.defaults = defaults
        let bundleStore = KeyBundleStore(keychain: keychain)
        self.bundleStore = bundleStore
        self.migrationCoordinator = KeyMigrationCoordinator(bundleStore: bundleStore)
    }

    // MARK: - AuthenticationEvaluable

    var isBiometricsAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    func canEvaluate(mode: AuthenticationMode) -> Bool {
        switch mode {
        case .standard:
            // Standard mode always available (passcode fallback).
            let context = LAContext()
            var error: NSError?
            return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        case .highSecurity:
            return isBiometricsAvailable
        }
    }

    func evaluate(mode: AuthenticationMode, reason: String) async throws -> Bool {
        let context = LAContext()
        let success: Bool

        switch mode {
        case .standard:
            // Face ID / Touch ID with device passcode fallback.
            success = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )

        case .highSecurity:
            // Face ID / Touch ID only. Hide the passcode fallback button.
            context.localizedFallbackTitle = ""

            do {
                success = try await context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithBiometrics,
                    localizedReason: reason
                )
            } catch let error as LAError where error.code == .biometryNotAvailable
                                             || error.code == .biometryNotEnrolled
                                             || error.code == .biometryLockout {
                throw AuthenticationError.biometricsUnavailable
            } catch let error as LAError where error.code == .userCancel
                                             || error.code == .appCancel
                                             || error.code == .systemCancel {
                throw AuthenticationError.cancelled
            } catch {
                throw AuthenticationError.failed
            }
        }

        if success {
            lastEvaluatedContext = context
        }
        return success
    }

    // MARK: - Access Control Creation

    /// Create a SecAccessControl appropriate for the given authentication mode.
    /// Delegates to `AuthenticationMode.createAccessControl()` — the single source of truth.
    func createAccessControl(for mode: AuthenticationMode) throws -> SecAccessControl {
        try mode.createAccessControl()
    }

    // MARK: - Mode Switching

    /// Switch authentication mode by re-wrapping all SE-protected private keys.
    ///
    /// This is an atomic operation: if any step fails before old keys are deleted,
    /// the original keys remain intact and the temporary items are cleaned up.
    ///
    /// The method authenticates the user under the CURRENT mode before proceeding.
    /// This ensures the security boundary is self-contained and cannot be bypassed
    /// by a caller forgetting to authenticate first.
    ///
    /// - Parameters:
    ///   - newMode: The target authentication mode.
    ///   - fingerprints: All identity fingerprints (lowercase hex) that have SE-wrapped keys.
    ///   - hasBackup: Whether at least one private key has been backed up.
    ///     If false and switching to High Security, the caller must show a stronger warning.
    ///   - authenticator: The authentication evaluator to use for verifying user identity.
    ///     In production, pass `self` (the AuthenticationManager). In tests, pass a mock.
    func switchMode(
        to newMode: AuthenticationMode,
        fingerprints: [String],
        hasBackup: Bool,
        authenticator: any AuthenticationEvaluable
    ) async throws {
        guard !fingerprints.isEmpty else {
            throw AuthenticationError.noIdentities
        }

        // Defense-in-depth: require at least one backed-up key before enabling
        // High Security mode. The UI should also warn; this is the safety net.
        if newMode == .highSecurity && !hasBackup {
            throw AuthenticationError.backupRequired
        }

        let oldMode = currentMode
        guard newMode != oldMode else { return }

        // Step 0: Authenticate under the CURRENT mode before any Keychain modification.
        let authenticated = try await authenticator.evaluate(
            mode: oldMode,
            reason: AuthStrings.switchModeReason
        )
        guard authenticated else {
            throw AuthenticationError.failed
        }

        // Step 1: Set in-progress flag and target mode before any Keychain modifications.
        defaults.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        defaults.set(newMode.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)

        // Phase A: Create all pending items (Steps 2-3).
        // If anything fails here, old items are intact — safe to clean up pending and abort.
        do {
            let newAccessControl = try createAccessControl(for: newMode)

            // Step 2: Re-wrap each identity under temporary Keychain names.
            for fingerprint in fingerprints {
                // 2a. Load existing wrapped bundle from permanent Keychain items.
                let existingBundle = try bundleStore.loadBundle(fingerprint: fingerprint)

                // 2b. Reconstruct SE key. Passes the pre-authenticated LAContext from
                // Step 0 to avoid triggering another Face ID prompt for each key.
                let existingHandle = try secureEnclave.reconstructKey(
                    from: existingBundle.seKeyData,
                    authenticationContext: authenticator.lastEvaluatedContext
                )

                // 2c. Unwrap to get raw private key bytes.
                var rawKeyBytes = try secureEnclave.unwrap(
                    bundle: existingBundle,
                    using: existingHandle,
                    fingerprint: fingerprint
                )

                defer {
                    // 2e. Zeroize raw key bytes regardless of success or failure.
                    rawKeyBytes.resetBytes(in: rawKeyBytes.startIndex..<rawKeyBytes.endIndex)
                }

                // 2d. Generate new SE key with new access control flags and re-wrap.
                // Pass pre-authenticated LAContext so the new key's first ECDH operation
                // (in wrap()) reuses the existing Face ID session instead of prompting again.
                let newHandle = try secureEnclave.generateWrappingKey(
                    accessControl: newAccessControl,
                    authenticationContext: authenticator.lastEvaluatedContext
                )
                let newBundle = try secureEnclave.wrap(
                    privateKey: rawKeyBytes,
                    using: newHandle,
                    fingerprint: fingerprint
                )

                // 2d. Store new items under TEMPORARY (pending-*) Keychain names.
                try bundleStore.saveBundle(
                    newBundle,
                    fingerprint: fingerprint,
                    namespace: .pending
                )
            }

            // Step 3: Verify all new items stored successfully by loading each one.
            for fingerprint in fingerprints {
                _ = try bundleStore.loadBundle(
                    fingerprint: fingerprint,
                    namespace: .pending
                )
            }
        } catch {
            // Phase A failed: old items are intact. Safe to clean up pending and abort.
            fingerprints.forEach { bundleStore.cleanupPendingBundle(fingerprint: $0) }
            defaults.set(false, forKey: AuthPreferences.rewrapInProgressKey)
            defaults.removeObject(forKey: AuthPreferences.rewrapTargetModeKey)
            throw AuthenticationError.modeSwitchFailed(underlying: error)
        }

        // Phase B: Delete old items and promote pending (Steps 4-7).
        // At this point all pending items are confirmed stored. If anything fails here,
        // we must NOT clean up pending items — they may be the only copy of some keys.
        // Instead, leave the rewrapInProgress flag set so crash recovery can handle it.
        do {
            // Step 4: Delete OLD Keychain items. All new items are confirmed stored.
            for fingerprint in fingerprints {
                try bundleStore.deleteBundle(fingerprint: fingerprint)
            }

            // Step 5: Rename temporary items to permanent names (load + save + delete).
            // The SE key item is saved without Keychain-level access control because
            // the primary enforcement is at the SE level: the SE key was generated
            // in Phase A with the correct biometric/passcode flags, and
            // reconstructKey(from:) enforces those flags in hardware.
            for fingerprint in fingerprints {
                try bundleStore.promotePendingToPermanent(
                    fingerprint: fingerprint,
                    seKeyAccessControl: nil
                )
            }

            // Step 6: Persist mode preference.
            defaults.set(newMode.rawValue, forKey: AuthPreferences.authModeKey)

            // Step 7: Clear in-progress flag and target mode.
            defaults.set(false, forKey: AuthPreferences.rewrapInProgressKey)
            defaults.removeObject(forKey: AuthPreferences.rewrapTargetModeKey)

        } catch {
            // Phase B failed: some old items may already be deleted.
            // Do NOT clean up pending items — they are the only remaining copy.
            // Leave rewrapInProgress flag set so crash recovery runs on next launch.
            throw AuthenticationError.modeSwitchFailed(underlying: error)
        }
    }

    // MARK: - Crash Recovery

    /// Check for an interrupted mode switch on app launch and recover.
    ///
    /// Call this from the app's initialization path (e.g., `CypherAirApp.init`).
    ///
    /// Recovery logic:
    /// - Temporary items exist + old items exist: interrupted before deletion.
    ///   Delete temporary items. Original keys remain intact.
    /// - Old items missing + temporary items exist: interrupted after old deletion
    ///   but before rename. Promote temporary items to permanent names with
    ///   correct access control flags, and update the persisted auth mode.
    /// - Neither exists: catastrophic. Clear flag. User must restore from backup.
    func checkAndRecoverFromInterruptedRewrap(fingerprints: [String]) {
        guard defaults.bool(forKey: AuthPreferences.rewrapInProgressKey) else {
            return
        }

        // Read the target mode that was being switched to.
        // If absent (legacy data or corruption), fall back to current mode.
        let targetMode: AuthenticationMode
        if let targetRaw = defaults.string(forKey: AuthPreferences.rewrapTargetModeKey),
           let mode = AuthenticationMode(rawValue: targetRaw) {
            targetMode = mode
        } else {
            targetMode = currentMode
        }

        var anyPromotionOccurred = false

        for fingerprint in fingerprints {
            let recoveryOutcome = migrationCoordinator.recoverInterruptedMigration(
                for: fingerprint,
                seKeyAccessControl: nil
            )
            if recoveryOutcome == .promotedPending {
                anyPromotionOccurred = true
            }
        }

        // Only persist targetMode if Case 2 promotion actually occurred.
        // In Case 1, old keys are intact with the ORIGINAL mode's access control
        // flags — changing the persisted mode would create a mismatch between the
        // UI and the actual SE key ACLs. In Case 3, keys are lost entirely.
        if anyPromotionOccurred {
            defaults.set(targetMode.rawValue, forKey: AuthPreferences.authModeKey)
        }

        // Always clear the flags after recovery attempt.
        defaults.set(false, forKey: AuthPreferences.rewrapInProgressKey)
        defaults.removeObject(forKey: AuthPreferences.rewrapTargetModeKey)
    }

}

// MARK: - UserDefaults Helper

private extension UserDefaults {
    /// Check if a key has been explicitly set (distinguishes "0" from "never set").
    func contains(key: String) -> Bool {
        object(forKey: key) != nil
    }
}
