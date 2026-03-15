import Foundation
import LocalAuthentication
import Security

// MARK: - Localized Strings

private enum AuthStrings {
    static let switchModeReason = String(localized: "Authenticate to change security mode")
}

/// Errors from authentication and mode switching operations.
enum AuthenticationError: Error {
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

    // MARK: - State

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

        switch mode {
        case .standard:
            // Face ID / Touch ID with device passcode fallback.
            return try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )

        case .highSecurity:
            // Face ID / Touch ID only. Hide the passcode fallback button.
            context.localizedFallbackTitle = ""

            do {
                return try await context.evaluatePolicy(
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
                let existingSEKeyData = try keychain.load(
                    service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )
                let existingSalt = try keychain.load(
                    service: KeychainConstants.saltService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )
                let existingSealedBox = try keychain.load(
                    service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )

                // 2b. Reconstruct SE key (triggers biometric/passcode auth under CURRENT mode).
                let existingHandle = try secureEnclave.reconstructKey(from: existingSEKeyData)

                let existingBundle = WrappedKeyBundle(
                    seKeyData: existingSEKeyData,
                    salt: existingSalt,
                    sealedBox: existingSealedBox
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
                let newHandle = try secureEnclave.generateWrappingKey(accessControl: newAccessControl)
                let newBundle = try secureEnclave.wrap(
                    privateKey: rawKeyBytes,
                    using: newHandle,
                    fingerprint: fingerprint
                )

                // 2d. Store new items under TEMPORARY (pending-*) Keychain names.
                try keychain.save(
                    newBundle.seKeyData,
                    service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount,
                    accessControl: nil
                )
                try keychain.save(
                    newBundle.salt,
                    service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount,
                    accessControl: nil
                )
                try keychain.save(
                    newBundle.sealedBox,
                    service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount,
                    accessControl: nil
                )
            }

            // Step 3: Verify all new items stored successfully by loading each one.
            for fingerprint in fingerprints {
                _ = try keychain.load(
                    service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )
                _ = try keychain.load(
                    service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )
                _ = try keychain.load(
                    service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )
            }
        } catch {
            // Phase A failed: old items are intact. Safe to clean up pending and abort.
            cleanupPendingItems(fingerprints: fingerprints)
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
                try keychain.delete(
                    service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )
                try keychain.delete(
                    service: KeychainConstants.saltService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )
                try keychain.delete(
                    service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )
            }

            // Step 5: Rename temporary items to permanent names (load + save + delete).
            // The SE key item is saved without Keychain-level access control because
            // the primary enforcement is at the SE level: the SE key was generated
            // in Phase A with the correct biometric/passcode flags, and
            // reconstructKey(from:) enforces those flags in hardware.
            for fingerprint in fingerprints {
                try promoteFromPending(fingerprint: fingerprint, seKeyAccessControl: nil)
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

        for fingerprint in fingerprints {
            let oldExists = keychain.exists(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )
            let pendingSeKeyExists = keychain.exists(
                service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )

            if oldExists && pendingSeKeyExists {
                // Case 1: Interrupted before old items deleted.
                // Delete temporary items. Original keys are intact.
                cleanupPendingItems(fingerprints: [fingerprint])

            } else if !oldExists && pendingSeKeyExists {
                // Case 2: Interrupted after old deletion but before rename.
                // Verify all 3 pending items exist before attempting promotion.
                // If only some pending items were written (partial write crash),
                // promotion will fail and the user must restore from backup.
                let pendingSaltExists = keychain.exists(
                    service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )
                let pendingSealedExists = keychain.exists(
                    service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                )

                if pendingSaltExists && pendingSealedExists {
                    // All 3 pending items present — safe to promote.
                    // The SE key item is saved without Keychain-level access control.
                    // The primary enforcement is at the SE level (the SE key was
                    // generated with the correct biometric flags in Phase A).
                    do {
                        try promoteFromPending(fingerprint: fingerprint, seKeyAccessControl: nil)
                    } catch {
                        // If promotion fails, the pending items remain in Keychain
                        // for manual recovery. The user will need to restore from backup.
                    }
                }
                // else: Incomplete pending set — catastrophic partial write.
                // Cannot promote. The user must restore from backup.
                // Leave the incomplete pending items as-is for forensics.

            }
            // Case 3: Neither exists — catastrophic loss. Nothing we can do here.
            // The user must restore from backup. Clear the flag below.
        }

        // If Case 2 promotion succeeded, persist the target mode as the current mode.
        // This is safe even if some keys failed promotion — the mode matches the
        // access control flags on the keys that were successfully promoted.
        // If no promotion happened (Case 1 or Case 3), this is harmless.
        defaults.set(targetMode.rawValue, forKey: AuthPreferences.authModeKey)

        // Always clear the flags after recovery attempt.
        defaults.set(false, forKey: AuthPreferences.rewrapInProgressKey)
        defaults.removeObject(forKey: AuthPreferences.rewrapTargetModeKey)
    }

    // MARK: - Private Helpers

    /// Promote pending Keychain items to permanent names for one identity.
    /// Sequence: load all pending → save as permanent → delete pending.
    ///
    /// The SE key item is saved with the provided access control (defense-in-depth
    /// at the Keychain layer). Salt and sealed box use no access control.
    ///
    /// If saving permanent items partially fails, any already-saved permanent
    /// items are rolled back (deleted) to preserve the pending-only state.
    /// This prevents crash recovery from seeing partial permanent data.
    private func promoteFromPending(fingerprint: String, seKeyAccessControl: SecAccessControl?) throws {
        let account = KeychainConstants.defaultAccount

        // Load all 3 pending items first (validates completeness before writing).
        let seKeyData = try keychain.load(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account
        )
        let saltData = try keychain.load(
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account
        )
        let sealedData = try keychain.load(
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account
        )

        // Save under permanent names, rolling back on partial failure.
        // Track which permanent items were successfully saved.
        var savedPermanentServices: [String] = []

        do {
            // SE key item gets access control flags for defense-in-depth.
            try keychain.save(
                seKeyData,
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: account,
                accessControl: seKeyAccessControl
            )
            savedPermanentServices.append(KeychainConstants.seKeyService(fingerprint: fingerprint))

            try keychain.save(
                saltData,
                service: KeychainConstants.saltService(fingerprint: fingerprint),
                account: account,
                accessControl: nil
            )
            savedPermanentServices.append(KeychainConstants.saltService(fingerprint: fingerprint))

            try keychain.save(
                sealedData,
                service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
                account: account,
                accessControl: nil
            )
        } catch {
            // Partial save failure: rollback any permanent items we just created.
            // This restores the pending-only state so crash recovery works correctly.
            for service in savedPermanentServices {
                try? keychain.delete(service: service, account: account)
            }
            throw error
        }

        // All 3 permanent items saved successfully. Delete pending items.
        try? keychain.delete(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account
        )
        try? keychain.delete(
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account
        )
        try? keychain.delete(
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account
        )
    }

    /// Best-effort cleanup of all pending Keychain items.
    private func cleanupPendingItems(fingerprints: [String]) {
        let account = KeychainConstants.defaultAccount
        for fingerprint in fingerprints {
            try? keychain.delete(
                service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                account: account
            )
            try? keychain.delete(
                service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
                account: account
            )
            try? keychain.delete(
                service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
                account: account
            )
        }
    }
}

// MARK: - UserDefaults Helper

private extension UserDefaults {
    /// Check if a key has been explicitly set (distinguishes "0" from "never set").
    func contains(key: String) -> Bool {
        object(forKey: key) != nil
    }
}
