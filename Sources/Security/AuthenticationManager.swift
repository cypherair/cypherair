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
            }
        }
    }

    // MARK: - Access Control Creation

    /// Create a SecAccessControl appropriate for the given authentication mode.
    ///
    /// - Standard: [.privateKeyUsage, .biometryAny, .or, .devicePasscode]
    /// - High Security: [.privateKeyUsage, .biometryAny]
    func createAccessControl(for mode: AuthenticationMode) throws -> SecAccessControl {
        let flags: SecAccessControlCreateFlags
        switch mode {
        case .standard:
            flags = [.privateKeyUsage, .biometryAny, .or, .devicePasscode]
        case .highSecurity:
            flags = [.privateKeyUsage, .biometryAny]
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

        // Step 1: Set in-progress flag before any Keychain modifications.
        defaults.set(true, forKey: AuthPreferences.rewrapInProgressKey)

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
            for fingerprint in fingerprints {
                try promoteFromPending(fingerprint: fingerprint)
            }

            // Step 6: Persist mode preference.
            defaults.set(newMode.rawValue, forKey: AuthPreferences.authModeKey)

            // Step 7: Clear in-progress flag.
            defaults.set(false, forKey: AuthPreferences.rewrapInProgressKey)

        } catch {
            // Rollback: clean up any temporary items that were created.
            cleanupPendingItems(fingerprints: fingerprints)
            defaults.set(false, forKey: AuthPreferences.rewrapInProgressKey)
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
    ///   but before rename. Promote temporary items to permanent names.
    /// - Neither exists: catastrophic. Clear flag. User must restore from backup.
    func checkAndRecoverFromInterruptedRewrap(fingerprints: [String]) {
        guard defaults.bool(forKey: AuthPreferences.rewrapInProgressKey) else {
            return
        }

        for fingerprint in fingerprints {
            let oldExists = keychain.exists(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )
            let pendingExists = keychain.exists(
                service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            )

            if oldExists && pendingExists {
                // Case 1: Interrupted before old items deleted.
                // Delete temporary items. Original keys are intact.
                cleanupPendingItems(fingerprints: [fingerprint])

            } else if !oldExists && pendingExists {
                // Case 2: Interrupted after old deletion but before rename.
                // Promote temporary items to permanent names.
                do {
                    try promoteFromPending(fingerprint: fingerprint)
                } catch {
                    // If promotion fails, the user will need to restore from backup.
                    // The pending items are still in Keychain for manual recovery.
                }

            }
            // Case 3: Neither exists — catastrophic loss. Nothing we can do here.
            // The user must restore from backup. Clear the flag below.
        }

        // Always clear the flag after recovery attempt.
        defaults.set(false, forKey: AuthPreferences.rewrapInProgressKey)
    }

    // MARK: - Private Helpers

    /// Promote pending Keychain items to permanent names for one identity.
    /// Sequence: load pending → save as permanent → delete pending.
    private func promoteFromPending(fingerprint: String) throws {
        let account = KeychainConstants.defaultAccount

        // Load pending items.
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

        // Save under permanent names.
        try keychain.save(
            seKeyData,
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            saltData,
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            sealedData,
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )

        // Delete pending items.
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
