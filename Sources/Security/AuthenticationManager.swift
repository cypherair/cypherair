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
    /// App Access biometrics-only authentication is unavailable.
    case appAccessBiometricsUnavailable
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
        case .appAccessBiometricsUnavailable:
            String(localized: "error.auth.appAccessBiometricsUnavailable",
                   defaultValue: "Biometric authentication is currently unavailable. App Access Protection cannot use Biometrics Only until biometric authentication is restored.")
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
    private enum UITestPreferences {
        static let bypassAuthenticationKey = "com.cypherair.preference.uiTestBypassAuthentication"
    }

    // MARK: - Dependencies

    private let secureEnclave: any SecureEnclaveManageable
    private let keychain: any KeychainManageable
    private let defaults: UserDefaults
    private let bundleStore: KeyBundleStore
    private let migrationCoordinator: KeyMigrationCoordinator
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let traceStore: AuthLifecycleTraceStore?
    private var privateKeyControlStore: (any PrivateKeyControlStoreProtocol)?

    // MARK: - State

    /// The LAContext from the most recent successful evaluate() call.
    /// Used by switchMode to pass a pre-authenticated context to SE key
    /// reconstruction, avoiding repeated Face ID prompts.
    private(set) var lastEvaluatedContext: LAContext?

    /// The current authentication mode when the private-key control domain is unlocked.
    var currentMode: AuthenticationMode? {
        try? privateKeyControlStore?.requireUnlockedAuthMode()
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

    func clearCachedAuthenticationContextAfterLocalDataReset() {
        lastEvaluatedContext?.invalidate()
        lastEvaluatedContext = nil
    }

    // MARK: - Init

    init(
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        defaults: UserDefaults = .standard,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator(),
        traceStore: AuthLifecycleTraceStore? = nil,
        privateKeyControlStore: (any PrivateKeyControlStoreProtocol)? = nil
    ) {
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.defaults = defaults
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.traceStore = traceStore
        self.privateKeyControlStore = privateKeyControlStore
        let bundleStore = KeyBundleStore(keychain: keychain)
        self.bundleStore = bundleStore
        self.migrationCoordinator = KeyMigrationCoordinator(bundleStore: bundleStore)
    }

    func configurePrivateKeyControlStore(_ store: any PrivateKeyControlStoreProtocol) {
        privateKeyControlStore = store
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

    func canEvaluate(appSessionPolicy: AppSessionAuthenticationPolicy) -> Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(
            appSessionPolicy.localAuthenticationPolicy,
            error: &error
        )
    }

    func evaluate(mode: AuthenticationMode, reason: String) async throws -> Bool {
        try await evaluate(mode: mode, reason: reason, source: "unspecified")
    }

    func evaluate(mode: AuthenticationMode, reason: String, source: String) async throws -> Bool {
        if defaults.bool(forKey: UITestPreferences.bypassAuthenticationKey) {
            traceStore?.record(
                category: .prompt,
                name: "privateKey.evaluate.start",
                metadata: ["mode": mode.rawValue, "source": source, "promptID": "none"]
            )
            traceStore?.record(
                category: .prompt,
                name: "privateKey.evaluate.finish",
                metadata: ["result": "bypass", "mode": mode.rawValue, "source": source, "promptID": "none"]
            )
            return true
        }

        let context = LAContext()
        var promptID = "none"
        do {
            let success = try await authenticationPromptCoordinator.withPrivacyPrompt(source: source) { promptContext in
                promptID = String(promptContext.promptID)
                traceStore?.record(
                    category: .prompt,
                    name: "privateKey.evaluate.start",
                    metadata: ["mode": mode.rawValue, "source": source, "promptID": promptID]
                )
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

                    return try await context.evaluatePolicy(
                        .deviceOwnerAuthenticationWithBiometrics,
                        localizedReason: reason
                    )
                }
            }

            traceStore?.record(
                category: .prompt,
                name: "privateKey.evaluate.finish",
                metadata: [
                    "result": success ? "success" : "failed",
                    "mode": mode.rawValue,
                    "source": source,
                    "promptID": promptID
                ]
            )
            if success {
                lastEvaluatedContext = context
            }
            return success
        } catch let error as LAError where mode == .highSecurity
                                        && (error.code == .biometryNotAvailable
                                            || error.code == .biometryNotEnrolled
                                            || error.code == .biometryLockout) {
            traceStore?.record(
                category: .prompt,
                name: "privateKey.evaluate.error",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "mode": mode.rawValue,
                        "source": source,
                        "promptID": promptID,
                        "mappedError": "biometricsUnavailable"
                    ]
                )
            )
            traceStore?.record(
                category: .prompt,
                name: "privateKey.evaluate.finish",
                metadata: [
                    "result": "error",
                    "mode": mode.rawValue,
                    "source": source,
                    "promptID": promptID,
                    "mappedError": "biometricsUnavailable"
                ]
            )
            throw AuthenticationError.biometricsUnavailable
        } catch let error as LAError where mode == .highSecurity
                                        && (error.code == .userCancel
                                            || error.code == .appCancel
                                            || error.code == .systemCancel) {
            traceStore?.record(
                category: .prompt,
                name: "privateKey.evaluate.error",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "mode": mode.rawValue,
                        "source": source,
                        "promptID": promptID,
                        "mappedError": "cancelled"
                    ]
                )
            )
            traceStore?.record(
                category: .prompt,
                name: "privateKey.evaluate.finish",
                metadata: [
                    "result": "error",
                    "mode": mode.rawValue,
                    "source": source,
                    "promptID": promptID,
                    "mappedError": "cancelled"
                ]
            )
            throw AuthenticationError.cancelled
        } catch {
            let mappedError = mode == .highSecurity ? "failed" : "unmapped"
            traceStore?.record(
                category: .prompt,
                name: "privateKey.evaluate.error",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "mode": mode.rawValue,
                        "source": source,
                        "promptID": promptID,
                        "mappedError": mappedError
                    ]
                )
            )
            traceStore?.record(
                category: .prompt,
                name: "privateKey.evaluate.finish",
                metadata: [
                    "result": "error",
                    "mode": mode.rawValue,
                    "source": source,
                    "promptID": promptID,
                    "mappedError": mappedError
                ]
            )
            if mode == .highSecurity {
                throw AuthenticationError.failed
            }
            throw error
        }
    }

    func evaluateAppSession(
        policy: AppSessionAuthenticationPolicy,
        reason: String,
        source: String = "unspecified"
    ) async throws -> AppSessionAuthenticationResult {
        if defaults.bool(forKey: UITestPreferences.bypassAuthenticationKey) {
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.start",
                metadata: ["policy": policy.rawValue, "source": source, "promptID": "none"]
            )
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.finish",
                metadata: [
                    "result": "bypass",
                    "policy": policy.rawValue,
                    "source": source,
                    "promptID": "none",
                    "hasContext": "false"
                ]
            )
            return .authenticated(context: nil)
        }

        let context = LAContext()
        policy.configure(context)
        var promptID = "none"

        do {
            let success = try await authenticationPromptCoordinator.withPrivacyPrompt(source: source) { promptContext in
                promptID = String(promptContext.promptID)
                traceStore?.record(
                    category: .prompt,
                    name: "appSession.evaluate.start",
                    metadata: ["policy": policy.rawValue, "source": source, "promptID": promptID]
                )
                return try await context.evaluatePolicy(
                    policy.localAuthenticationPolicy,
                    localizedReason: reason
                )
            }
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.finish",
                metadata: [
                    "result": success ? "success" : "failed",
                    "policy": policy.rawValue,
                    "source": source,
                    "promptID": promptID,
                    "hasContext": success ? "true" : "false"
                ]
            )
            return success ? .authenticated(context: context) : .failed
        } catch let error as LAError where error.code == .biometryNotAvailable
                                         || error.code == .biometryNotEnrolled
                                         || error.code == .biometryLockout {
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.error",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "policy": policy.rawValue,
                        "source": source,
                        "promptID": promptID,
                        "mappedError": "appAccessBiometricsUnavailable"
                    ]
                )
            )
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.finish",
                metadata: [
                    "result": "error",
                    "policy": policy.rawValue,
                    "source": source,
                    "promptID": promptID,
                    "mappedError": "appAccessBiometricsUnavailable",
                    "hasContext": "false"
                ]
            )
            throw AuthenticationError.appAccessBiometricsUnavailable
        } catch let error as LAError where error.code == .userCancel
                                         || error.code == .appCancel
                                         || error.code == .systemCancel {
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.error",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "policy": policy.rawValue,
                        "source": source,
                        "promptID": promptID,
                        "mappedError": "cancelled"
                    ]
                )
            )
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.finish",
                metadata: [
                    "result": "error",
                    "policy": policy.rawValue,
                    "source": source,
                    "promptID": promptID,
                    "mappedError": "cancelled",
                    "hasContext": "false"
                ]
            )
            throw AuthenticationError.cancelled
        } catch {
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.error",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "policy": policy.rawValue,
                        "source": source,
                        "promptID": promptID,
                        "mappedError": "failed"
                    ]
                )
            )
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.finish",
                metadata: [
                    "result": "error",
                    "policy": policy.rawValue,
                    "source": source,
                    "promptID": promptID,
                    "mappedError": "failed",
                    "hasContext": "false"
                ]
            )
            throw AuthenticationError.failed
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
        guard let privateKeyControlStore else {
            throw PrivateKeyControlError.missingStore
        }
        let oldMode = try privateKeyControlStore.requireUnlockedAuthMode()
        traceStore?.record(
            category: .operation,
            name: "privateKeyProtection.switch.start",
            metadata: [
                "currentMode": oldMode.rawValue,
                "targetMode": newMode.rawValue,
                "keyCount": String(fingerprints.count),
                "hasBackup": hasBackup ? "true" : "false"
            ]
        )

        guard !fingerprints.isEmpty else {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: ["result": "noIdentities", "targetMode": newMode.rawValue]
            )
            throw AuthenticationError.noIdentities
        }

        // Defense-in-depth: require at least one backed-up key before enabling
        // High Security mode. The UI should also warn; this is the safety net.
        if newMode == .highSecurity && !hasBackup {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: ["result": "backupRequired", "targetMode": newMode.rawValue]
            )
            throw AuthenticationError.backupRequired
        }

        guard newMode != oldMode else {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: ["result": "noChange", "targetMode": newMode.rawValue]
            )
            return
        }

        // Step 0: Authenticate under the CURRENT mode before any Keychain modification.
        traceStore?.record(
            category: .prompt,
            name: "privateKeyProtection.switch.auth.start",
            metadata: [
                "mode": oldMode.rawValue,
                "targetMode": newMode.rawValue,
                "source": "privateKeyProtection.switch"
            ]
        )
        let authenticated: Bool
        do {
            if let tracedAuthenticator = authenticator as? AuthenticationManager {
                authenticated = try await tracedAuthenticator.evaluate(
                    mode: oldMode,
                    reason: AuthStrings.switchModeReason,
                    source: "privateKeyProtection.switch"
                )
            } else {
                authenticated = try await authenticator.evaluate(
                    mode: oldMode,
                    reason: AuthStrings.switchModeReason
                )
            }
            traceStore?.record(
                category: .prompt,
                name: "privateKeyProtection.switch.auth.finish",
                metadata: [
                    "result": authenticated ? "success" : "failed",
                    "mode": oldMode.rawValue,
                    "source": "privateKeyProtection.switch"
                ]
            )
        } catch {
            traceStore?.record(
                category: .prompt,
                name: "privateKeyProtection.switch.auth.finish",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "result": "error",
                        "mode": oldMode.rawValue,
                        "source": "privateKeyProtection.switch"
                    ]
                )
            )
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: traceErrorMetadata(
                    error,
                    extra: ["result": "authError", "targetMode": newMode.rawValue]
                )
            )
            throw error
        }
        guard authenticated else {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: ["result": "authFailed", "targetMode": newMode.rawValue]
            )
            throw AuthenticationError.failed
        }

        // Step 1: Write protected rewrap journal before any Keychain modifications.
        try privateKeyControlStore.beginRewrap(targetMode: newMode)

        // Phase A: Create all pending items (Steps 2-3).
        // If anything fails here, old items are intact — safe to clean up pending and abort.
        do {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseA.start",
                metadata: ["keyCount": String(fingerprints.count), "targetMode": newMode.rawValue]
            )
            let newAccessControl = try createAccessControl(for: newMode)

            // Step 2: Re-wrap each identity under temporary Keychain names.
            for (index, fingerprint) in fingerprints.enumerated() {
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseA.key.start",
                    metadata: ["index": String(index), "keyCount": String(fingerprints.count)]
                )
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
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseA.key.finish",
                    metadata: ["index": String(index), "result": "success"]
                )
            }

            // Step 3: Verify all new items stored successfully by loading each one.
            for fingerprint in fingerprints {
                _ = try bundleStore.loadBundle(
                    fingerprint: fingerprint,
                    namespace: .pending
                )
            }

            // From this point forward Phase B may delete permanent items, so the
            // target mode must survive even if the final protected write fails.
            try privateKeyControlStore.markRewrapCommitRequired()
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseA.finish",
                metadata: ["result": "success", "keyCount": String(fingerprints.count)]
            )
        } catch {
            // Phase A failed: old items are intact. Safe to clean up pending and abort.
            fingerprints.forEach { bundleStore.cleanupPendingBundle(fingerprint: $0) }
            try? privateKeyControlStore.clearRewrapJournal()
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseA.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "failed"])
            )
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "phaseAFailed"])
            )
            throw AuthenticationError.modeSwitchFailed(underlying: error)
        }

        // Phase B: Delete old items and promote pending (Steps 4-7).
        // At this point all pending items are confirmed stored. If anything fails here,
        // we must NOT clean up pending items — they may be the only copy of some keys.
        // Instead, leave the rewrapInProgress flag set so crash recovery can handle it.
        do {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseB.start",
                metadata: ["keyCount": String(fingerprints.count), "targetMode": newMode.rawValue]
            )
            // Step 4: Delete OLD Keychain items. All new items are confirmed stored.
            for (index, fingerprint) in fingerprints.enumerated() {
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseB.delete.start",
                    metadata: ["index": String(index)]
                )
                try bundleStore.deleteBundle(fingerprint: fingerprint)
            }

            // Step 5: Rename temporary items to permanent names (load + save + delete).
            // The SE key item is saved without Keychain-level access control because
            // the primary enforcement is at the SE level: the SE key was generated
            // in Phase A with the correct biometric/passcode flags, and
            // reconstructKey(from:) enforces those flags in hardware.
            for (index, fingerprint) in fingerprints.enumerated() {
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseB.promote.start",
                    metadata: ["index": String(index)]
                )
                try bundleStore.promotePendingToPermanent(
                    fingerprint: fingerprint,
                    seKeyAccessControl: nil
                )
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseB.promote.finish",
                    metadata: ["index": String(index), "result": "success"]
                )
            }

            // Step 6: Persist the new mode and clear the protected rewrap journal.
            try privateKeyControlStore.completeRewrap(targetMode: newMode)
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseB.finish",
                metadata: ["result": "success", "keyCount": String(fingerprints.count)]
            )
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: ["result": "success", "targetMode": newMode.rawValue]
            )

        } catch {
            // Phase B failed: some old items may already be deleted.
            // Do NOT clean up pending items — they are the only remaining copy.
            // Leave rewrapInProgress flag set so crash recovery runs on next launch.
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseB.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "failed"])
            )
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "phaseBFailed"])
            )
            throw AuthenticationError.modeSwitchFailed(underlying: error)
        }
    }

    private func traceErrorMetadata(
        _ error: Error,
        extra: [String: String] = [:]
    ) -> [String: String] {
        var metadata = extra
        metadata["errorType"] = String(describing: type(of: error))
        if let laError = error as? LAError {
            metadata["laCode"] = String(laError.errorCode)
            metadata["laCodeName"] = String(describing: laError.code)
        }
        return metadata
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
    func checkAndRecoverFromInterruptedRewrap(
        fingerprints: [String]
    ) -> KeyMigrationRecoverySummary? {
        guard let privateKeyControlStore,
              let journal = try? privateKeyControlStore.recoveryJournal(),
              let targetMode = journal.rewrapTargetMode else {
            return nil
        }

        let recoverySummary = migrationCoordinator.recoverInterruptedMigrations(
            for: fingerprints,
            seKeyAccessControl: nil
        )

        // If the metadata set is empty but a recovery flag was present, we cannot
        // identify which bundles need recovery. Treat that as unrecoverable.
        let effectiveSummary: KeyMigrationRecoverySummary
        if fingerprints.isEmpty {
            effectiveSummary = KeyMigrationRecoverySummary(outcomes: [.unrecoverable])
        } else {
            effectiveSummary = recoverySummary
        }

        // Persist target mode when recovery promoted pending bundles, or when a
        // prior run already crossed the Phase B commit point and only the final
        // protected payload write remains.
        let shouldCompleteRewrap = effectiveSummary.shouldUpdateAuthMode
            || (journal.rewrapPhase == .commitRequired && effectiveSummary.isNoActionSafeOnly)

        if shouldCompleteRewrap {
            do {
                try privateKeyControlStore.completeRewrap(targetMode: targetMode)
            } catch {
                return effectiveSummary.appendingRetryableFailure()
            }
        } else if effectiveSummary.shouldClearRecoveryFlag {
            try? privateKeyControlStore.clearRewrapJournal()
        }

        return effectiveSummary
    }

}

// MARK: - UserDefaults Helper

private extension UserDefaults {
    /// Check if a key has been explicitly set (distinguishes "0" from "never set").
    func contains(key: String) -> Bool {
        object(forKey: key) != nil
    }
}
