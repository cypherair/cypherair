import Foundation
import LocalAuthentication
import Security

// LAContext may reply off-main; this box only forwards that single callback.
private final class LocalAuthenticationPolicyReplyBox: @unchecked Sendable {
    private let reply: (Bool, Error?) -> Void

    init(_ reply: @escaping (Bool, Error?) -> Void) {
        self.reply = reply
    }

    func callAsFunction(_ success: Bool, _ error: Error?) {
        reply(success, error)
    }
}

/// Errors from authentication and mode switching operations.
enum AuthenticationError: Error, LocalizedError {
    /// Biometric authentication is not available (sensor damaged, locked out, etc.).
    case biometricsUnavailable
    /// App Access biometrics-only authentication is unavailable.
    case appAccessBiometricsUnavailable
    /// App Access biometrics-only authentication is locked out by the system.
    case appAccessBiometricsLockedOut
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
        case .appAccessBiometricsLockedOut:
            String(localized: "error.auth.appAccessBiometricsLockedOut",
                   defaultValue: "Biometric authentication is locked by the system. App Access Protection cannot use Biometrics Only until biometric authentication is restored.")
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
                   defaultValue: "No portable private keys found. Generate or import a portable key first.")
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
/// See SECURITY.md Section 4 and Section 10.
@Observable
final class AuthenticationManager: AuthenticationEvaluable {
    private enum UITestPreferences {
        static let bypassAuthenticationKey = "com.cypherair.preference.uiTestBypassAuthentication"
    }

    // MARK: - Dependencies

    private let defaults: UserDefaults
    private let allowsUITestAuthenticationBypass: Bool
    private let modeSwitchAuthenticator: PrivateKeyModeSwitchAuthenticator
    private let rewrapRecoveryCoordinator: PrivateKeyRewrapRecoveryCoordinator
    private let rewrapWorkflow: PrivateKeyRewrapWorkflow
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    /// The app-wide prompt coordinator, exposed so user-action owners can enroll
    /// only the authentication sheet and immediate authenticated Keychain/Secure
    /// Enclave window. Long-running action work must stay outside this session
    /// so genuine macOS away events still lock immediately at grace period 0.
    var promptCoordinator: AuthenticationPromptCoordinator {
        authenticationPromptCoordinator
    }
    private let localAuthenticationPolicyEvaluator: (
        LAContext,
        LAPolicy,
        String,
        @escaping (Bool, Error?) -> Void
    ) -> Void
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

    func clearCachedAuthenticationContextAfterLocalDataReset() {
        lastEvaluatedContext?.invalidate()
        lastEvaluatedContext = nil
    }

    // MARK: - Init

    init(
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        defaults: UserDefaults = .standard,
        allowsUITestAuthenticationBypass: Bool = false,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        privateKeyControlStore: (any PrivateKeyControlStoreProtocol)? = nil,
        localAuthenticationPolicyEvaluator: @escaping (
            LAContext,
            LAPolicy,
            String,
            @escaping (Bool, Error?) -> Void
        ) -> Void = { context, policy, reason, reply in
            let replyBox = LocalAuthenticationPolicyReplyBox(reply)
            context.evaluatePolicy(policy, localizedReason: reason) { success, error in
                replyBox(success, error)
            }
        }
    ) {
        self.defaults = defaults
        self.allowsUITestAuthenticationBypass = allowsUITestAuthenticationBypass
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.localAuthenticationPolicyEvaluator = localAuthenticationPolicyEvaluator
        self.privateKeyControlStore = privateKeyControlStore
        let bundleStore = KeyBundleStore(keychain: keychain)
        let rewrapRecoveryStrategy = PrivateKeyRewrapRecoveryStrategy(bundleStore: bundleStore)
        self.modeSwitchAuthenticator = PrivateKeyModeSwitchAuthenticator()
        self.rewrapRecoveryCoordinator = PrivateKeyRewrapRecoveryCoordinator(
            bundleStore: bundleStore,
            rewrapRecoveryStrategy: rewrapRecoveryStrategy
        )
        self.rewrapWorkflow = PrivateKeyRewrapWorkflow(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore,
            authenticationPromptCoordinator: authenticationPromptCoordinator
        )
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
        if isUITestAuthenticationBypassEnabled {
            return true
        }

        let context = LAContext()
        do {
            let success = try await authenticationPromptCoordinator.withPrivacyPrompt(source: source) { _ in
                let policy: LAPolicy
                switch mode {
                case .standard:
                    // Face ID / Touch ID with device passcode fallback.
                    policy = .deviceOwnerAuthentication

                case .highSecurity:
                    // Face ID / Touch ID only. Hide the passcode fallback button.
                    context.localizedFallbackTitle = ""
                    policy = .deviceOwnerAuthenticationWithBiometrics
                }

                return try await evaluateLocalAuthenticationPolicy(
                    context,
                    policy: policy,
                    reason: reason
                )
            }

            if success {
                lastEvaluatedContext = context
            }
            return success
        } catch let error as LAError where mode == .highSecurity
                                        && (error.code == .biometryNotAvailable
                                            || error.code == .biometryNotEnrolled
                                            || error.code == .biometryLockout) {
            throw AuthenticationError.biometricsUnavailable
        } catch let error as LAError where mode == .highSecurity
                                        && (error.code == .userCancel
                                            || error.code == .appCancel
                                            || error.code == .systemCancel) {
            throw AuthenticationError.cancelled
        } catch {
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
        if isUITestAuthenticationBypassEnabled {
            return .authenticated(context: nil)
        }

        let context = LAContext()
        policy.configure(context)

        do {
            let success = try await authenticationPromptCoordinator.withPrivacyPrompt(source: source) { _ in
                try await evaluateLocalAuthenticationPolicyWithCallback(
                    context,
                    appSessionPolicy: policy,
                    reason: reason
                )
            }
            return success ? .authenticated(context: context) : .failed
        } catch let error as LAError where error.code == .biometryLockout {
            throw AuthenticationError.appAccessBiometricsLockedOut
        } catch let error as LAError where error.code == .biometryNotAvailable
                                         || error.code == .biometryNotEnrolled {
            throw AuthenticationError.appAccessBiometricsUnavailable
        } catch let error as LAError where error.code == .userCancel
                                         || error.code == .appCancel
                                         || error.code == .systemCancel {
            throw AuthenticationError.cancelled
        } catch {
            throw AuthenticationError.failed
        }
    }

    private var isUITestAuthenticationBypassEnabled: Bool {
        allowsUITestAuthenticationBypass && defaults.bool(forKey: UITestPreferences.bypassAuthenticationKey)
    }

    private func evaluateLocalAuthenticationPolicy(
        _ context: LAContext,
        policy: LAPolicy,
        reason: String
    ) async throws -> Bool {
        try await withCheckedThrowingContinuation { continuation in
            localAuthenticationPolicyEvaluator(
                context,
                policy,
                reason
            ) { success, error in
                if success {
                    continuation.resume(returning: true)
                } else if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(throwing: AuthenticationError.failed)
                }
            }
        }
    }

    private func evaluateLocalAuthenticationPolicyWithCallback(
        _ context: LAContext,
        appSessionPolicy policy: AppSessionAuthenticationPolicy,
        reason: String
    ) async throws -> Bool {
        try await evaluateLocalAuthenticationPolicy(
            context,
            policy: policy.localAuthenticationPolicy,
            reason: reason
        )
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
    ///   - fingerprints: Software-custody identity fingerprints (lowercase hex)
    ///     that have SE-wrapped private-key bundles. Device-bound Secure Enclave
    ///     custody keys have no bundle to re-wrap and must not be passed; a
    ///     device-bound-only population yields an empty list and the switch
    ///     fails closed with `noIdentities`.
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
        try await performSwitchMode(
            to: newMode,
            fingerprints: fingerprints,
            hasBackup: hasBackup,
            authenticator: authenticator
        )
    }

    private func performSwitchMode(
        to newMode: AuthenticationMode,
        fingerprints: [String],
        hasBackup: Bool,
        authenticator: any AuthenticationEvaluable
    ) async throws {
        guard let privateKeyControlStore else {
            throw PrivateKeyControlError.missingStore
        }
        let oldMode = try privateKeyControlStore.requireUnlockedAuthMode()

        guard !fingerprints.isEmpty else {
            throw AuthenticationError.noIdentities
        }

        // Defense-in-depth: require at least one backed-up key before enabling
        // High Security mode. The UI should also warn; this is the safety net.
        if newMode == .highSecurity && !hasBackup {
            throw AuthenticationError.backupRequired
        }

        guard newMode != oldMode else {
            return
        }

        // Step 0: Authenticate under the CURRENT mode before any Keychain modification.
        try await authenticationPromptCoordinator.withOperationPrompt(
            source: "privateKeyProtection.switch.authenticate"
        ) {
            try await modeSwitchAuthenticator.authenticateCurrentMode(
                oldMode,
                authenticator: authenticator
            )
        }

        try await rewrapWorkflow.run(
            targetMode: newMode,
            fingerprints: fingerprints,
            authenticator: authenticator,
            privateKeyControlStore: privateKeyControlStore
        )
    }

    // MARK: - Crash Recovery

    /// Check for an interrupted mode switch on app launch and recover.
    ///
    /// Call this from the app's initialization path (e.g., `CypherAirApp.init`).
    ///
    /// Recovery is phase-aware:
    /// - preparing: old + pending rolls back to the old mode by deleting pending.
    /// - commitRequired: complete pending bundles are treated as target-mode
    ///   authoritative data and are promoted/replaced before the target mode is
    ///   persisted.
    ///
    /// `fingerprints` must contain software-custody identities only (the keys
    /// with SE-wrapped bundles). A bundleless fingerprint — e.g. a device-bound
    /// Secure Enclave custody key — classifies as unrecoverable and blocks
    /// target-mode persistence while the journal is cleared.
    func checkAndRecoverFromInterruptedRewrap(
        fingerprints: [String]
    ) -> PrivateKeyRewrapRecoverySummary? {
        rewrapRecoveryCoordinator.checkAndRecoverFromInterruptedRewrap(
            fingerprints: fingerprints,
            privateKeyControlStore: privateKeyControlStore
        )
    }

}
