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
    private let modeSwitchAuthenticator: PrivateKeyModeSwitchAuthenticator
    private let rewrapRecoveryCoordinator: PrivateKeyRewrapRecoveryCoordinator
    private let rewrapWorkflow: PrivateKeyRewrapWorkflow
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let traceStore: AuthLifecycleTraceStore?
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
        authenticationPromptCoordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator(),
        traceStore: AuthLifecycleTraceStore? = nil,
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
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.defaults = defaults
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.traceStore = traceStore
        self.localAuthenticationPolicyEvaluator = localAuthenticationPolicyEvaluator
        self.privateKeyControlStore = privateKeyControlStore
        let bundleStore = KeyBundleStore(keychain: keychain)
        let migrationCoordinator = KeyMigrationCoordinator(bundleStore: bundleStore)
        self.bundleStore = bundleStore
        self.migrationCoordinator = migrationCoordinator
        self.modeSwitchAuthenticator = PrivateKeyModeSwitchAuthenticator(traceStore: traceStore)
        self.rewrapRecoveryCoordinator = PrivateKeyRewrapRecoveryCoordinator(
            bundleStore: bundleStore,
            migrationCoordinator: migrationCoordinator
        )
        self.rewrapWorkflow = PrivateKeyRewrapWorkflow(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore,
            traceStore: traceStore
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
                traceAppSessionPolicyAwaitStage(
                    "appSession.evaluate.policy.await.start",
                    policy: policy,
                    source: source,
                    promptID: promptID
                )
                do {
                    let success = try await evaluateLocalAuthenticationPolicyWithCallback(
                        context,
                        appSessionPolicy: policy,
                        reason: reason,
                        source: source,
                        promptID: promptID
                    )
                    traceAppSessionPolicyAwaitStage(
                        "appSession.evaluate.policy.await.finish",
                        policy: policy,
                        source: source,
                        promptID: promptID,
                        metadata: ["result": success ? "success" : "failed"]
                    )
                    return success
                } catch {
                    traceAppSessionPolicyAwaitStage(
                        "appSession.evaluate.policy.await.throw",
                        policy: policy,
                        source: source,
                        promptID: promptID,
                        metadata: AuthErrorTraceMetadata.errorMetadata(error)
                    )
                    throw error
                }
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
        } catch let error as LAError where error.code == .biometryLockout {
            traceStore?.record(
                category: .prompt,
                name: "appSession.evaluate.error",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "policy": policy.rawValue,
                        "source": source,
                        "promptID": promptID,
                        "mappedError": "appAccessBiometricsLockedOut"
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
                    "mappedError": "appAccessBiometricsLockedOut",
                    "hasContext": "false"
                ]
            )
            throw AuthenticationError.appAccessBiometricsLockedOut
        } catch let error as LAError where error.code == .biometryNotAvailable
                                         || error.code == .biometryNotEnrolled {
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

    private func evaluateLocalAuthenticationPolicyWithCallback(
        _ context: LAContext,
        appSessionPolicy policy: AppSessionAuthenticationPolicy,
        reason: String,
        source: String,
        promptID: String
    ) async throws -> Bool {
        traceAppSessionCallbackStage(
            "appSession.evaluate.callback.call.start",
            policy: policy,
            source: source,
            promptID: promptID
        )

        return try await withCheckedThrowingContinuation { continuation in
            localAuthenticationPolicyEvaluator(
                context,
                policy.localAuthenticationPolicy,
                reason
            ) { success, error in
                var metadata = Self.callbackReplyMetadata(success: success, error: error)
                self.traceAppSessionCallbackStage(
                    "appSession.evaluate.callback.reply",
                    policy: policy,
                    source: source,
                    promptID: promptID,
                    metadata: metadata
                )

                if !success && error == nil {
                    metadata["mappedError"] = "failedWithoutError"
                }
                self.traceAppSessionCallbackStage(
                    "appSession.evaluate.callback.resume",
                    policy: policy,
                    source: source,
                    promptID: promptID,
                    metadata: metadata
                )

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

    private func traceAppSessionPolicyAwaitStage(
        _ name: String,
        policy: AppSessionAuthenticationPolicy,
        source: String,
        promptID: String,
        metadata: [String: String] = [:]
    ) {
        var mergedMetadata = metadata
        mergedMetadata["policy"] = policy.rawValue
        mergedMetadata["source"] = source
        mergedMetadata["promptID"] = promptID
        mergedMetadata["isMainThread"] = Thread.isMainThread ? "true" : "false"
        traceStore?.record(
            category: .prompt,
            name: name,
            metadata: mergedMetadata
        )
    }

    private func traceAppSessionCallbackStage(
        _ name: String,
        policy: AppSessionAuthenticationPolicy,
        source: String,
        promptID: String,
        metadata: [String: String] = [:]
    ) {
        var mergedMetadata = metadata
        mergedMetadata["policy"] = policy.rawValue
        mergedMetadata["source"] = source
        mergedMetadata["promptID"] = promptID
        mergedMetadata["isMainThread"] = Thread.isMainThread ? "true" : "false"
        traceStore?.record(
            category: .prompt,
            name: name,
            metadata: mergedMetadata
        )
    }

    private static func callbackReplyMetadata(success: Bool, error: Error?) -> [String: String] {
        if success {
            return ["result": "success"]
        }

        guard let error else {
            return ["result": "failed"]
        }

        var metadata = [
            "result": "error",
            "errorType": String(describing: type(of: error))
        ]
        let nsError = error as NSError
        metadata["errorDomain"] = nsError.domain
        metadata["errorCode"] = String(nsError.code)
        if let laError = error as? LAError {
            metadata["laCode"] = String(laError.errorCode)
            metadata["laCodeName"] = String(describing: laError.code)
        }
        return metadata
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
        try await modeSwitchAuthenticator.authenticateCurrentMode(
            oldMode,
            targetMode: newMode,
            authenticator: authenticator
        )

        try rewrapWorkflow.run(
            targetMode: newMode,
            fingerprints: fingerprints,
            authenticator: authenticator,
            privateKeyControlStore: privateKeyControlStore
        )
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
    /// Recovery is phase-aware:
    /// - preparing: old + pending rolls back to the old mode by deleting pending.
    /// - commitRequired: complete pending bundles are treated as target-mode
    ///   authoritative data and are promoted/replaced before the target mode is
    ///   persisted.
    func checkAndRecoverFromInterruptedRewrap(
        fingerprints: [String]
    ) -> KeyMigrationRecoverySummary? {
        rewrapRecoveryCoordinator.checkAndRecoverFromInterruptedRewrap(
            fingerprints: fingerprints,
            privateKeyControlStore: privateKeyControlStore
        )
    }

}

// MARK: - UserDefaults Helper

private extension UserDefaults {
    /// Check if a key has been explicitly set (distinguishes "0" from "never set").
    func contains(key: String) -> Bool {
        object(forKey: key) != nil
    }
}
