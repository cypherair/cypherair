import Foundation
import LocalAuthentication

@Observable
final class AppSessionOrchestrator {
    private let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    private let currentRegistryProvider: () throws -> ProtectedDataRegistry
    private let shouldBypassPrivacyAuthentication: () -> Bool
    private let gracePeriodProvider: () -> Int?
    private let evaluateAppAuthentication: (String, String) async throws -> AppSessionAuthenticationResult
    private let postAuthenticationHandler: (LAContext?, String) async -> Void
    private let contentClearHandler: () -> Void
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let traceStore: AuthLifecycleTraceStore?

    private var hasAppearedOnce = false
    private var pendingAuthenticatedContext: LAContext?
    private var isAuthenticationSettleBlurActive = false

    var isPrivacyScreenBlurred = false
    var isAuthenticating = false
    var authFailed = false
    private(set) var authenticationFailureReason: AppSessionAuthenticationFailureReason?
    private(set) var contentClearGeneration = 0
    private(set) var postAuthenticationGeneration = 0
    private(set) var lastAuthenticationDate: Date?

    convenience init(
        currentRegistryProvider: @escaping () throws -> ProtectedDataRegistry,
        shouldBypassPrivacyAuthentication: @escaping () -> Bool = { false },
        gracePeriodProvider: @escaping () -> Int?,
        evaluateAppAuthentication: @escaping (String) async throws -> AppSessionAuthenticationResult,
        postAuthenticationHandler: @escaping (LAContext?, String) async -> Void = { _, _ in },
        contentClearHandler: @escaping () -> Void = {},
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator(),
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.init(
            currentRegistryProvider: currentRegistryProvider,
            shouldBypassPrivacyAuthentication: shouldBypassPrivacyAuthentication,
            gracePeriodProvider: gracePeriodProvider,
            evaluateAppAuthenticationWithSource: { reason, _ in
                try await evaluateAppAuthentication(reason)
            },
            postAuthenticationHandler: postAuthenticationHandler,
            contentClearHandler: contentClearHandler,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            traceStore: traceStore
        )
    }

    init(
        currentRegistryProvider: @escaping () throws -> ProtectedDataRegistry,
        shouldBypassPrivacyAuthentication: @escaping () -> Bool = { false },
        gracePeriodProvider: @escaping () -> Int?,
        evaluateAppAuthenticationWithSource: @escaping (String, String) async throws -> AppSessionAuthenticationResult,
        postAuthenticationHandler: @escaping (LAContext?, String) async -> Void = { _, _ in },
        contentClearHandler: @escaping () -> Void = {},
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator(),
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.currentRegistryProvider = currentRegistryProvider
        self.shouldBypassPrivacyAuthentication = shouldBypassPrivacyAuthentication
        self.gracePeriodProvider = gracePeriodProvider
        self.evaluateAppAuthentication = evaluateAppAuthenticationWithSource
        self.postAuthenticationHandler = postAuthenticationHandler
        self.contentClearHandler = contentClearHandler
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.traceStore = traceStore
    }

    func recordAuthentication() {
        clearAuthenticationFailure()
        lastAuthenticationDate = Date()
        traceStore?.record(
            category: .session,
            name: "session.recordAuthentication",
            metadata: ["hasPendingContext": pendingAuthenticatedContext == nil ? "false" : "true"]
        )
    }

    func requestContentClear() {
        clearAuthenticationSettleBlur()
        clearAuthenticationFailure()
        discardPendingAuthenticatedContext(reason: "contentClear")
        contentClearHandler()
        contentClearGeneration += 1
        traceStore?.record(
            category: .session,
            name: "session.requestContentClear",
            metadata: ["generation": String(contentClearGeneration)]
        )
    }

    func resetAfterLocalDataReset(preserveAuthentication: Bool = false) {
        clearAuthenticationSettleBlur()
        discardPendingAuthenticatedContext(reason: "localDataReset")
        lastAuthenticationDate = preserveAuthentication ? Date() : nil
        isAuthenticating = false
        isPrivacyScreenBlurred = false
        authFailed = false
        clearAuthenticationFailure()
        contentClearGeneration += 1
        traceStore?.record(
            category: .session,
            name: "session.localDataReset",
            metadata: [
                "contentClearGeneration": String(contentClearGeneration),
                "preservedAuthentication": preserveAuthentication ? "true" : "false"
            ]
        )
    }

    var isOperationAuthenticationPromptInProgress: Bool {
        authenticationPromptCoordinator.isOperationPromptInProgress
    }

    var operationAuthenticationAttemptGeneration: UInt64 {
        authenticationPromptCoordinator.operationPromptAttemptGeneration
    }

    var hasProtectedDataAuthorizationHandoffContext: Bool {
        pendingAuthenticatedContext != nil
    }

    func discardProtectedDataAuthorizationHandoffContextForPolicyChange() {
        discardPendingAuthenticatedContext(reason: "appAccessPolicyChange")
    }

    var isGracePeriodExpired: Bool {
        guard let lastAuthenticationDate else {
            return true
        }
        return Date().timeIntervalSince(lastAuthenticationDate) > TimeInterval(effectiveGracePeriod())
    }

    @discardableResult
    func handleInitialAppearance(
        localizedReason: String,
        source: String = "initialAppearance"
    ) async -> Bool {
        traceStore?.record(
            category: .session,
            name: "session.handleInitialAppearance.enter",
            metadata: ["source": source]
        )
        guard !hasAppearedOnce else {
            traceStore?.record(
                category: .session,
                name: "session.handleInitialAppearance.exit",
                metadata: ["reason": "alreadyAppeared", "source": source]
            )
            return false
        }
        hasAppearedOnce = true

        if shouldBypassPrivacyAuthentication() {
            clearAuthenticationSettleBlur()
            authFailed = false
            clearAuthenticationFailure()
            isPrivacyScreenBlurred = false
            traceStore?.record(
                category: .session,
                name: "session.handleInitialAppearance.exit",
                metadata: ["reason": "bypass", "source": source]
            )
            return false
        }

        clearAuthenticationSettleBlur()
        clearAuthenticationFailure()
        isPrivacyScreenBlurred = true
        traceStore?.record(
            category: .session,
            name: "session.handleInitialAppearance.exit",
            metadata: ["reason": "delegatedToResume", "source": source]
        )
        return await handleResume(localizedReason: localizedReason, source: source)
    }

    func handleSceneDidResignActive() {
        guard !isOperationAuthenticationPromptInProgress else {
            traceStore?.record(
                category: .session,
                name: "session.handleSceneDidResignActive",
                metadata: ["result": "ignoredForOperationPrompt"]
            )
            return
        }
        clearAuthenticationSettleBlur()
        discardPendingAuthenticatedContext(reason: "sceneResignActive")
        clearAuthenticationFailure()
        isPrivacyScreenBlurred = true
        authFailed = false
        traceStore?.record(
            category: .session,
            name: "session.handleSceneDidResignActive",
            metadata: ["result": "handled"]
        )
    }

    func handleSceneDidEnterBackground() {
        clearAuthenticationSettleBlur()
        discardPendingAuthenticatedContext(reason: "sceneBackground")
        clearAuthenticationFailure()
        isPrivacyScreenBlurred = true
        authFailed = false
        traceStore?.record(
            category: .session,
            name: "session.handleSceneDidEnterBackground",
            metadata: ["result": "handled"]
        )
    }

    @discardableResult
    func handleResume(
        localizedReason: String,
        source: String = "unspecified"
    ) async -> Bool {
        traceStore?.record(
            category: .session,
            name: "session.handleResume.enter",
            metadata: [
                "source": source,
                "operationPrompt": isOperationAuthenticationPromptInProgress ? "true" : "false",
                "isAuthenticating": isAuthenticating ? "true" : "false",
                "hasLastAuthenticationDate": lastAuthenticationDate == nil ? "false" : "true"
            ]
        )
        if shouldBypassPrivacyAuthentication() {
            clearAuthenticationSettleBlur()
            authFailed = false
            clearAuthenticationFailure()
            isPrivacyScreenBlurred = false
            traceStore?.record(
                category: .session,
                name: "session.handleResume.exit",
                metadata: ["reason": "bypass", "attemptedAuthentication": "false", "source": source]
            )
            return false
        }

        guard !isOperationAuthenticationPromptInProgress else {
            traceStore?.record(
                category: .session,
                name: "session.handleResume.exit",
                metadata: ["reason": "operationPromptInProgress", "attemptedAuthentication": "false", "source": source]
            )
            return false
        }

        guard !isAuthenticating else {
            traceStore?.record(
                category: .session,
                name: "session.handleResume.exit",
                metadata: ["reason": "alreadyAuthenticating", "attemptedAuthentication": "false", "source": source]
            )
            return false
        }

        let gracePeriod = effectiveGracePeriod()
        let graceExpired = isGracePeriodExpired
        if gracePeriod == 0 || graceExpired {
            traceStore?.record(
                category: .session,
                name: "session.handleResume.reauthRequired",
                metadata: [
                    "gracePeriod": String(gracePeriod),
                    "graceAvailable": gracePeriodProvider() == nil ? "false" : "true",
                    "graceExpired": graceExpired ? "true" : "false",
                    "source": source
                ]
            )
            requestContentClear()
            await protectedDataSessionCoordinator.relockCurrentSession()

            clearAuthenticationSettleBlur()
            isAuthenticating = true
            authFailed = false
            clearAuthenticationFailure()
            isPrivacyScreenBlurred = true
            defer { isAuthenticating = false }

            do {
                traceHandleResumeStage(
                    "session.handleResume.evaluate.start",
                    source: source
                )
                let result = try await evaluateAppAuthentication(localizedReason, source)
                traceHandleResumeStage(
                    "session.handleResume.evaluate.finish",
                    source: source,
                    metadata: [
                        "result": result.isAuthenticated ? "authenticated" : "failed",
                        "hasContext": result.context == nil ? "false" : "true"
                    ]
                )
                if result.isAuthenticated {
                    replacePendingAuthenticatedContext(with: result.context, reason: "resumeAuthenticated")
                    recordAuthentication()
                    traceHandleResumeStage(
                        "session.handleResume.postAuth.start",
                        source: source,
                        metadata: ["hasContext": result.context == nil ? "false" : "true"]
                    )
                    await postAuthenticationHandler(
                        borrowAuthenticatedContextForMetadataMigration(),
                        source
                    )
                    traceHandleResumeStage(
                        "session.handleResume.postAuth.finish",
                        source: source
                    )
                    recordPostAuthenticationCompletion(source: source)
                    authFailed = false
                    clearAuthenticationSettleBlur()
                    clearAuthenticationFailure()
                    isPrivacyScreenBlurred = false
                    traceStore?.record(
                        category: .session,
                        name: "session.handleResume.exit",
                        metadata: ["reason": "authenticated", "attemptedAuthentication": "true", "source": source]
                    )
                } else {
                    discardPendingAuthenticatedContext(reason: "resumeReturnedFalse")
                    clearAuthenticationSettleBlur()
                    authFailed = true
                    setAuthenticationFailureReason(.authenticationFailed, source: source)
                    traceStore?.record(
                        category: .session,
                        name: "session.handleResume.exit",
                        metadata: ["reason": "authenticationReturnedFalse", "attemptedAuthentication": "true", "source": source]
                    )
                }
            } catch {
                traceHandleResumeStage(
                    "session.handleResume.evaluate.throw",
                    source: source,
                    metadata: AuthErrorTraceMetadata.errorMetadata(error)
                )
                discardPendingAuthenticatedContext(reason: "resumeThrew")
                clearAuthenticationSettleBlur()
                authFailed = true
                let failureReason = authenticationFailureReason(for: error)
                setAuthenticationFailureReason(failureReason, source: source)
                traceStore?.record(
                    category: .session,
                    name: "session.handleResume.exit",
                    metadata: [
                        "reason": "authenticationThrew",
                        "attemptedAuthentication": "true",
                        "source": source,
                        "errorType": String(describing: type(of: error)),
                        "failureReason": failureReason.rawValue
                    ]
                )
            }
            return true
        } else {
            clearAuthenticationSettleBlur()
            authFailed = false
            clearAuthenticationFailure()
            isPrivacyScreenBlurred = false
            traceStore?.record(
                category: .session,
                name: "session.handleResume.exit",
                metadata: ["reason": "graceValid", "attemptedAuthentication": "false", "source": source]
            )
            return false
        }
    }

    private func traceHandleResumeStage(
        _ name: String,
        source: String,
        metadata: [String: String] = [:]
    ) {
        var mergedMetadata = metadata
        mergedMetadata["source"] = source
        traceStore?.record(
            category: .session,
            name: name,
            metadata: mergedMetadata
        )
    }

    private func effectiveGracePeriod() -> Int {
        gracePeriodProvider() ?? 0
    }

    func handleAuthenticationSettleInactive(source: String = "authenticationSettle") {
        isAuthenticationSettleBlurActive = true
        isPrivacyScreenBlurred = true
        traceStore?.record(
            category: .session,
            name: "session.authenticationSettle.inactive",
            metadata: [
                "source": source,
                "result": "blurred",
                "authFailed": authFailed ? "true" : "false",
                "isAuthenticating": isAuthenticating ? "true" : "false"
            ]
        )
    }

    func handleAuthenticationSettleActive(source: String = "authenticationSettle") {
        guard isAuthenticationSettleBlurActive else {
            traceStore?.record(
                category: .session,
                name: "session.authenticationSettle.active",
                metadata: [
                    "source": source,
                    "result": "ignored",
                    "authFailed": authFailed ? "true" : "false",
                    "isAuthenticating": isAuthenticating ? "true" : "false"
                ]
            )
            return
        }

        isAuthenticationSettleBlurActive = false
        let result: String
        if authFailed {
            result = "keptForAuthFailure"
        } else if isAuthenticating {
            result = "keptForAuthentication"
        } else {
            isPrivacyScreenBlurred = false
            result = "hidden"
        }

        traceStore?.record(
            category: .session,
            name: "session.authenticationSettle.active",
            metadata: [
                "source": source,
                "result": result,
                "authFailed": authFailed ? "true" : "false",
                "isAuthenticating": isAuthenticating ? "true" : "false"
            ]
        )
    }

    private func clearAuthenticationSettleBlur() {
        isAuthenticationSettleBlurActive = false
    }

    @discardableResult
    func retryPrivacyUnlock(
        localizedReason: String,
        source: String = "retryButton"
    ) async -> Bool {
        traceStore?.record(
            category: .session,
            name: "session.retryPrivacyUnlock",
            metadata: ["source": source]
        )
        return await handleResume(localizedReason: localizedReason, source: source)
    }

    func consumeAuthenticatedContextForProtectedData() -> LAContext? {
        let context = pendingAuthenticatedContext
        pendingAuthenticatedContext = nil
        traceStore?.record(
            category: .session,
            name: "session.consumeAuthenticatedContext",
            metadata: [
                "hadContext": context == nil ? "false" : "true",
                "remainingContext": pendingAuthenticatedContext == nil ? "false" : "true"
            ]
        )
        return context
    }

    func borrowAuthenticatedContextForMetadataMigration() -> LAContext? {
        traceStore?.record(
            category: .session,
            name: "session.borrowAuthenticatedContext",
            metadata: [
                "purpose": "metadataMigration",
                "hasContext": pendingAuthenticatedContext == nil ? "false" : "true"
            ]
        )
        return pendingAuthenticatedContext
    }

    func evaluateProtectedDataAccessGate(
        startupBootstrapOutcome: ProtectedDataBootstrapOutcome,
        isFirstProtectedAccessInCurrentProcess: Bool
    ) -> ProtectedDataAccessGateDecision {
        let bootstrapOutcome: ProtectedDataBootstrapOutcome
        if isFirstProtectedAccessInCurrentProcess {
            bootstrapOutcome = startupBootstrapOutcome
        } else {
            do {
                let registry = try currentRegistryProvider()
                bootstrapOutcome = .loadedRegistry(
                    registry: registry,
                    recoveryDisposition: registry.classifyRecoveryDisposition()
                )
            } catch {
                return .frameworkRecoveryNeeded
            }
        }

        switch bootstrapOutcome {
        case .frameworkRecoveryNeeded:
            return .frameworkRecoveryNeeded
        case .emptySteadyState:
            return .noProtectedDomainPresent
        case .loadedRegistry(let registry, let recoveryDisposition):
            switch recoveryDisposition {
            case .frameworkRecoveryNeeded:
                return .frameworkRecoveryNeeded
            case .continuePendingMutation:
                return .pendingMutationRecoveryRequired
            case .resumeSteadyState:
                if registry.committedMembership.isEmpty && registry.sharedResourceLifecycleState == .absent {
                    return .noProtectedDomainPresent
                }
                switch protectedDataSessionCoordinator.frameworkState {
                case .frameworkRecoveryNeeded, .restartRequired:
                    return .frameworkRecoveryNeeded
                case .sessionAuthorized:
                    return .alreadyAuthorized(registry: registry)
                case .sessionLocked:
                    return .authorizationRequired(registry: registry)
                }
            }
        }
    }

    private func replacePendingAuthenticatedContext(with context: LAContext?, reason: String) {
        let hadExistingContext = pendingAuthenticatedContext != nil
        pendingAuthenticatedContext?.invalidate()
        pendingAuthenticatedContext = context
        traceStore?.record(
            category: .session,
            name: "session.pendingContext.store",
            metadata: [
                "reason": reason,
                "hasContext": context == nil ? "false" : "true",
                "replacedExisting": hadExistingContext ? "true" : "false"
            ]
        )
    }

    private func recordPostAuthenticationCompletion(source: String) {
        postAuthenticationGeneration += 1
        traceStore?.record(
            category: .session,
            name: "session.postAuthentication.complete",
            metadata: [
                "generation": String(postAuthenticationGeneration),
                "source": source
            ]
        )
    }

    private func setAuthenticationFailureReason(
        _ reason: AppSessionAuthenticationFailureReason,
        source: String
    ) {
        authenticationFailureReason = reason
        traceStore?.record(
            category: .session,
            name: "session.authenticationFailure.reason",
            metadata: [
                "reason": reason.rawValue,
                "source": source
            ]
        )
    }

    private func clearAuthenticationFailure() {
        guard authenticationFailureReason != nil else {
            return
        }
        authenticationFailureReason = nil
        traceStore?.record(
            category: .session,
            name: "session.authenticationFailure.clear"
        )
    }

    private func authenticationFailureReason(for error: Error) -> AppSessionAuthenticationFailureReason {
        if let authenticationError = error as? AuthenticationError {
            switch authenticationError {
            case .appAccessBiometricsLockedOut:
                return .biometricsLockedOut
            case .biometricsUnavailable,
                 .appAccessBiometricsUnavailable,
                 .cancelled,
                 .failed,
                 .accessControlCreationFailed,
                 .modeSwitchFailed,
                 .noIdentities,
                 .backupRequired:
                return .authenticationFailed
            }
        }

        if let laError = error as? LAError, laError.code == .biometryLockout {
            return .biometricsLockedOut
        }

        return .authenticationFailed
    }

    private func discardPendingAuthenticatedContext(reason: String) {
        let hadContext = pendingAuthenticatedContext != nil
        pendingAuthenticatedContext?.invalidate()
        pendingAuthenticatedContext = nil
        traceStore?.record(
            category: .session,
            name: "session.pendingContext.discard",
            metadata: ["reason": reason, "hadContext": hadContext ? "true" : "false"]
        )
    }
}
