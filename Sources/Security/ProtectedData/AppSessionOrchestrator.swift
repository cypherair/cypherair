import Foundation
import LocalAuthentication

@Observable
final class AppSessionOrchestrator {
    private let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    private let currentRegistryProvider: () throws -> ProtectedDataRegistry
    private let shouldBypassPrivacyAuthentication: () -> Bool
    private let gracePeriodProvider: () -> Int
    private let requireAuthOnLaunchProvider: () -> Bool
    private let evaluateAppAuthentication: (String) async throws -> AppSessionAuthenticationResult
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let traceStore: AuthLifecycleTraceStore?

    private var hasAppearedOnce = false
    private var pendingAuthenticatedContext: LAContext?

    var isPrivacyScreenBlurred = false
    var isAuthenticating = false
    var authFailed = false
    private(set) var contentClearGeneration = 0
    private(set) var lastAuthenticationDate: Date?

    init(
        currentRegistryProvider: @escaping () throws -> ProtectedDataRegistry,
        shouldBypassPrivacyAuthentication: @escaping () -> Bool = { false },
        gracePeriodProvider: @escaping () -> Int,
        requireAuthOnLaunchProvider: @escaping () -> Bool,
        evaluateAppAuthentication: @escaping (String) async throws -> AppSessionAuthenticationResult,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator(),
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.currentRegistryProvider = currentRegistryProvider
        self.shouldBypassPrivacyAuthentication = shouldBypassPrivacyAuthentication
        self.gracePeriodProvider = gracePeriodProvider
        self.requireAuthOnLaunchProvider = requireAuthOnLaunchProvider
        self.evaluateAppAuthentication = evaluateAppAuthentication
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.traceStore = traceStore
    }

    func recordAuthentication() {
        lastAuthenticationDate = Date()
        traceStore?.record(
            category: .session,
            name: "session.recordAuthentication",
            metadata: ["hasPendingContext": pendingAuthenticatedContext == nil ? "false" : "true"]
        )
    }

    func requestContentClear() {
        discardPendingAuthenticatedContext(reason: "contentClear")
        contentClearGeneration += 1
        traceStore?.record(
            category: .session,
            name: "session.requestContentClear",
            metadata: ["generation": String(contentClearGeneration)]
        )
    }

    var isOperationAuthenticationPromptInProgress: Bool {
        authenticationPromptCoordinator.isOperationPromptInProgress
    }

    var operationAuthenticationAttemptGeneration: UInt64 {
        authenticationPromptCoordinator.operationPromptAttemptGeneration
    }

    var isGracePeriodExpired: Bool {
        guard let lastAuthenticationDate else {
            return true
        }
        return Date().timeIntervalSince(lastAuthenticationDate) > TimeInterval(gracePeriodProvider())
    }

    @discardableResult
    func handleInitialAppearance(localizedReason: String) async -> Bool {
        traceStore?.record(category: .session, name: "session.handleInitialAppearance.enter")
        guard !hasAppearedOnce else {
            traceStore?.record(
                category: .session,
                name: "session.handleInitialAppearance.exit",
                metadata: ["reason": "alreadyAppeared"]
            )
            return false
        }
        hasAppearedOnce = true

        if shouldBypassPrivacyAuthentication() {
            authFailed = false
            isPrivacyScreenBlurred = false
            traceStore?.record(
                category: .session,
                name: "session.handleInitialAppearance.exit",
                metadata: ["reason": "bypass"]
            )
            return false
        }

        guard requireAuthOnLaunchProvider() else {
            traceStore?.record(
                category: .session,
                name: "session.handleInitialAppearance.exit",
                metadata: ["reason": "launchAuthDisabled"]
            )
            return false
        }

        isPrivacyScreenBlurred = true
        traceStore?.record(
            category: .session,
            name: "session.handleInitialAppearance.exit",
            metadata: ["reason": "delegatedToResume"]
        )
        return await handleResume(localizedReason: localizedReason)
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
        discardPendingAuthenticatedContext(reason: "sceneResignActive")
        isPrivacyScreenBlurred = true
        authFailed = false
        traceStore?.record(
            category: .session,
            name: "session.handleSceneDidResignActive",
            metadata: ["result": "handled"]
        )
    }

    func handleSceneDidEnterBackground() {
        discardPendingAuthenticatedContext(reason: "sceneBackground")
        isPrivacyScreenBlurred = true
        authFailed = false
        traceStore?.record(
            category: .session,
            name: "session.handleSceneDidEnterBackground",
            metadata: ["result": "handled"]
        )
    }

    @discardableResult
    func handleResume(localizedReason: String) async -> Bool {
        traceStore?.record(
            category: .session,
            name: "session.handleResume.enter",
            metadata: [
                "operationPrompt": isOperationAuthenticationPromptInProgress ? "true" : "false",
                "isAuthenticating": isAuthenticating ? "true" : "false",
                "hasLastAuthenticationDate": lastAuthenticationDate == nil ? "false" : "true"
            ]
        )
        if shouldBypassPrivacyAuthentication() {
            authFailed = false
            isPrivacyScreenBlurred = false
            traceStore?.record(
                category: .session,
                name: "session.handleResume.exit",
                metadata: ["reason": "bypass", "attemptedAuthentication": "false"]
            )
            return false
        }

        guard !isOperationAuthenticationPromptInProgress else {
            traceStore?.record(
                category: .session,
                name: "session.handleResume.exit",
                metadata: ["reason": "operationPromptInProgress", "attemptedAuthentication": "false"]
            )
            return false
        }

        guard !isAuthenticating else {
            traceStore?.record(
                category: .session,
                name: "session.handleResume.exit",
                metadata: ["reason": "alreadyAuthenticating", "attemptedAuthentication": "false"]
            )
            return false
        }

        if gracePeriodProvider() == 0 || isGracePeriodExpired {
            traceStore?.record(
                category: .session,
                name: "session.handleResume.reauthRequired",
                metadata: [
                    "gracePeriod": String(gracePeriodProvider()),
                    "graceExpired": isGracePeriodExpired ? "true" : "false"
                ]
            )
            requestContentClear()
            await protectedDataSessionCoordinator.relockCurrentSession()

            isAuthenticating = true
            authFailed = false
            isPrivacyScreenBlurred = true
            defer { isAuthenticating = false }

            do {
                let result = try await evaluateAppAuthentication(localizedReason)
                if result.isAuthenticated {
                    replacePendingAuthenticatedContext(with: result.context, reason: "resumeAuthenticated")
                    recordAuthentication()
                    authFailed = false
                    isPrivacyScreenBlurred = false
                    traceStore?.record(
                        category: .session,
                        name: "session.handleResume.exit",
                        metadata: ["reason": "authenticated", "attemptedAuthentication": "true"]
                    )
                } else {
                    discardPendingAuthenticatedContext(reason: "resumeReturnedFalse")
                    authFailed = true
                    traceStore?.record(
                        category: .session,
                        name: "session.handleResume.exit",
                        metadata: ["reason": "authenticationReturnedFalse", "attemptedAuthentication": "true"]
                    )
                }
            } catch {
                discardPendingAuthenticatedContext(reason: "resumeThrew")
                authFailed = true
                traceStore?.record(
                    category: .session,
                    name: "session.handleResume.exit",
                    metadata: [
                        "reason": "authenticationThrew",
                        "attemptedAuthentication": "true",
                        "errorType": String(describing: type(of: error))
                    ]
                )
            }
            return true
        } else {
            authFailed = false
            isPrivacyScreenBlurred = false
            traceStore?.record(
                category: .session,
                name: "session.handleResume.exit",
                metadata: ["reason": "graceValid", "attemptedAuthentication": "false"]
            )
            return false
        }
    }

    @discardableResult
    func retryPrivacyUnlock(localizedReason: String) async -> Bool {
        traceStore?.record(category: .session, name: "session.retryPrivacyUnlock")
        return await handleResume(localizedReason: localizedReason)
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
