import Foundation

@Observable
final class AppSessionOrchestrator {
    private let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    private let currentRegistryProvider: () throws -> ProtectedDataRegistry
    private let shouldBypassPrivacyAuthentication: () -> Bool
    private let gracePeriodProvider: () -> Int
    private let requireAuthOnLaunchProvider: () -> Bool
    private let evaluateAppAuthentication: (String) async throws -> Bool

    private var hasAppearedOnce = false

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
        evaluateAppAuthentication: @escaping (String) async throws -> Bool,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    ) {
        self.currentRegistryProvider = currentRegistryProvider
        self.shouldBypassPrivacyAuthentication = shouldBypassPrivacyAuthentication
        self.gracePeriodProvider = gracePeriodProvider
        self.requireAuthOnLaunchProvider = requireAuthOnLaunchProvider
        self.evaluateAppAuthentication = evaluateAppAuthentication
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
    }

    func recordAuthentication() {
        lastAuthenticationDate = Date()
    }

    func requestContentClear() {
        contentClearGeneration += 1
    }

    var isGracePeriodExpired: Bool {
        guard let lastAuthenticationDate else {
            return true
        }
        return Date().timeIntervalSince(lastAuthenticationDate) > TimeInterval(gracePeriodProvider())
    }

    @discardableResult
    func handleInitialAppearance(localizedReason: String) async -> Bool {
        guard !hasAppearedOnce else {
            return false
        }
        hasAppearedOnce = true

        if shouldBypassPrivacyAuthentication() {
            authFailed = false
            isPrivacyScreenBlurred = false
            return false
        }

        guard requireAuthOnLaunchProvider() else {
            return false
        }

        isPrivacyScreenBlurred = true
        return await handleResume(localizedReason: localizedReason)
    }

    func handleSceneDidResignActive() {
        isPrivacyScreenBlurred = true
        authFailed = false
    }

    @discardableResult
    func handleResume(localizedReason: String) async -> Bool {
        if shouldBypassPrivacyAuthentication() {
            authFailed = false
            isPrivacyScreenBlurred = false
            return false
        }

        if gracePeriodProvider() == 0 || isGracePeriodExpired {
            requestContentClear()
            await protectedDataSessionCoordinator.relockCurrentSession()

            guard !isAuthenticating else {
                return false
            }

            isAuthenticating = true
            authFailed = false
            isPrivacyScreenBlurred = true
            defer { isAuthenticating = false }

            do {
                let success = try await evaluateAppAuthentication(localizedReason)
                if success {
                    recordAuthentication()
                    authFailed = false
                    isPrivacyScreenBlurred = false
                } else {
                    authFailed = true
                }
            } catch {
                authFailed = true
            }
            return true
        } else {
            authFailed = false
            isPrivacyScreenBlurred = false
            return false
        }
    }

    @discardableResult
    func retryPrivacyUnlock(localizedReason: String) async -> Bool {
        await handleResume(localizedReason: localizedReason)
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
                if protectedDataSessionCoordinator.frameworkState == .sessionAuthorized {
                    return .alreadyAuthorized(registry: registry)
                }
                return .authorizationRequired(registry: registry)
            }
        }
    }

    func beginProtectedDataAuthorizationIfNeeded(
        gateDecision: ProtectedDataAccessGateDecision,
        localizedReason: String
    ) async -> ProtectedDataAuthorizationResult {
        switch gateDecision {
        case .frameworkRecoveryNeeded, .pendingMutationRecoveryRequired, .noProtectedDomainPresent:
            return .frameworkRecoveryNeeded
        case .alreadyAuthorized:
            return .authorized
        case .authorizationRequired(let registry):
            return await protectedDataSessionCoordinator.beginProtectedDataAuthorization(
                registry: registry,
                localizedReason: localizedReason
            )
        }
    }
}
