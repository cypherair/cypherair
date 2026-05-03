import Foundation

struct ProtectedDataAccessGateClassifier {
    private let currentRegistryProvider: () throws -> ProtectedDataRegistry
    private let frameworkStateProvider: () -> ProtectedDataFrameworkState

    init(
        currentRegistryProvider: @escaping () throws -> ProtectedDataRegistry,
        frameworkStateProvider: @escaping () -> ProtectedDataFrameworkState
    ) {
        self.currentRegistryProvider = currentRegistryProvider
        self.frameworkStateProvider = frameworkStateProvider
    }

    func evaluate(
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

        return Self.evaluate(
            bootstrapOutcome: bootstrapOutcome,
            frameworkState: frameworkStateProvider()
        )
    }

    static func evaluate(
        bootstrapOutcome: ProtectedDataBootstrapOutcome,
        frameworkState: ProtectedDataFrameworkState
    ) -> ProtectedDataAccessGateDecision {
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
                switch frameworkState {
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
}
