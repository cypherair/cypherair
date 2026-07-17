import Foundation
import LocalAuthentication

@MainActor
final class ProtectedSettingsAccessCoordinator {
    typealias AccessGateDecision = ProtectedSettingsHost.AccessGateDecision
    typealias AuthorizationInteractionMode = ProtectedSettingsHost.AuthorizationInteractionMode
    typealias AuthorizationOutcome = ProtectedSettingsHost.AuthorizationOutcome
    typealias DomainState = ProtectedSettingsHost.DomainState
    typealias MutationAuthorizationRequirement = ProtectedSettingsHost.MutationAuthorizationRequirement
    typealias RecoveryOutcome = ProtectedSettingsHost.RecoveryOutcome
    typealias SectionState = ProtectedSettingsHost.SectionState

    enum AccessAuthorizationMode: Equatable {
        case authorizeIfNeeded
        case requireExistingAuthorization
        case handoffOnly
    }

    struct Dependencies: @unchecked Sendable {
        let evaluateAccessGate: @MainActor (_ isFirstProtectedAccess: Bool) -> AccessGateDecision
        let hasAuthorizationHandoffContext: @MainActor () -> Bool
        let authorizeSharedRight: @MainActor (_ localizedReason: String, _ interactionMode: AuthorizationInteractionMode) async -> AuthorizationOutcome
        let currentWrappingRootKey: @MainActor () throws -> Data
        let syncPreAuthorizationState: @MainActor () -> Void
        let currentDomainState: @MainActor () -> DomainState
        let currentClipboardNotice: @MainActor () -> Bool?
        let ensureCommittedSettingsIfNeeded: @MainActor () async throws -> Void
        let openDomainIfNeeded: @MainActor (_ wrappingRootKey: Data) async throws -> Void
        let updateClipboardNotice: @MainActor (_ enabled: Bool, _ wrappingRootKey: Data) async throws -> Void
        let pendingRecoveryAuthorizationRequirement: @MainActor () -> MutationAuthorizationRequirement
        let recoverPendingMutation: @MainActor (_ authenticationContext: LAContext?) async throws -> RecoveryOutcome
        let resetAuthorizationRequirement: @MainActor () -> MutationAuthorizationRequirement
        let resetDomain: @MainActor () async throws -> Void
    }

    struct StateAdapter: @unchecked Sendable {
        let currentSectionState: @MainActor () -> SectionState
        let setSectionState: @MainActor (_ state: SectionState) -> Void
        let syncPreAuthorizationSectionState: @MainActor () -> DomainState
        let syncSectionStateFromStore: @MainActor () -> Void
        let syncSectionStateAfterOperationError: @MainActor () -> Void
    }

    private struct MutationAuthorizationResult: @unchecked Sendable {
        let isAuthorized: Bool
        let authenticationContext: LAContext?

        static var notAuthorized: MutationAuthorizationResult {
            MutationAuthorizationResult(
                isAuthorized: false,
                authenticationContext: nil
            )
        }

        static func authorized(authenticationContext: LAContext?) -> MutationAuthorizationResult {
            MutationAuthorizationResult(
                isAuthorized: true,
                authenticationContext: authenticationContext
            )
        }

        func invalidateAuthenticationContext() {
            authenticationContext?.invalidate()
        }
    }

    private let dependencies: Dependencies
    private let stateAdapter: StateAdapter

    private var hasEvaluatedProtectedAccessGate = false

    init(
        dependencies: Dependencies,
        stateAdapter: StateAdapter
    ) {
        self.dependencies = dependencies
        self.stateAdapter = stateAdapter
    }

    func currentAccessGateDecision() -> AccessGateDecision {
        let decision = dependencies.evaluateAccessGate(!hasEvaluatedProtectedAccessGate)
        hasEvaluatedProtectedAccessGate = true
        return decision
    }

    func openProtectedSettings(
        localizedReason: String,
        authorizationMode: AccessAuthorizationMode = .authorizeIfNeeded
    ) async -> Bool {
        stateAdapter.setSectionState(.loading)
        do {
            guard try await ensureProtectedSettingsAccess(
                localizedReason: localizedReason,
                authorizationMode: authorizationMode
            ) else {
                stateAdapter.syncSectionStateFromStore()
                return false
            }

            stateAdapter.syncSectionStateFromStore()
            if case .available = stateAdapter.currentSectionState() {
                return true
            }
            return false
        } catch {
            stateAdapter.syncSectionStateAfterOperationError()
            return false
        }
    }

    func setClipboardNoticeEnabled(
        _ isEnabled: Bool,
        localizedReason: String
    ) async {
        stateAdapter.setSectionState(.loading)
        do {
            guard try await ensureProtectedSettingsAccess(localizedReason: localizedReason) else {
                stateAdapter.syncSectionStateFromStore()
                return
            }

            let wrappingRootKey = try dependencies.currentWrappingRootKey()
            try await dependencies.updateClipboardNotice(
                isEnabled,
                wrappingRootKey
            )
            stateAdapter.setSectionState(.available(clipboardNoticeEnabled: isEnabled))
        } catch {
            stateAdapter.syncSectionStateAfterOperationError()
        }
    }

    func retryPendingRecovery(localizedReason: String) async {
        stateAdapter.setSectionState(.loading)
        do {
            let recoveryRequirement = dependencies.pendingRecoveryAuthorizationRequirement()
            let recoveryAuthorization = try await authorizeMutationIfNeeded(
                requirement: recoveryRequirement,
                localizedReason: localizedReason,
                operation: "pendingRecovery",
                interactionMode: recoveryRequirement == .wrappingRootKeyRequired
                    ? .requireReusableContext
                    : .allowInteraction
            )
            guard recoveryAuthorization.isAuthorized else {
                return
            }
            defer {
                recoveryAuthorization.invalidateAuthenticationContext()
            }

            let outcome = try await dependencies.recoverPendingMutation(
                recoveryAuthorization.authenticationContext
            )
            switch outcome {
            case .resumedToSteadyState, .retryablePending:
                dependencies.syncPreAuthorizationState()
                stateAdapter.syncSectionStateFromStore()
            case .resetRequired:
                stateAdapter.setSectionState(.pendingResetRequired)
            case .frameworkRecoveryNeeded:
                stateAdapter.setSectionState(.frameworkUnavailable)
            }
        } catch {
            dependencies.syncPreAuthorizationState()
            stateAdapter.syncSectionStateAfterOperationError()
        }
    }

    func resetProtectedSettingsDomain(localizedReason: String) async {
        stateAdapter.setSectionState(.loading)
        do {
            let resetAuthorization = try await authorizeMutationIfNeeded(
                requirement: dependencies.resetAuthorizationRequirement(),
                localizedReason: localizedReason,
                operation: "reset"
            )
            guard resetAuthorization.isAuthorized else {
                return
            }
            defer {
                resetAuthorization.invalidateAuthenticationContext()
            }

            try await dependencies.resetDomain()

            let didOpen = await openProtectedSettings(localizedReason: localizedReason)
            if !didOpen {
                dependencies.syncPreAuthorizationState()
                stateAdapter.syncSectionStateFromStore()
            }
        } catch {
            dependencies.syncPreAuthorizationState()
            stateAdapter.syncSectionStateAfterOperationError()
        }
    }

    func clipboardNoticeDecision(localizedReason: String) async -> Bool {
        do {
            dependencies.syncPreAuthorizationState()
            stateAdapter.syncSectionStateFromStore()
            guard try await ensureProtectedSettingsAccess(
                localizedReason: localizedReason,
                authorizationMode: .requireExistingAuthorization
            ) else {
                return true
            }

            return dependencies.currentClipboardNotice() ?? true
        } catch {
            return true
        }
    }

    private func authorizeMutationIfNeeded(
        requirement: MutationAuthorizationRequirement,
        localizedReason: String,
        operation: String,
        interactionMode: AuthorizationInteractionMode = .allowInteraction
    ) async throws -> MutationAuthorizationResult {
        switch requirement {
        case .notRequired:
            return .authorized(authenticationContext: nil)
        case .frameworkRecoveryNeeded:
            dependencies.syncPreAuthorizationState()
            stateAdapter.setSectionState(.frameworkUnavailable)
            return .notAuthorized
        case .wrappingRootKeyRequired:
            let authorizationResult = await dependencies.authorizeSharedRight(
                localizedReason,
                interactionMode
            )
            switch authorizationResult {
            case .authorized, .authorizedWithContext:
                do {
                    var wrappingRootKey = try dependencies.currentWrappingRootKey()
                    wrappingRootKey.resetBytes(in: 0..<wrappingRootKey.count)
                } catch {
                    authorizationResult.authenticationContext?.invalidate()
                    throw error
                }
                return .authorized(authenticationContext: authorizationResult.authenticationContext)
            case .cancelledOrDenied:
                dependencies.syncPreAuthorizationState()
                stateAdapter.syncSectionStateFromStore()
                return .notAuthorized
            case .frameworkRecoveryNeeded:
                dependencies.syncPreAuthorizationState()
                stateAdapter.setSectionState(.frameworkUnavailable)
                return .notAuthorized
            }
        }
    }

    private func ensureCommittedSettingsIfNeeded(
        gateDecision: AccessGateDecision,
        preauthorized: Bool
    ) async throws {
        try await dependencies.ensureCommittedSettingsIfNeeded()
    }

    private func ensureProtectedSettingsAccess(
        localizedReason: String,
        authorizationMode: AccessAuthorizationMode = .authorizeIfNeeded
    ) async throws -> Bool {
        var operationAuthenticationContexts: [LAContext] = []
        defer {
            operationAuthenticationContexts.forEach { $0.invalidate() }
        }
        let preAuthorizationState = stateAdapter.syncPreAuthorizationSectionState()
        switch preAuthorizationState {
        case .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            return false
        case .locked, .unlocked:
            break
        }

        let decision = currentAccessGateDecision()
        switch decision {
        case .frameworkRecoveryNeeded:
            dependencies.syncPreAuthorizationState()
            stateAdapter.setSectionState(.frameworkUnavailable)
            return false
        case .pendingMutationRecoveryRequired:
            dependencies.syncPreAuthorizationState()
            stateAdapter.syncSectionStateFromStore()
            return false
        case .noProtectedDomainPresent:
            guard authorizationMode == .authorizeIfNeeded else {
                stateAdapter.setSectionState(.locked)
                return false
            }
            try await ensureCommittedSettingsIfNeeded(
                gateDecision: decision,
                preauthorized: false
            )
            let authorizationResult = await dependencies.authorizeSharedRight(
                localizedReason,
                .allowInteraction
            )
            switch authorizationResult {
            case .authorized, .authorizedWithContext:
                if let authenticationContext = authorizationResult.authenticationContext {
                    operationAuthenticationContexts.append(authenticationContext)
                }
            case .cancelledOrDenied:
                stateAdapter.setSectionState(.locked)
                return false
            case .frameworkRecoveryNeeded:
                stateAdapter.setSectionState(.frameworkUnavailable)
                return false
            }
        case .authorizationRequired:
            guard authorizationMode == .authorizeIfNeeded || authorizationMode == .handoffOnly else {
                stateAdapter.setSectionState(.locked)
                return false
            }
            let interactionMode: AuthorizationInteractionMode
            switch authorizationMode {
            case .authorizeIfNeeded:
                interactionMode = .allowInteraction
            case .handoffOnly:
                guard dependencies.hasAuthorizationHandoffContext() else {
                    stateAdapter.setSectionState(.locked)
                    return false
                }
                interactionMode = .handoffOnly
            case .requireExistingAuthorization:
                stateAdapter.setSectionState(.locked)
                return false
            }
            let authorizationResult = await dependencies.authorizeSharedRight(
                localizedReason,
                interactionMode
            )
            switch authorizationResult {
            case .authorized, .authorizedWithContext:
                if let authenticationContext = authorizationResult.authenticationContext {
                    operationAuthenticationContexts.append(authenticationContext)
                }
                try await ensureCommittedSettingsIfNeeded(
                    gateDecision: decision,
                    preauthorized: true
                )
            case .cancelledOrDenied:
                stateAdapter.setSectionState(.locked)
                return false
            case .frameworkRecoveryNeeded:
                stateAdapter.setSectionState(.frameworkUnavailable)
                return false
            }
        case .alreadyAuthorized:
            try await ensureCommittedSettingsIfNeeded(
                gateDecision: decision,
                preauthorized: true
            )
        }

        let wrappingRootKey = try dependencies.currentWrappingRootKey()
        try await dependencies.openDomainIfNeeded(wrappingRootKey)
        return true
    }
}
