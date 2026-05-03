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
        let migrationAuthorizationRequirement: @MainActor () -> MutationAuthorizationRequirement
        let ensureCommittedAndMigrateSettingsIfNeeded: @MainActor () async throws -> Void
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
        let stateMetadata: @MainActor (_ domainState: DomainState?) -> [String: String]
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
    private let traceEvent: @MainActor (_ name: String, _ metadata: [String: String]) -> Void

    private var hasEvaluatedProtectedAccessGate = false

    init(
        dependencies: Dependencies,
        stateAdapter: StateAdapter,
        traceEvent: @escaping @MainActor (_ name: String, _ metadata: [String: String]) -> Void
    ) {
        self.dependencies = dependencies
        self.stateAdapter = stateAdapter
        self.traceEvent = traceEvent
    }

    func currentAccessGateDecision() -> AccessGateDecision {
        let decision = dependencies.evaluateAccessGate(!hasEvaluatedProtectedAccessGate)
        traceCoordinatorEvent(
            "protectedSettings.gate.decision",
            metadata: [
                "decision": accessGateTraceValue(decision),
                "isFirstProtectedAccess": hasEvaluatedProtectedAccessGate ? "false" : "true"
            ]
        )
        hasEvaluatedProtectedAccessGate = true
        return decision
    }

    func openProtectedSettings(
        localizedReason: String,
        authorizationMode: AccessAuthorizationMode = .authorizeIfNeeded
    ) async -> Bool {
        stateAdapter.setSectionState(.loading)
        traceCoordinatorEvent(
            "protectedSettings.open.start",
            metadata: stateMetadata()
                .merging(["authorizationMode": authorizationModeTraceValue(authorizationMode)], uniquingKeysWith: { _, new in new })
        )
        do {
            guard try await ensureProtectedSettingsAccess(
                localizedReason: localizedReason,
                authorizationMode: authorizationMode
            ) else {
                stateAdapter.syncSectionStateFromStore()
                traceCoordinatorEvent(
                    "protectedSettings.open.finish",
                    metadata: stateMetadata()
                        .merging(["result": "accessDenied"], uniquingKeysWith: { _, new in new })
                )
                return false
            }

            stateAdapter.syncSectionStateFromStore()
            if case .available = stateAdapter.currentSectionState() {
                traceCoordinatorEvent(
                    "protectedSettings.open.finish",
                    metadata: stateMetadata()
                        .merging(["result": "available"], uniquingKeysWith: { _, new in new })
                )
                return true
            }
            traceCoordinatorEvent(
                "protectedSettings.open.finish",
                metadata: stateMetadata()
                    .merging(["result": "openedButUnavailable"], uniquingKeysWith: { _, new in new })
            )
            return false
        } catch {
            stateAdapter.syncSectionStateAfterOperationError()
            traceCoordinatorEvent(
                "protectedSettings.open.finish",
                metadata: stateMetadata()
                    .merging(traceErrorMetadata(error, extra: ["result": "error"]), uniquingKeysWith: { _, new in new })
            )
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
        traceCoordinatorEvent(
            "protectedSettings.mutationAuthorization.start",
            metadata: [
                "operation": operation,
                "requirement": mutationAuthorizationRequirementTraceValue(requirement)
            ]
        )

        switch requirement {
        case .notRequired:
            traceCoordinatorEvent(
                "protectedSettings.mutationAuthorization.finish",
                metadata: ["operation": operation, "result": "notRequired"]
            )
            return .authorized(authenticationContext: nil)
        case .frameworkRecoveryNeeded:
            dependencies.syncPreAuthorizationState()
            stateAdapter.setSectionState(.frameworkUnavailable)
            traceCoordinatorEvent(
                "protectedSettings.mutationAuthorization.finish",
                metadata: ["operation": operation, "result": "frameworkRecoveryNeeded"]
            )
            return .notAuthorized
        case .wrappingRootKeyRequired:
            let authorizationResult = await dependencies.authorizeSharedRight(
                localizedReason,
                interactionMode
            )
            traceCoordinatorEvent(
                "protectedSettings.mutationAuthorization.result",
                metadata: [
                    "operation": operation,
                    "outcome": authorizationOutcomeTraceValue(authorizationResult)
                ]
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
                traceCoordinatorEvent(
                    "protectedSettings.mutationAuthorization.finish",
                    metadata: ["operation": operation, "result": "authorized"]
                )
                return .authorized(authenticationContext: authorizationResult.authenticationContext)
            case .cancelledOrDenied:
                dependencies.syncPreAuthorizationState()
                stateAdapter.syncSectionStateFromStore()
                traceCoordinatorEvent(
                    "protectedSettings.mutationAuthorization.finish",
                    metadata: ["operation": operation, "result": "cancelledOrDenied"]
                )
                return .notAuthorized
            case .frameworkRecoveryNeeded:
                dependencies.syncPreAuthorizationState()
                stateAdapter.setSectionState(.frameworkUnavailable)
                traceCoordinatorEvent(
                    "protectedSettings.mutationAuthorization.finish",
                    metadata: ["operation": operation, "result": "frameworkRecoveryNeeded"]
                )
                return .notAuthorized
            }
        }
    }

    private func ensureCommittedAndMigrateSettingsIfNeeded(
        gateDecision: AccessGateDecision,
        preauthorized: Bool
    ) async throws {
        traceCoordinatorEvent(
            "protectedSettings.settingsMigration.start",
            metadata: [
                "gateDecision": accessGateTraceValue(gateDecision),
                "preauthorized": preauthorized ? "true" : "false"
            ]
        )
        do {
            try await dependencies.ensureCommittedAndMigrateSettingsIfNeeded()
            traceCoordinatorEvent(
                "protectedSettings.settingsMigration.finish",
                metadata: [
                    "result": "success",
                    "gateDecision": accessGateTraceValue(gateDecision),
                    "preauthorized": preauthorized ? "true" : "false"
                ]
            )
        } catch {
            traceCoordinatorEvent(
                "protectedSettings.settingsMigration.finish",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "result": "failed",
                        "gateDecision": accessGateTraceValue(gateDecision),
                        "preauthorized": preauthorized ? "true" : "false"
                    ]
                )
            )
            throw error
        }
    }

    private func ensureProtectedSettingsAccess(
        localizedReason: String,
        authorizationMode: AccessAuthorizationMode = .authorizeIfNeeded
    ) async throws -> Bool {
        traceCoordinatorEvent(
            "protectedSettings.ensureAccess.start",
            metadata: ["authorizationMode": authorizationModeTraceValue(authorizationMode)]
        )
        var operationAuthenticationContexts: [LAContext] = []
        defer {
            operationAuthenticationContexts.forEach { $0.invalidate() }
        }
        let preAuthorizationState = stateAdapter.syncPreAuthorizationSectionState()
        traceCoordinatorEvent(
            "protectedSettings.ensureAccess.preAuthorization",
            metadata: stateMetadata(domainState: preAuthorizationState)
        )
        switch preAuthorizationState {
        case .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            traceCoordinatorEvent(
                "protectedSettings.ensureAccess.finish",
                metadata: stateMetadata(domainState: preAuthorizationState)
                    .merging(["result": "blockedByDomainState"], uniquingKeysWith: { _, new in new })
            )
            return false
        case .locked, .unlocked:
            break
        }

        let decision = currentAccessGateDecision()
        switch decision {
        case .frameworkRecoveryNeeded:
            dependencies.syncPreAuthorizationState()
            stateAdapter.setSectionState(.frameworkUnavailable)
            traceCoordinatorEvent(
                "protectedSettings.ensureAccess.finish",
                metadata: stateMetadata()
                    .merging(["result": "frameworkRecoveryNeeded", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
            )
            return false
        case .pendingMutationRecoveryRequired:
            dependencies.syncPreAuthorizationState()
            stateAdapter.syncSectionStateFromStore()
            traceCoordinatorEvent(
                "protectedSettings.ensureAccess.finish",
                metadata: stateMetadata()
                    .merging(["result": "pendingMutationRecoveryRequired", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
            )
            return false
        case .noProtectedDomainPresent:
            guard authorizationMode == .authorizeIfNeeded else {
                stateAdapter.setSectionState(.locked)
                traceCoordinatorEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata()
                        .merging(["result": "authorizationModeBlocked", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
            let migrationRequirement = dependencies.migrationAuthorizationRequirement()
            let didPreauthorizeMigration: Bool
            switch migrationRequirement {
            case .notRequired:
                didPreauthorizeMigration = false
            case .wrappingRootKeyRequired:
                let migrationAuthorization = try await authorizeMutationIfNeeded(
                    requirement: migrationRequirement,
                    localizedReason: localizedReason,
                    operation: "settingsMigration"
                )
                guard migrationAuthorization.isAuthorized else {
                    traceCoordinatorEvent(
                        "protectedSettings.ensureAccess.finish",
                        metadata: stateMetadata()
                            .merging(["result": "migrationAuthorizationBlocked", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                    )
                    return false
                }
                if let authenticationContext = migrationAuthorization.authenticationContext {
                    operationAuthenticationContexts.append(authenticationContext)
                }
                didPreauthorizeMigration = true
            case .frameworkRecoveryNeeded:
                dependencies.syncPreAuthorizationState()
                stateAdapter.setSectionState(.frameworkUnavailable)
                traceCoordinatorEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata()
                        .merging(["result": "migrationFrameworkRecoveryNeeded", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
            try await ensureCommittedAndMigrateSettingsIfNeeded(
                gateDecision: decision,
                preauthorized: didPreauthorizeMigration
            )
            if !didPreauthorizeMigration {
                traceCoordinatorEvent("protectedSettings.authorization.request", metadata: ["gateDecision": accessGateTraceValue(decision)])
                let authorizationResult = await dependencies.authorizeSharedRight(
                    localizedReason,
                    .allowInteraction
                )
                traceCoordinatorEvent(
                    "protectedSettings.authorization.result",
                    metadata: ["outcome": authorizationOutcomeTraceValue(authorizationResult)]
                )
                switch authorizationResult {
                case .authorized, .authorizedWithContext:
                    if let authenticationContext = authorizationResult.authenticationContext {
                        operationAuthenticationContexts.append(authenticationContext)
                    }
                    break
                case .cancelledOrDenied:
                    stateAdapter.setSectionState(.locked)
                    traceCoordinatorEvent(
                        "protectedSettings.ensureAccess.finish",
                        metadata: stateMetadata()
                            .merging(["result": "cancelledOrDenied", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                    )
                    return false
                case .frameworkRecoveryNeeded:
                    stateAdapter.setSectionState(.frameworkUnavailable)
                    traceCoordinatorEvent(
                        "protectedSettings.ensureAccess.finish",
                        metadata: stateMetadata()
                            .merging(["result": "authorizationFrameworkRecoveryNeeded", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                    )
                    return false
                }
            }
        case .authorizationRequired:
            guard authorizationMode == .authorizeIfNeeded || authorizationMode == .handoffOnly else {
                stateAdapter.setSectionState(.locked)
                traceCoordinatorEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata()
                        .merging(["result": "authorizationModeBlocked", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
            let interactionMode: AuthorizationInteractionMode
            switch authorizationMode {
            case .authorizeIfNeeded:
                interactionMode = .allowInteraction
            case .handoffOnly:
                guard dependencies.hasAuthorizationHandoffContext() else {
                    stateAdapter.setSectionState(.locked)
                    traceCoordinatorEvent(
                        "protectedSettings.ensureAccess.finish",
                        metadata: stateMetadata()
                            .merging(
                                [
                                    "result": "handoffMissing",
                                    "gateDecision": accessGateTraceValue(decision),
                                    "hasHandoff": "false"
                                ],
                                uniquingKeysWith: { _, new in new }
                            )
                    )
                    return false
                }
                interactionMode = .handoffOnly
            case .requireExistingAuthorization:
                stateAdapter.setSectionState(.locked)
                traceCoordinatorEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata()
                        .merging(["result": "authorizationModeBlocked", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
            traceCoordinatorEvent("protectedSettings.authorization.request", metadata: ["gateDecision": accessGateTraceValue(decision)])
            let authorizationResult = await dependencies.authorizeSharedRight(
                localizedReason,
                interactionMode
            )
            traceCoordinatorEvent(
                "protectedSettings.authorization.result",
                metadata: ["outcome": authorizationOutcomeTraceValue(authorizationResult)]
            )
            switch authorizationResult {
            case .authorized, .authorizedWithContext:
                if let authenticationContext = authorizationResult.authenticationContext {
                    operationAuthenticationContexts.append(authenticationContext)
                }
                try await ensureCommittedAndMigrateSettingsIfNeeded(
                    gateDecision: decision,
                    preauthorized: true
                )
            case .cancelledOrDenied:
                stateAdapter.setSectionState(.locked)
                traceCoordinatorEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata()
                        .merging(["result": "cancelledOrDenied", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            case .frameworkRecoveryNeeded:
                stateAdapter.setSectionState(.frameworkUnavailable)
                traceCoordinatorEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata()
                        .merging(["result": "authorizationFrameworkRecoveryNeeded", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
        case .alreadyAuthorized:
            try await ensureCommittedAndMigrateSettingsIfNeeded(
                gateDecision: decision,
                preauthorized: true
            )
        }

        let wrappingRootKey = try dependencies.currentWrappingRootKey()
        traceCoordinatorEvent(
            "protectedSettings.openDomain.start",
            metadata: ["gateDecision": accessGateTraceValue(decision)]
        )
        do {
            try await dependencies.openDomainIfNeeded(wrappingRootKey)
            traceCoordinatorEvent(
                "protectedSettings.openDomain.finish",
                metadata: stateMetadata()
                    .merging(["result": "success", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
            )
        } catch {
            traceCoordinatorEvent(
                "protectedSettings.openDomain.finish",
                metadata: stateMetadata()
                    .merging(
                        traceErrorMetadata(
                            error,
                            extra: ["result": "failed", "gateDecision": accessGateTraceValue(decision)]
                        ),
                        uniquingKeysWith: { _, new in new }
                    )
            )
            throw error
        }
        traceCoordinatorEvent(
            "protectedSettings.ensureAccess.finish",
            metadata: stateMetadata()
                .merging(["result": "success", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
        )
        return true
    }

    private func stateMetadata(domainState: DomainState? = nil) -> [String: String] {
        stateAdapter.stateMetadata(domainState)
    }

    private func traceErrorMetadata(
        _ error: Error,
        extra: [String: String] = [:]
    ) -> [String: String] {
        var metadata = extra
        metadata["errorType"] = String(describing: type(of: error))
        return metadata
    }

    private func traceCoordinatorEvent(
        _ name: String,
        metadata: [String: String] = [:]
    ) {
        traceEvent(name, metadata)
    }

    private func authorizationModeTraceValue(_ mode: AccessAuthorizationMode) -> String {
        switch mode {
        case .authorizeIfNeeded:
            "authorizeIfNeeded"
        case .requireExistingAuthorization:
            "requireExistingAuthorization"
        case .handoffOnly:
            "handoffOnly"
        }
    }

    private func accessGateTraceValue(_ decision: AccessGateDecision) -> String {
        switch decision {
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        case .pendingMutationRecoveryRequired:
            "pendingMutationRecoveryRequired"
        case .noProtectedDomainPresent:
            "noProtectedDomainPresent"
        case .authorizationRequired:
            "authorizationRequired"
        case .alreadyAuthorized:
            "alreadyAuthorized"
        }
    }

    private func authorizationOutcomeTraceValue(_ outcome: AuthorizationOutcome) -> String {
        switch outcome {
        case .authorized, .authorizedWithContext:
            "authorized"
        case .cancelledOrDenied:
            "cancelledOrDenied"
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        }
    }

    private func mutationAuthorizationRequirementTraceValue(
        _ requirement: MutationAuthorizationRequirement
    ) -> String {
        switch requirement {
        case .notRequired:
            "notRequired"
        case .wrappingRootKeyRequired:
            "wrappingRootKeyRequired"
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        }
    }
}
