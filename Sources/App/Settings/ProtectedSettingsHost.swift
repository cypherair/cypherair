import Foundation
import SwiftUI

@MainActor
@Observable
final class ProtectedSettingsHost {
    enum AccessGateDecision: Equatable {
        case frameworkRecoveryNeeded
        case pendingMutationRecoveryRequired
        case noProtectedDomainPresent
        case authorizationRequired
        case alreadyAuthorized
    }

    enum AuthorizationOutcome: Equatable {
        case authorized
        case cancelledOrDenied
        case frameworkRecoveryNeeded
    }

    enum AuthorizationInteractionMode: Equatable {
        case allowInteraction
        case handoffOnly
    }

    enum RecoveryOutcome: Equatable {
        case resumedToSteadyState
        case retryablePending
        case resetRequired
        case frameworkRecoveryNeeded
    }

    enum MutationAuthorizationRequirement: Equatable {
        case notRequired
        case wrappingRootKeyRequired
        case frameworkRecoveryNeeded
    }

    enum DomainState: Equatable {
        case locked
        case unlocked
        case recoveryNeeded
        case pendingRetryRequired
        case pendingResetRequired
        case frameworkUnavailable
    }

    enum Mode: Equatable {
        case mainWindowLive
        case settingsSceneProxy
        case tutorialSandbox
    }

    enum SectionState: Equatable {
        case loading
        case locked
        case available(clipboardNoticeEnabled: Bool)
        case recoveryNeeded
        case pendingRetryRequired
        case pendingResetRequired
        case frameworkUnavailable
        case settingsSceneProxy
        case tutorialSandbox
    }

    private enum AccessAuthorizationMode: Equatable {
        case authorizeIfNeeded
        case requireExistingAuthorization
        case handoffOnly
    }

    private struct LiveDependencies: @unchecked Sendable {
        let evaluateAccessGate: @MainActor (_ isFirstProtectedAccess: Bool) -> AccessGateDecision
        let hasAuthorizationHandoffContext: @MainActor () -> Bool
        let authorizeSharedRight: @MainActor (_ localizedReason: String, _ interactionMode: AuthorizationInteractionMode) async -> AuthorizationOutcome
        let currentWrappingRootKey: @MainActor () throws -> Data
        let syncPreAuthorizationState: @MainActor () -> Void
        let currentDomainState: @MainActor () -> DomainState
        let currentClipboardNotice: @MainActor () -> Bool?
        let migrationAuthorizationRequirement: @MainActor () -> MutationAuthorizationRequirement
        let migrateLegacyClipboardNoticeIfNeeded: @MainActor () async throws -> Void
        let openDomainIfNeeded: @MainActor (_ wrappingRootKey: Data) async throws -> Void
        let updateClipboardNotice: @MainActor (_ enabled: Bool, _ wrappingRootKey: Data) async throws -> Void
        let pendingRecoveryAuthorizationRequirement: @MainActor () -> MutationAuthorizationRequirement
        let recoverPendingMutation: @MainActor () async throws -> RecoveryOutcome
        let resetAuthorizationRequirement: @MainActor () -> MutationAuthorizationRequirement
        let resetDomain: @MainActor () async throws -> Void
    }

    let mode: Mode
    private let openMainWindowAction: (() -> Void)?
    private let liveDependencies: LiveDependencies?
    private let traceStore: AuthLifecycleTraceStore?

    private(set) var sectionState: SectionState

    @ObservationIgnored
    private var hasEvaluatedProtectedAccessGate = false

    init(
        evaluateAccessGate: @escaping @MainActor (_ isFirstProtectedAccess: Bool) -> AccessGateDecision,
        hasAuthorizationHandoffContext: @escaping @MainActor () -> Bool = { false },
        authorizeSharedRight: @escaping @MainActor (_ localizedReason: String, _ interactionMode: AuthorizationInteractionMode) async -> AuthorizationOutcome,
        currentWrappingRootKey: @escaping @MainActor () throws -> Data,
        syncPreAuthorizationState: @escaping @MainActor () -> Void,
        currentDomainState: @escaping @MainActor () -> DomainState,
        currentClipboardNotice: @escaping @MainActor () -> Bool?,
        migrationAuthorizationRequirement: @escaping @MainActor () -> MutationAuthorizationRequirement = { .notRequired },
        migrateLegacyClipboardNoticeIfNeeded: @escaping @MainActor () async throws -> Void,
        openDomainIfNeeded: @escaping @MainActor (_ wrappingRootKey: Data) async throws -> Void,
        updateClipboardNotice: @escaping @MainActor (_ enabled: Bool, _ wrappingRootKey: Data) async throws -> Void,
        pendingRecoveryAuthorizationRequirement: @escaping @MainActor () -> MutationAuthorizationRequirement = { .notRequired },
        recoverPendingMutation: @escaping @MainActor () async throws -> RecoveryOutcome,
        resetAuthorizationRequirement: @escaping @MainActor () -> MutationAuthorizationRequirement = { .notRequired },
        resetDomain: @escaping @MainActor () async throws -> Void,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.mode = .mainWindowLive
        self.openMainWindowAction = nil
        self.traceStore = traceStore
        self.liveDependencies = LiveDependencies(
            evaluateAccessGate: evaluateAccessGate,
            hasAuthorizationHandoffContext: hasAuthorizationHandoffContext,
            authorizeSharedRight: authorizeSharedRight,
            currentWrappingRootKey: currentWrappingRootKey,
            syncPreAuthorizationState: syncPreAuthorizationState,
            currentDomainState: currentDomainState,
            currentClipboardNotice: currentClipboardNotice,
            migrationAuthorizationRequirement: migrationAuthorizationRequirement,
            migrateLegacyClipboardNoticeIfNeeded: migrateLegacyClipboardNoticeIfNeeded,
            openDomainIfNeeded: openDomainIfNeeded,
            updateClipboardNotice: updateClipboardNotice,
            pendingRecoveryAuthorizationRequirement: pendingRecoveryAuthorizationRequirement,
            recoverPendingMutation: recoverPendingMutation,
            resetAuthorizationRequirement: resetAuthorizationRequirement,
            resetDomain: resetDomain
        )
        self.sectionState = .locked
    }

    init(
        mode: Mode,
        openMainWindowAction: (() -> Void)? = nil,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.mode = mode
        self.openMainWindowAction = openMainWindowAction
        self.liveDependencies = nil
        self.traceStore = traceStore
        switch mode {
        case .mainWindowLive:
            self.sectionState = .locked
        case .settingsSceneProxy:
            self.sectionState = .settingsSceneProxy
        case .tutorialSandbox:
            self.sectionState = .tutorialSandbox
        }
    }

    func refreshSettingsSection() async {
        traceHostEvent("protectedSettings.refresh.start")
        guard let liveDependencies else {
            traceHostEvent("protectedSettings.refresh.finish", metadata: ["result": "noLiveDependencies"])
            return
        }

        let preAuthorizationState = syncPreAuthorizationSectionState(liveDependencies)
        traceHostEvent(
            "protectedSettings.refresh.preAuthorization",
            metadata: stateMetadata(liveDependencies, domainState: preAuthorizationState)
        )
        switch preAuthorizationState {
        case .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            traceHostEvent(
                "protectedSettings.refresh.finish",
                metadata: stateMetadata(liveDependencies, domainState: preAuthorizationState)
                    .merging(["result": "blockedByDomainState"], uniquingKeysWith: { _, new in new })
            )
            return
        case .unlocked:
            traceHostEvent(
                "protectedSettings.refresh.finish",
                metadata: stateMetadata(liveDependencies, domainState: preAuthorizationState)
                    .merging(["result": "alreadyUnlocked"], uniquingKeysWith: { _, new in new })
            )
            return
        case .locked:
            break
        }

        let decision = currentAccessGateDecision(liveDependencies)
        switch decision {
        case .frameworkRecoveryNeeded:
            liveDependencies.syncPreAuthorizationState()
            syncSectionStateFromStore(liveDependencies)
        case .pendingMutationRecoveryRequired:
            liveDependencies.syncPreAuthorizationState()
            syncSectionStateFromStore(liveDependencies)
        case .noProtectedDomainPresent:
            sectionState = .locked
        case .authorizationRequired:
            let hasHandoff = liveDependencies.hasAuthorizationHandoffContext()
            if hasHandoff {
                traceHostEvent(
                    "protectedSettings.refresh.autoOpenHandoff",
                    metadata: [
                        "gateDecision": accessGateTraceValue(decision),
                        "hasHandoff": "true",
                        "result": "start"
                    ]
                )
                let didOpen = await openProtectedSettings(
                    using: liveDependencies,
                    localizedReason: settingsLocalizedReason,
                    authorizationMode: .handoffOnly
                )
                traceHostEvent(
                    "protectedSettings.refresh.autoOpenHandoff",
                    metadata: stateMetadata(liveDependencies)
                        .merging(
                            [
                                "gateDecision": accessGateTraceValue(decision),
                                "hasHandoff": "true",
                                "result": didOpen ? "opened" : "notOpened"
                            ],
                            uniquingKeysWith: { _, new in new }
                        )
                )
            } else {
                sectionState = .locked
                traceHostEvent(
                    "protectedSettings.refresh.autoOpenHandoff",
                    metadata: [
                        "gateDecision": accessGateTraceValue(decision),
                        "hasHandoff": "false",
                        "result": "skipped"
                    ]
                )
            }
        case .alreadyAuthorized:
            _ = await openProtectedSettings(
                using: liveDependencies,
                localizedReason: settingsLocalizedReason,
                authorizationMode: .requireExistingAuthorization
            )
        }
        traceHostEvent(
            "protectedSettings.refresh.finish",
            metadata: stateMetadata(liveDependencies)
                .merging(["result": "gateEvaluated", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
        )
    }

    func unlockForSettings() async {
        traceHostEvent("protectedSettings.unlock.start")
        guard let liveDependencies else {
            traceHostEvent("protectedSettings.unlock.finish", metadata: ["result": "noLiveDependencies"])
            return
        }

        let didOpen = await openProtectedSettings(
            using: liveDependencies,
            localizedReason: settingsLocalizedReason
        )
        traceHostEvent(
            "protectedSettings.unlock.finish",
            metadata: stateMetadata(liveDependencies)
                .merging(["result": didOpen ? "opened" : "notOpened"], uniquingKeysWith: { _, new in new })
        )
    }

    func setClipboardNoticeEnabled(_ isEnabled: Bool) async {
        guard let liveDependencies else {
            return
        }

        sectionState = .loading
        do {
            guard try await ensureProtectedSettingsAccess(
                using: liveDependencies,
                localizedReason: settingsLocalizedReason
            ) else {
                syncSectionStateFromStore(liveDependencies)
                return
            }

            let wrappingRootKey = try liveDependencies.currentWrappingRootKey()
            try await liveDependencies.updateClipboardNotice(
                isEnabled,
                wrappingRootKey
            )
            sectionState = .available(clipboardNoticeEnabled: isEnabled)
        } catch {
            syncSectionStateAfterOperationError(liveDependencies)
        }
    }

    func retryPendingRecovery() async {
        guard let liveDependencies else {
            return
        }

        sectionState = .loading
        do {
            guard try await authorizeMutationIfNeeded(
                using: liveDependencies,
                requirement: liveDependencies.pendingRecoveryAuthorizationRequirement(),
                localizedReason: settingsLocalizedReason,
                operation: "pendingRecovery"
            ) else {
                return
            }

            let outcome = try await liveDependencies.recoverPendingMutation()
            switch outcome {
            case .resumedToSteadyState:
                liveDependencies.syncPreAuthorizationState()
                syncSectionStateFromStore(liveDependencies)
            case .retryablePending:
                liveDependencies.syncPreAuthorizationState()
                syncSectionStateFromStore(liveDependencies)
            case .resetRequired:
                sectionState = .pendingResetRequired
            case .frameworkRecoveryNeeded:
                sectionState = .frameworkUnavailable
            }
        } catch {
            liveDependencies.syncPreAuthorizationState()
            syncSectionStateAfterOperationError(liveDependencies)
        }
    }

    func resetProtectedSettingsDomain() async {
        guard let liveDependencies else {
            return
        }

        sectionState = .loading
        do {
            guard try await authorizeMutationIfNeeded(
                using: liveDependencies,
                requirement: liveDependencies.resetAuthorizationRequirement(),
                localizedReason: settingsLocalizedReason,
                operation: "reset"
            ) else {
                return
            }

            try await liveDependencies.resetDomain()

            let didOpen = await openProtectedSettings(
                using: liveDependencies,
                localizedReason: settingsLocalizedReason
            )
            if !didOpen {
                liveDependencies.syncPreAuthorizationState()
                syncSectionStateFromStore(liveDependencies)
            }
        } catch {
            liveDependencies.syncPreAuthorizationState()
            syncSectionStateAfterOperationError(liveDependencies)
        }
    }

    func clipboardNoticeDecision() async -> Bool {
        guard let liveDependencies else {
            return true
        }

        do {
            liveDependencies.syncPreAuthorizationState()
            syncSectionStateFromStore(liveDependencies)
            guard try await ensureProtectedSettingsAccess(
                using: liveDependencies,
                localizedReason: clipboardLocalizedReason,
                authorizationMode: .requireExistingAuthorization
            ) else {
                return true
            }

            return liveDependencies.currentClipboardNotice() ?? true
        } catch {
            return true
        }
    }

    func disableClipboardNotice() async {
        await setClipboardNoticeEnabled(false)
    }

    func invalidateForContentClearGeneration(_ generation: Int) async {
        traceHostEvent(
            "protectedSettings.invalidateForContentClear.start",
            metadata: ["generation": String(generation)]
        )
        guard let liveDependencies else {
            traceHostEvent(
                "protectedSettings.invalidateForContentClear.finish",
                metadata: ["result": "noLiveDependencies", "generation": String(generation)]
            )
            return
        }

        await Task.yield()
        await refreshSettingsSection()
        traceHostEvent(
            "protectedSettings.invalidateForContentClear.finish",
            metadata: stateMetadata(liveDependencies)
                .merging(["result": "refreshed", "generation": String(generation)], uniquingKeysWith: { _, new in new })
        )
    }

    func refreshAfterAppAuthenticationGeneration(_ generation: Int) async {
        traceHostEvent(
            "protectedSettings.postAuthenticationRefresh.start",
            metadata: ["generation": String(generation)]
        )
        guard let liveDependencies else {
            traceHostEvent(
                "protectedSettings.postAuthenticationRefresh.finish",
                metadata: ["result": "noLiveDependencies", "generation": String(generation)]
            )
            return
        }

        await refreshSettingsSection()
        traceHostEvent(
            "protectedSettings.postAuthenticationRefresh.finish",
            metadata: stateMetadata(liveDependencies)
                .merging(["result": "refreshed", "generation": String(generation)], uniquingKeysWith: { _, new in new })
        )
    }

    func openMainWindow() {
        openMainWindowAction?()
    }

    private func openProtectedSettings(
        using liveDependencies: LiveDependencies,
        localizedReason: String,
        authorizationMode: AccessAuthorizationMode = .authorizeIfNeeded
    ) async -> Bool {
        sectionState = .loading
        traceHostEvent(
            "protectedSettings.open.start",
            metadata: stateMetadata(liveDependencies)
                .merging(["authorizationMode": authorizationModeTraceValue(authorizationMode)], uniquingKeysWith: { _, new in new })
        )
        do {
            guard try await ensureProtectedSettingsAccess(
                using: liveDependencies,
                localizedReason: localizedReason,
                authorizationMode: authorizationMode
            ) else {
                syncSectionStateFromStore(liveDependencies)
                traceHostEvent(
                    "protectedSettings.open.finish",
                    metadata: stateMetadata(liveDependencies)
                        .merging(["result": "accessDenied"], uniquingKeysWith: { _, new in new })
                )
                return false
            }

            syncSectionStateFromStore(liveDependencies)
            if case .available = sectionState {
                traceHostEvent(
                    "protectedSettings.open.finish",
                    metadata: stateMetadata(liveDependencies)
                        .merging(["result": "available"], uniquingKeysWith: { _, new in new })
                )
                return true
            }
            traceHostEvent(
                "protectedSettings.open.finish",
                metadata: stateMetadata(liveDependencies)
                    .merging(["result": "openedButUnavailable"], uniquingKeysWith: { _, new in new })
            )
            return false
        } catch {
            syncSectionStateAfterOperationError(liveDependencies)
            traceHostEvent(
                "protectedSettings.open.finish",
                metadata: stateMetadata(liveDependencies)
                    .merging(traceErrorMetadata(error, extra: ["result": "error"]), uniquingKeysWith: { _, new in new })
            )
            return false
        }
    }

    private func authorizeMutationIfNeeded(
        using liveDependencies: LiveDependencies,
        requirement: MutationAuthorizationRequirement,
        localizedReason: String,
        operation: String
    ) async throws -> Bool {
        traceHostEvent(
            "protectedSettings.mutationAuthorization.start",
            metadata: [
                "operation": operation,
                "requirement": mutationAuthorizationRequirementTraceValue(requirement)
            ]
        )

        switch requirement {
        case .notRequired:
            traceHostEvent(
                "protectedSettings.mutationAuthorization.finish",
                metadata: ["operation": operation, "result": "notRequired"]
            )
            return true
        case .frameworkRecoveryNeeded:
            liveDependencies.syncPreAuthorizationState()
            sectionState = .frameworkUnavailable
            traceHostEvent(
                "protectedSettings.mutationAuthorization.finish",
                metadata: ["operation": operation, "result": "frameworkRecoveryNeeded"]
            )
            return false
        case .wrappingRootKeyRequired:
            let authorizationResult = await liveDependencies.authorizeSharedRight(
                localizedReason,
                .allowInteraction
            )
            traceHostEvent(
                "protectedSettings.mutationAuthorization.result",
                metadata: [
                    "operation": operation,
                    "outcome": authorizationOutcomeTraceValue(authorizationResult)
                ]
            )
            switch authorizationResult {
            case .authorized:
                var wrappingRootKey = try liveDependencies.currentWrappingRootKey()
                wrappingRootKey.resetBytes(in: 0..<wrappingRootKey.count)
                traceHostEvent(
                    "protectedSettings.mutationAuthorization.finish",
                    metadata: ["operation": operation, "result": "authorized"]
                )
                return true
            case .cancelledOrDenied:
                liveDependencies.syncPreAuthorizationState()
                syncSectionStateFromStore(liveDependencies)
                traceHostEvent(
                    "protectedSettings.mutationAuthorization.finish",
                    metadata: ["operation": operation, "result": "cancelledOrDenied"]
                )
                return false
            case .frameworkRecoveryNeeded:
                liveDependencies.syncPreAuthorizationState()
                sectionState = .frameworkUnavailable
                traceHostEvent(
                    "protectedSettings.mutationAuthorization.finish",
                    metadata: ["operation": operation, "result": "frameworkRecoveryNeeded"]
                )
                return false
            }
        }
    }

    private func migrateLegacyClipboardNoticeIfNeeded(
        using liveDependencies: LiveDependencies,
        gateDecision: AccessGateDecision,
        preauthorized: Bool
    ) async throws {
        traceHostEvent(
            "protectedSettings.legacyMigration.start",
            metadata: [
                "gateDecision": accessGateTraceValue(gateDecision),
                "preauthorized": preauthorized ? "true" : "false"
            ]
        )
        do {
            try await liveDependencies.migrateLegacyClipboardNoticeIfNeeded()
            traceHostEvent(
                "protectedSettings.legacyMigration.finish",
                metadata: [
                    "result": "success",
                    "gateDecision": accessGateTraceValue(gateDecision),
                    "preauthorized": preauthorized ? "true" : "false"
                ]
            )
        } catch {
            traceHostEvent(
                "protectedSettings.legacyMigration.finish",
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
        using liveDependencies: LiveDependencies,
        localizedReason: String,
        authorizationMode: AccessAuthorizationMode = .authorizeIfNeeded
    ) async throws -> Bool {
        traceHostEvent(
            "protectedSettings.ensureAccess.start",
            metadata: ["authorizationMode": authorizationModeTraceValue(authorizationMode)]
        )
        let preAuthorizationState = syncPreAuthorizationSectionState(liveDependencies)
        traceHostEvent(
            "protectedSettings.ensureAccess.preAuthorization",
            metadata: stateMetadata(liveDependencies, domainState: preAuthorizationState)
        )
        switch preAuthorizationState {
        case .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            traceHostEvent(
                "protectedSettings.ensureAccess.finish",
                metadata: stateMetadata(liveDependencies, domainState: preAuthorizationState)
                    .merging(["result": "blockedByDomainState"], uniquingKeysWith: { _, new in new })
            )
            return false
        case .locked, .unlocked:
            break
        }

        let decision = currentAccessGateDecision(liveDependencies)
        switch decision {
        case .frameworkRecoveryNeeded:
            liveDependencies.syncPreAuthorizationState()
            sectionState = .frameworkUnavailable
            traceHostEvent(
                "protectedSettings.ensureAccess.finish",
                metadata: stateMetadata(liveDependencies)
                    .merging(["result": "frameworkRecoveryNeeded", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
            )
            return false
        case .pendingMutationRecoveryRequired:
            liveDependencies.syncPreAuthorizationState()
            syncSectionStateFromStore(liveDependencies)
            traceHostEvent(
                "protectedSettings.ensureAccess.finish",
                metadata: stateMetadata(liveDependencies)
                    .merging(["result": "pendingMutationRecoveryRequired", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
            )
            return false
        case .noProtectedDomainPresent:
            guard authorizationMode == .authorizeIfNeeded else {
                sectionState = .locked
                traceHostEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata(liveDependencies)
                        .merging(["result": "authorizationModeBlocked", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
            let migrationRequirement = liveDependencies.migrationAuthorizationRequirement()
            let didPreauthorizeMigration: Bool
            switch migrationRequirement {
            case .notRequired:
                didPreauthorizeMigration = false
            case .wrappingRootKeyRequired:
                guard try await authorizeMutationIfNeeded(
                    using: liveDependencies,
                    requirement: migrationRequirement,
                    localizedReason: localizedReason,
                    operation: "legacyMigration"
                ) else {
                    traceHostEvent(
                        "protectedSettings.ensureAccess.finish",
                        metadata: stateMetadata(liveDependencies)
                            .merging(["result": "migrationAuthorizationBlocked", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                    )
                    return false
                }
                didPreauthorizeMigration = true
            case .frameworkRecoveryNeeded:
                liveDependencies.syncPreAuthorizationState()
                sectionState = .frameworkUnavailable
                traceHostEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata(liveDependencies)
                        .merging(["result": "migrationFrameworkRecoveryNeeded", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
            try await migrateLegacyClipboardNoticeIfNeeded(
                using: liveDependencies,
                gateDecision: decision,
                preauthorized: didPreauthorizeMigration
            )
            if !didPreauthorizeMigration {
                traceHostEvent("protectedSettings.authorization.request", metadata: ["gateDecision": accessGateTraceValue(decision)])
                let authorizationResult = await liveDependencies.authorizeSharedRight(
                    localizedReason,
                    .allowInteraction
                )
                traceHostEvent(
                    "protectedSettings.authorization.result",
                    metadata: ["outcome": authorizationOutcomeTraceValue(authorizationResult)]
                )
                switch authorizationResult {
                case .authorized:
                    break
                case .cancelledOrDenied:
                    sectionState = .locked
                    traceHostEvent(
                        "protectedSettings.ensureAccess.finish",
                        metadata: stateMetadata(liveDependencies)
                            .merging(["result": "cancelledOrDenied", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                    )
                    return false
                case .frameworkRecoveryNeeded:
                    sectionState = .frameworkUnavailable
                    traceHostEvent(
                        "protectedSettings.ensureAccess.finish",
                        metadata: stateMetadata(liveDependencies)
                            .merging(["result": "authorizationFrameworkRecoveryNeeded", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                    )
                    return false
                }
            }
        case .authorizationRequired:
            guard authorizationMode == .authorizeIfNeeded || authorizationMode == .handoffOnly else {
                sectionState = .locked
                traceHostEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata(liveDependencies)
                        .merging(["result": "authorizationModeBlocked", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
            let interactionMode: AuthorizationInteractionMode
            switch authorizationMode {
            case .authorizeIfNeeded:
                interactionMode = .allowInteraction
            case .handoffOnly:
                guard liveDependencies.hasAuthorizationHandoffContext() else {
                    sectionState = .locked
                    traceHostEvent(
                        "protectedSettings.ensureAccess.finish",
                        metadata: stateMetadata(liveDependencies)
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
                sectionState = .locked
                traceHostEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata(liveDependencies)
                        .merging(["result": "authorizationModeBlocked", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
            traceHostEvent("protectedSettings.authorization.request", metadata: ["gateDecision": accessGateTraceValue(decision)])
            let authorizationResult = await liveDependencies.authorizeSharedRight(
                localizedReason,
                interactionMode
            )
            traceHostEvent(
                "protectedSettings.authorization.result",
                metadata: ["outcome": authorizationOutcomeTraceValue(authorizationResult)]
            )
            switch authorizationResult {
            case .authorized:
                try await migrateLegacyClipboardNoticeIfNeeded(
                    using: liveDependencies,
                    gateDecision: decision,
                    preauthorized: true
                )
            case .cancelledOrDenied:
                sectionState = .locked
                traceHostEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata(liveDependencies)
                        .merging(["result": "cancelledOrDenied", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            case .frameworkRecoveryNeeded:
                sectionState = .frameworkUnavailable
                traceHostEvent(
                    "protectedSettings.ensureAccess.finish",
                    metadata: stateMetadata(liveDependencies)
                        .merging(["result": "authorizationFrameworkRecoveryNeeded", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
                )
                return false
            }
        case .alreadyAuthorized:
            try await migrateLegacyClipboardNoticeIfNeeded(
                using: liveDependencies,
                gateDecision: decision,
                preauthorized: true
            )
        }

        let wrappingRootKey = try liveDependencies.currentWrappingRootKey()
        traceHostEvent(
            "protectedSettings.openDomain.start",
            metadata: ["gateDecision": accessGateTraceValue(decision)]
        )
        do {
            try await liveDependencies.openDomainIfNeeded(wrappingRootKey)
            traceHostEvent(
                "protectedSettings.openDomain.finish",
                metadata: stateMetadata(liveDependencies)
                    .merging(["result": "success", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
            )
        } catch {
            traceHostEvent(
                "protectedSettings.openDomain.finish",
                metadata: stateMetadata(liveDependencies)
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
        traceHostEvent(
            "protectedSettings.ensureAccess.finish",
            metadata: stateMetadata(liveDependencies)
                .merging(["result": "success", "gateDecision": accessGateTraceValue(decision)], uniquingKeysWith: { _, new in new })
        )
        return true
    }

    private func currentAccessGateDecision(
        _ liveDependencies: LiveDependencies
    ) -> AccessGateDecision {
        let decision = liveDependencies.evaluateAccessGate(!hasEvaluatedProtectedAccessGate)
        traceHostEvent(
            "protectedSettings.gate.decision",
            metadata: [
                "decision": accessGateTraceValue(decision),
                "isFirstProtectedAccess": hasEvaluatedProtectedAccessGate ? "false" : "true"
            ]
        )
        hasEvaluatedProtectedAccessGate = true
        return decision
    }

    private func syncSectionStateFromStore(_ liveDependencies: LiveDependencies) {
        switch liveDependencies.currentDomainState() {
        case .locked:
            sectionState = .locked
        case .unlocked:
            sectionState = .available(
                clipboardNoticeEnabled: liveDependencies.currentClipboardNotice() ?? true
            )
        case .recoveryNeeded:
            sectionState = .recoveryNeeded
        case .pendingRetryRequired:
            sectionState = .pendingRetryRequired
        case .pendingResetRequired:
            sectionState = .pendingResetRequired
        case .frameworkUnavailable:
            sectionState = .frameworkUnavailable
        }
        traceHostEvent(
            "protectedSettings.sectionState.synced",
            metadata: stateMetadata(liveDependencies)
        )
    }

    private func syncSectionStateAfterOperationError(_ liveDependencies: LiveDependencies) {
        liveDependencies.syncPreAuthorizationState()
        switch liveDependencies.currentDomainState() {
        case .locked:
            sectionState = .frameworkUnavailable
        case .unlocked, .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            syncSectionStateFromStore(liveDependencies)
        }
        traceHostEvent(
            "protectedSettings.sectionState.errorSynced",
            metadata: stateMetadata(liveDependencies)
        )
    }

    @discardableResult
    private func syncPreAuthorizationSectionState(
        _ liveDependencies: LiveDependencies
    ) -> DomainState {
        liveDependencies.syncPreAuthorizationState()
        let domainState = liveDependencies.currentDomainState()
        syncSectionStateFromStore(liveDependencies)
        return domainState
    }

    private func traceHostEvent(
        _ name: String,
        metadata: [String: String] = [:]
    ) {
        traceStore?.record(
            category: .operation,
            name: name,
            metadata: metadata.merging(["mode": modeTraceValue(mode)], uniquingKeysWith: { _, new in new })
        )
    }

    private func stateMetadata(
        _ liveDependencies: LiveDependencies,
        domainState: DomainState? = nil
    ) -> [String: String] {
        [
            "domainState": domainStateTraceValue(domainState ?? liveDependencies.currentDomainState()),
            "sectionState": sectionStateTraceValue(sectionState)
        ]
    }

    private func traceErrorMetadata(
        _ error: Error,
        extra: [String: String] = [:]
    ) -> [String: String] {
        var metadata = extra
        metadata["errorType"] = String(describing: type(of: error))
        return metadata
    }

    private func modeTraceValue(_ mode: Mode) -> String {
        switch mode {
        case .mainWindowLive:
            "mainWindowLive"
        case .settingsSceneProxy:
            "settingsSceneProxy"
        case .tutorialSandbox:
            "tutorialSandbox"
        }
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
        case .authorized:
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

    private func domainStateTraceValue(_ state: DomainState) -> String {
        switch state {
        case .locked:
            "locked"
        case .unlocked:
            "unlocked"
        case .recoveryNeeded:
            "recoveryNeeded"
        case .pendingRetryRequired:
            "pendingRetryRequired"
        case .pendingResetRequired:
            "pendingResetRequired"
        case .frameworkUnavailable:
            "frameworkUnavailable"
        }
    }

    private func sectionStateTraceValue(_ state: SectionState) -> String {
        switch state {
        case .loading:
            "loading"
        case .locked:
            "locked"
        case .available:
            "available"
        case .recoveryNeeded:
            "recoveryNeeded"
        case .pendingRetryRequired:
            "pendingRetryRequired"
        case .pendingResetRequired:
            "pendingResetRequired"
        case .frameworkUnavailable:
            "frameworkUnavailable"
        case .settingsSceneProxy:
            "settingsSceneProxy"
        case .tutorialSandbox:
            "tutorialSandbox"
        }
    }

    private var settingsLocalizedReason: String {
        String(
            localized: "protectedSettings.unlock.reason",
            defaultValue: "Authenticate to access protected preferences."
        )
    }

    private var clipboardLocalizedReason: String {
        String(
            localized: "protectedSettings.clipboard.reason",
            defaultValue: "Authenticate to access the protected clipboard preference."
        )
    }
}

private struct ProtectedSettingsHostKey: EnvironmentKey {
    static let defaultValue: ProtectedSettingsHost? = nil
}

extension EnvironmentValues {
    var protectedSettingsHost: ProtectedSettingsHost? {
        get { self[ProtectedSettingsHostKey.self] }
        set { self[ProtectedSettingsHostKey.self] = newValue }
    }
}
