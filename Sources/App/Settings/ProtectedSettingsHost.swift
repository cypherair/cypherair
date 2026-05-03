import Foundation
import LocalAuthentication
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
        case authorizedWithContext(LAContext)
        case cancelledOrDenied
        case frameworkRecoveryNeeded

        static func == (lhs: AuthorizationOutcome, rhs: AuthorizationOutcome) -> Bool {
            switch (lhs, rhs) {
            case (.authorized, .authorized),
                 (.authorized, .authorizedWithContext),
                 (.authorizedWithContext, .authorized),
                 (.authorizedWithContext, .authorizedWithContext),
                 (.cancelledOrDenied, .cancelledOrDenied),
                 (.frameworkRecoveryNeeded, .frameworkRecoveryNeeded):
                return true
            default:
                return false
            }
        }

        var authenticationContext: LAContext? {
            if case .authorizedWithContext(let context) = self {
                return context
            }
            return nil
        }
    }

    enum AuthorizationInteractionMode: Equatable {
        case allowInteraction
        case handoffOnly
        case requireReusableContext
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

    let mode: Mode
    private let openMainWindowAction: (() -> Void)?
    private let liveDependencies: ProtectedSettingsAccessCoordinator.Dependencies?
    private let traceStore: AuthLifecycleTraceStore?

    private(set) var sectionState: SectionState

    @ObservationIgnored
    private var accessCoordinator: ProtectedSettingsAccessCoordinator?

    init(
        evaluateAccessGate: @escaping @MainActor (_ isFirstProtectedAccess: Bool) -> AccessGateDecision,
        hasAuthorizationHandoffContext: @escaping @MainActor () -> Bool = { false },
        authorizeSharedRight: @escaping @MainActor (_ localizedReason: String, _ interactionMode: AuthorizationInteractionMode) async -> AuthorizationOutcome,
        currentWrappingRootKey: @escaping @MainActor () throws -> Data,
        syncPreAuthorizationState: @escaping @MainActor () -> Void,
        currentDomainState: @escaping @MainActor () -> DomainState,
        currentClipboardNotice: @escaping @MainActor () -> Bool?,
        migrationAuthorizationRequirement: @escaping @MainActor () -> MutationAuthorizationRequirement = { .notRequired },
        ensureCommittedAndMigrateSettingsIfNeeded: @escaping @MainActor () async throws -> Void,
        openDomainIfNeeded: @escaping @MainActor (_ wrappingRootKey: Data) async throws -> Void,
        updateClipboardNotice: @escaping @MainActor (_ enabled: Bool, _ wrappingRootKey: Data) async throws -> Void,
        pendingRecoveryAuthorizationRequirement: @escaping @MainActor () -> MutationAuthorizationRequirement = { .notRequired },
        recoverPendingMutation: @escaping @MainActor () async throws -> RecoveryOutcome,
        recoverPendingMutationWithContext: (@MainActor (_ authenticationContext: LAContext?) async throws -> RecoveryOutcome)? = nil,
        resetAuthorizationRequirement: @escaping @MainActor () -> MutationAuthorizationRequirement = { .notRequired },
        resetDomain: @escaping @MainActor () async throws -> Void,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.mode = .mainWindowLive
        self.openMainWindowAction = nil
        self.traceStore = traceStore
        let liveDependencies = ProtectedSettingsAccessCoordinator.Dependencies(
            evaluateAccessGate: evaluateAccessGate,
            hasAuthorizationHandoffContext: hasAuthorizationHandoffContext,
            authorizeSharedRight: authorizeSharedRight,
            currentWrappingRootKey: currentWrappingRootKey,
            syncPreAuthorizationState: syncPreAuthorizationState,
            currentDomainState: currentDomainState,
            currentClipboardNotice: currentClipboardNotice,
            migrationAuthorizationRequirement: migrationAuthorizationRequirement,
            ensureCommittedAndMigrateSettingsIfNeeded: ensureCommittedAndMigrateSettingsIfNeeded,
            openDomainIfNeeded: openDomainIfNeeded,
            updateClipboardNotice: updateClipboardNotice,
            pendingRecoveryAuthorizationRequirement: pendingRecoveryAuthorizationRequirement,
            recoverPendingMutation: recoverPendingMutationWithContext ?? { _ in
                try await recoverPendingMutation()
            },
            resetAuthorizationRequirement: resetAuthorizationRequirement,
            resetDomain: resetDomain
        )
        self.liveDependencies = liveDependencies
        self.sectionState = .locked
        self.accessCoordinator = nil
        self.accessCoordinator = makeAccessCoordinator(liveDependencies)
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
        self.accessCoordinator = nil
        switch mode {
        case .mainWindowLive:
            self.sectionState = .locked
        case .settingsSceneProxy:
            self.sectionState = .settingsSceneProxy
        case .tutorialSandbox:
            self.sectionState = .tutorialSandbox
        }
    }

    private func makeAccessCoordinator(
        _ liveDependencies: ProtectedSettingsAccessCoordinator.Dependencies
    ) -> ProtectedSettingsAccessCoordinator {
        ProtectedSettingsAccessCoordinator(
            dependencies: liveDependencies,
            stateAdapter: ProtectedSettingsAccessCoordinator.StateAdapter(
                currentSectionState: { [weak self] in
                    self?.sectionState ?? .frameworkUnavailable
                },
                setSectionState: { [weak self] state in
                    self?.sectionState = state
                },
                syncPreAuthorizationSectionState: { [weak self] in
                    self?.syncPreAuthorizationSectionState(liveDependencies) ?? .frameworkUnavailable
                },
                syncSectionStateFromStore: { [weak self] in
                    self?.syncSectionStateFromStore(liveDependencies)
                },
                syncSectionStateAfterOperationError: { [weak self] in
                    self?.syncSectionStateAfterOperationError(liveDependencies)
                },
                stateMetadata: { [weak self] domainState in
                    self?.stateMetadata(liveDependencies, domainState: domainState) ?? [:]
                }
            ),
            traceEvent: { [weak self] name, metadata in
                self?.traceHostEvent(name, metadata: metadata)
            }
        )
    }

    func refreshSettingsSection() async {
        traceHostEvent("protectedSettings.refresh.start")
        guard let liveDependencies, let accessCoordinator else {
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

        let decision = accessCoordinator.currentAccessGateDecision()
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
                let didOpen = await accessCoordinator.openProtectedSettings(
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
            _ = await accessCoordinator.openProtectedSettings(
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
        guard let liveDependencies, let accessCoordinator else {
            traceHostEvent("protectedSettings.unlock.finish", metadata: ["result": "noLiveDependencies"])
            return
        }

        let didOpen = await accessCoordinator.openProtectedSettings(
            localizedReason: settingsLocalizedReason
        )
        traceHostEvent(
            "protectedSettings.unlock.finish",
            metadata: stateMetadata(liveDependencies)
                .merging(["result": didOpen ? "opened" : "notOpened"], uniquingKeysWith: { _, new in new })
        )
    }

    func setClipboardNoticeEnabled(_ isEnabled: Bool) async {
        await accessCoordinator?.setClipboardNoticeEnabled(
            isEnabled,
            localizedReason: settingsLocalizedReason
        )
    }

    func retryPendingRecovery() async {
        await accessCoordinator?.retryPendingRecovery(localizedReason: settingsLocalizedReason)
    }

    func resetProtectedSettingsDomain() async {
        await accessCoordinator?.resetProtectedSettingsDomain(localizedReason: settingsLocalizedReason)
    }

    func clipboardNoticeDecision() async -> Bool {
        await accessCoordinator?.clipboardNoticeDecision(
            localizedReason: clipboardLocalizedReason
        ) ?? true
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

    private func syncSectionStateFromStore(_ liveDependencies: ProtectedSettingsAccessCoordinator.Dependencies) {
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
            "protectedSettings.rowState.synced",
            metadata: stateMetadata(liveDependencies)
        )
    }

    private func syncSectionStateAfterOperationError(
        _ liveDependencies: ProtectedSettingsAccessCoordinator.Dependencies
    ) {
        liveDependencies.syncPreAuthorizationState()
        switch liveDependencies.currentDomainState() {
        case .locked:
            sectionState = .frameworkUnavailable
        case .unlocked, .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            syncSectionStateFromStore(liveDependencies)
        }
        traceHostEvent(
            "protectedSettings.rowState.errorSynced",
            metadata: stateMetadata(liveDependencies)
        )
    }

    @discardableResult
    private func syncPreAuthorizationSectionState(
        _ liveDependencies: ProtectedSettingsAccessCoordinator.Dependencies
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
        _ liveDependencies: ProtectedSettingsAccessCoordinator.Dependencies,
        domainState: DomainState? = nil
    ) -> [String: String] {
        [
            "domainState": domainStateTraceValue(domainState ?? liveDependencies.currentDomainState()),
            "sectionState": sectionStateTraceValue(sectionState)
        ]
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
            defaultValue: "Authenticate to access Clipboard Safety Notice."
        )
    }

    private var clipboardLocalizedReason: String {
        String(
            localized: "protectedSettings.clipboard.reason",
            defaultValue: "Authenticate to access Clipboard Safety Notice."
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
