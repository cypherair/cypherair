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
        case tutorialSandbox
    }

    let mode: Mode
    private let liveDependencies: ProtectedSettingsAccessCoordinator.Dependencies?

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
        ensureCommittedSettingsIfNeeded: @escaping @MainActor () async throws -> Void,
        openDomainIfNeeded: @escaping @MainActor (_ wrappingRootKey: Data) async throws -> Void,
        updateClipboardNotice: @escaping @MainActor (_ enabled: Bool, _ wrappingRootKey: Data) async throws -> Void,
        pendingRecoveryAuthorizationRequirement: @escaping @MainActor () -> MutationAuthorizationRequirement = { .notRequired },
        recoverPendingMutation: @escaping @MainActor () async throws -> RecoveryOutcome,
        recoverPendingMutationWithContext: (@MainActor (_ authenticationContext: LAContext?) async throws -> RecoveryOutcome)? = nil,
        resetAuthorizationRequirement: @escaping @MainActor () -> MutationAuthorizationRequirement = { .notRequired },
        resetDomain: @escaping @MainActor () async throws -> Void
    ) {
        self.mode = .mainWindowLive
        let liveDependencies = ProtectedSettingsAccessCoordinator.Dependencies(
            evaluateAccessGate: evaluateAccessGate,
            hasAuthorizationHandoffContext: hasAuthorizationHandoffContext,
            authorizeSharedRight: authorizeSharedRight,
            currentWrappingRootKey: currentWrappingRootKey,
            syncPreAuthorizationState: syncPreAuthorizationState,
            currentDomainState: currentDomainState,
            currentClipboardNotice: currentClipboardNotice,
            ensureCommittedSettingsIfNeeded: ensureCommittedSettingsIfNeeded,
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
        mode: Mode
    ) {
        self.mode = mode
        self.liveDependencies = nil
        self.accessCoordinator = nil
        switch mode {
        case .mainWindowLive:
            self.sectionState = .locked
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
                }
            )
        )
    }

    func refreshSettingsSection() async {
        guard let liveDependencies, let accessCoordinator else {
            return
        }

        let preAuthorizationState = syncPreAuthorizationSectionState(liveDependencies)
        switch preAuthorizationState {
        case .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            return
        case .unlocked:
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
                _ = await accessCoordinator.openProtectedSettings(
                    localizedReason: settingsLocalizedReason,
                    authorizationMode: .handoffOnly
                )
            } else {
                sectionState = .locked
            }
        case .alreadyAuthorized:
            _ = await accessCoordinator.openProtectedSettings(
                localizedReason: settingsLocalizedReason,
                authorizationMode: .requireExistingAuthorization
            )
        }
    }

    func unlockForSettings() async {
        guard let accessCoordinator else {
            return
        }

        _ = await accessCoordinator.openProtectedSettings(
            localizedReason: settingsLocalizedReason
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
        guard liveDependencies != nil else {
            return
        }

        await Task.yield()
        await refreshSettingsSection()
    }

    func refreshAfterAppAuthenticationGeneration(_ generation: Int) async {
        guard liveDependencies != nil else {
            return
        }

        await refreshSettingsSection()
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
