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

    enum RecoveryOutcome: Equatable {
        case resumedToSteadyState
        case retryablePending
        case resetRequired
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

    private enum AccessAuthorizationMode {
        case authorizeIfNeeded
        case requireExistingAuthorization
    }

    private struct LiveDependencies: @unchecked Sendable {
        let evaluateAccessGate: @MainActor (_ isFirstProtectedAccess: Bool) -> AccessGateDecision
        let authorizeSharedRight: @MainActor (_ localizedReason: String) async -> AuthorizationOutcome
        let currentWrappingRootKey: @MainActor () throws -> Data
        let syncPreAuthorizationState: @MainActor () -> Void
        let currentDomainState: @MainActor () -> DomainState
        let currentClipboardNotice: @MainActor () -> Bool?
        let migrateLegacyClipboardNoticeIfNeeded: @MainActor () async throws -> Void
        let openDomainIfNeeded: @MainActor (_ wrappingRootKey: Data) async throws -> Void
        let updateClipboardNotice: @MainActor (_ enabled: Bool, _ wrappingRootKey: Data) async throws -> Void
        let recoverPendingMutation: @MainActor () async throws -> RecoveryOutcome
        let resetDomain: @MainActor () async throws -> Void
    }

    let mode: Mode
    private let openMainWindowAction: (() -> Void)?
    private let liveDependencies: LiveDependencies?

    private(set) var sectionState: SectionState

    @ObservationIgnored
    private var hasEvaluatedProtectedAccessGate = false

    init(
        evaluateAccessGate: @escaping @MainActor (_ isFirstProtectedAccess: Bool) -> AccessGateDecision,
        authorizeSharedRight: @escaping @MainActor (_ localizedReason: String) async -> AuthorizationOutcome,
        currentWrappingRootKey: @escaping @MainActor () throws -> Data,
        syncPreAuthorizationState: @escaping @MainActor () -> Void,
        currentDomainState: @escaping @MainActor () -> DomainState,
        currentClipboardNotice: @escaping @MainActor () -> Bool?,
        migrateLegacyClipboardNoticeIfNeeded: @escaping @MainActor () async throws -> Void,
        openDomainIfNeeded: @escaping @MainActor (_ wrappingRootKey: Data) async throws -> Void,
        updateClipboardNotice: @escaping @MainActor (_ enabled: Bool, _ wrappingRootKey: Data) async throws -> Void,
        recoverPendingMutation: @escaping @MainActor () async throws -> RecoveryOutcome,
        resetDomain: @escaping @MainActor () async throws -> Void
    ) {
        self.mode = .mainWindowLive
        self.openMainWindowAction = nil
        self.liveDependencies = LiveDependencies(
            evaluateAccessGate: evaluateAccessGate,
            authorizeSharedRight: authorizeSharedRight,
            currentWrappingRootKey: currentWrappingRootKey,
            syncPreAuthorizationState: syncPreAuthorizationState,
            currentDomainState: currentDomainState,
            currentClipboardNotice: currentClipboardNotice,
            migrateLegacyClipboardNoticeIfNeeded: migrateLegacyClipboardNoticeIfNeeded,
            openDomainIfNeeded: openDomainIfNeeded,
            updateClipboardNotice: updateClipboardNotice,
            recoverPendingMutation: recoverPendingMutation,
            resetDomain: resetDomain
        )
        self.sectionState = .locked
    }

    init(
        mode: Mode,
        openMainWindowAction: (() -> Void)? = nil
    ) {
        self.mode = mode
        self.openMainWindowAction = openMainWindowAction
        self.liveDependencies = nil
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
        guard let liveDependencies else {
            return
        }

        switch syncPreAuthorizationSectionState(liveDependencies) {
        case .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            return
        case .unlocked:
            return
        case .locked:
            break
        }

        switch currentAccessGateDecision(liveDependencies) {
        case .frameworkRecoveryNeeded:
            liveDependencies.syncPreAuthorizationState()
            syncSectionStateFromStore(liveDependencies)
        case .pendingMutationRecoveryRequired:
            liveDependencies.syncPreAuthorizationState()
            syncSectionStateFromStore(liveDependencies)
        case .noProtectedDomainPresent, .authorizationRequired:
            sectionState = .locked
        case .alreadyAuthorized:
            _ = await openProtectedSettings(
                using: liveDependencies,
                localizedReason: settingsLocalizedReason,
                authorizationMode: .requireExistingAuthorization
            )
        }
    }

    func unlockForSettings() async {
        guard let liveDependencies else {
            return
        }

        _ = await openProtectedSettings(
            using: liveDependencies,
            localizedReason: settingsLocalizedReason
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
            syncSectionStateFromStore(liveDependencies)
        }
    }

    func retryPendingRecovery() async {
        guard let liveDependencies else {
            return
        }

        sectionState = .loading
        do {
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
            syncSectionStateFromStore(liveDependencies)
        }
    }

    func resetProtectedSettingsDomain() async {
        guard let liveDependencies else {
            return
        }

        sectionState = .loading
        do {
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
            syncSectionStateFromStore(liveDependencies)
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
                localizedReason: clipboardLocalizedReason
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
        _ = generation
        guard let liveDependencies else {
            return
        }

        await Task.yield()
        liveDependencies.syncPreAuthorizationState()
        syncSectionStateFromStore(liveDependencies)
    }

    func openMainWindow() {
        openMainWindowAction?()
    }

    private func openProtectedSettings(
        using liveDependencies: LiveDependencies,
        localizedReason: String,
        authorizationMode: AccessAuthorizationMode = .authorizeIfNeeded,
        shouldShowLoadingState: Bool = true
    ) async -> Bool {
        if shouldShowLoadingState {
            sectionState = .loading
        }
        do {
            guard try await ensureProtectedSettingsAccess(
                using: liveDependencies,
                localizedReason: localizedReason,
                authorizationMode: authorizationMode
            ) else {
                syncSectionStateFromStore(liveDependencies)
                return false
            }

            syncSectionStateFromStore(liveDependencies)
            if case .available = sectionState {
                return true
            }
            return false
        } catch {
            syncSectionStateFromStore(liveDependencies)
            return false
        }
    }

    private func ensureProtectedSettingsAccess(
        using liveDependencies: LiveDependencies,
        localizedReason: String,
        authorizationMode: AccessAuthorizationMode = .authorizeIfNeeded
    ) async throws -> Bool {
        switch syncPreAuthorizationSectionState(liveDependencies) {
        case .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            return false
        case .locked, .unlocked:
            break
        }

        switch currentAccessGateDecision(liveDependencies) {
        case .frameworkRecoveryNeeded:
            liveDependencies.syncPreAuthorizationState()
            sectionState = .frameworkUnavailable
            return false
        case .pendingMutationRecoveryRequired:
            liveDependencies.syncPreAuthorizationState()
            syncSectionStateFromStore(liveDependencies)
            return false
        case .noProtectedDomainPresent:
            guard authorizationMode == .authorizeIfNeeded else {
                sectionState = .locked
                return false
            }
            try await liveDependencies.migrateLegacyClipboardNoticeIfNeeded()
            let authorizationResult = await liveDependencies.authorizeSharedRight(
                localizedReason
            )
            switch authorizationResult {
            case .authorized:
                break
            case .cancelledOrDenied:
                sectionState = .locked
                return false
            case .frameworkRecoveryNeeded:
                sectionState = .frameworkUnavailable
                return false
            }
        case .authorizationRequired:
            guard authorizationMode == .authorizeIfNeeded else {
                sectionState = .locked
                return false
            }
            let authorizationResult = await liveDependencies.authorizeSharedRight(
                localizedReason
            )
            switch authorizationResult {
            case .authorized:
                break
            case .cancelledOrDenied:
                sectionState = .locked
                return false
            case .frameworkRecoveryNeeded:
                sectionState = .frameworkUnavailable
                return false
            }
        case .alreadyAuthorized:
            break
        }

        let wrappingRootKey = try liveDependencies.currentWrappingRootKey()
        try await liveDependencies.openDomainIfNeeded(wrappingRootKey)
        return true
    }

    private func currentAccessGateDecision(
        _ liveDependencies: LiveDependencies
    ) -> AccessGateDecision {
        let decision = liveDependencies.evaluateAccessGate(!hasEvaluatedProtectedAccessGate)
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
