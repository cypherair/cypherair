import LocalAuthentication
import SwiftUI
#if os(iOS)
import UIKit
#endif

@main
struct CypherAirApp: App {
    #if os(iOS)
    @UIApplicationDelegateAdaptor(CypherAirKeyboardPolicyDelegate.self)
    private var keyboardPolicyDelegate
    #endif

    // MARK: - Shared Dependencies

    @State private var container: AppContainer

    @State private var loadWarningCoordinator: AppLoadWarningCoordinator
    @State private var startupSnapshot: AppStartupCoordinator.AppStartupBootstrapSnapshot
    @State private var protectedSettingsHost: ProtectedSettingsHost
    @State private var localDataResetRestartCoordinator: LocalDataResetRestartCoordinator
    @State private var tutorialStore: TutorialSessionStore
    @State private var incomingURLImportCoordinator: IncomingURLImportCoordinator
    @State private var launchConfiguration: AppLaunchConfiguration
    #if os(macOS)
    @State private var macShellNavigationState = MacShellNavigationState()
    #endif
    #if os(iOS) || os(visionOS)
    @State private var iosPresentationState = TutorialOnboardingHandoffState()
    #endif

    // MARK: - Init

    init() {
        let launchConfiguration = AppLaunchConfiguration()
        let container: AppContainer
        #if DEBUG
        if launchConfiguration.usesUITestAppContainer {
            container = AppContainer.makeUITest(
                requiresManualAuthentication: launchConfiguration.requiresManualAuthentication,
                preloadContact: launchConfiguration.preloadsUITestContact
            )
        } else {
            container = AppContainer.makeDefault()
        }
        #else
        container = AppContainer.makeDefault()
        #endif
        if launchConfiguration.usesUITestAppContainer && !launchConfiguration.requiresManualAuthentication {
            container.appSessionOrchestrator.recordAuthentication()
        }
        if launchConfiguration.shouldSkipOnboarding {
            container.protectedOrdinarySettingsCoordinator.applyOnboardingCompletionOverrideForTesting(true)
        }
        let tutorialStore = TutorialSessionStore()
        let incomingURLImportCoordinator = IncomingURLImportCoordinator(
            importLoader: PublicKeyImportLoader(qrService: container.qrService),
            importWorkflow: ContactImportWorkflow(contactService: container.contactService)
        )
        let startupCoordinator = AppStartupCoordinator()
        let startupSnapshot = startupCoordinator.performPreAuthBootstrap(using: container)
        let firstDomainSharedRightCleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: container.protectedDataStorageRoot,
            hasPersistedSharedRight: { identifier in
                container.protectedDataSessionCoordinator.hasPersistedRootSecret(identifier: identifier)
            },
            hasExternalProtectedDataArtifacts: {
                try container.protectedDomainKeyManager.hasAnyPersistedDomainKeyRecord()
            },
            removePersistedSharedRight: { identifier in
                try await container.protectedDataSessionCoordinator.removePersistedSharedRight(identifier: identifier)
            }
        )
        let protectedSettingsHost = ProtectedSettingsHost(
            evaluateAccessGate: { isFirstProtectedAccess in
                let decision = container.appSessionOrchestrator.evaluateProtectedDataAccessGate(
                    startupBootstrapOutcome: startupSnapshot.bootstrapOutcome,
                    isFirstProtectedAccessInCurrentProcess: isFirstProtectedAccess
                )
                switch decision {
                case .frameworkRecoveryNeeded:
                    return .frameworkRecoveryNeeded
                case .pendingMutationRecoveryRequired:
                    return .pendingMutationRecoveryRequired
                case .noProtectedDomainPresent:
                    return .noProtectedDomainPresent
                case .authorizationRequired:
                    return .authorizationRequired
                case .alreadyAuthorized:
                    return .alreadyAuthorized
                }
            },
            hasAuthorizationHandoffContext: {
                container.appSessionOrchestrator.hasProtectedDataAuthorizationHandoffContext
            },
            authorizeSharedRight: { localizedReason, interactionMode in
                if container.protectedDataSessionCoordinator.frameworkState == .sessionAuthorized,
                   interactionMode != .requireReusableContext {
                    return .authorized
                }
                do {
                    let registry = try container.protectedDomainRecoveryCoordinator.loadCurrentRegistry()
                    let authenticationContext = container.appSessionOrchestrator
                        .consumeAuthenticatedContextForProtectedData()
                    guard interactionMode == .allowInteraction
                            || interactionMode == .requireReusableContext
                            || authenticationContext != nil else {
                        return .cancelledOrDenied
                    }
                    let authorization = await container.protectedDataSessionCoordinator.beginProtectedDataAuthorizationReturningContext(
                        registry: registry,
                        localizedReason: localizedReason,
                        authenticationContext: authenticationContext
                    )
                    switch authorization.result {
                    case .authorized:
                        return .authorizedWithContext(authorization.authenticationContext)
                    case .cancelledOrDenied:
                        authorization.authenticationContext.invalidate()
                        return .cancelledOrDenied
                    case .frameworkRecoveryNeeded:
                        authorization.authenticationContext.invalidate()
                        return .frameworkRecoveryNeeded
                    }
                } catch {
                    return .frameworkRecoveryNeeded
                }
            },
            currentWrappingRootKey: {
                try container.protectedDataSessionCoordinator.wrappingRootKeyData()
            },
            syncPreAuthorizationState: {
                container.protectedSettingsStore.syncPreAuthorizationState()
            },
            currentDomainState: {
                switch container.protectedSettingsStore.domainState {
                case .locked:
                    return .locked
                case .unlocked:
                    return .unlocked
                case .recoveryNeeded:
                    return .recoveryNeeded
                case .pendingRetryRequired:
                    return .pendingRetryRequired
                case .pendingResetRequired:
                    return .pendingResetRequired
                case .frameworkUnavailable:
                    return .frameworkUnavailable
                }
            },
            currentClipboardNotice: {
                container.protectedSettingsStore.clipboardNotice
            },
            ensureCommittedSettingsIfNeeded: {
                try await container.protectedSettingsStore.ensureCommittedIfNeeded(
                    persistSharedRight: { secret in
                        try await container.protectedDataSessionCoordinator.persistSharedRight(secretData: secret)
                    },
                    firstDomainSharedRightCleaner: firstDomainSharedRightCleaner,
                    currentWrappingRootKey: {
                        try container.protectedDataSessionCoordinator.wrappingRootKeyData()
                    }
                )
            },
            openDomainIfNeeded: { wrappingRootKey in
                _ = try await container.protectedSettingsStore.openDomainIfNeeded(
                    wrappingRootKey: wrappingRootKey
                )
            },
            updateClipboardNotice: { isEnabled, wrappingRootKey in
                try await container.protectedSettingsStore.updateClipboardNotice(
                    isEnabled,
                    wrappingRootKey: wrappingRootKey
                )
            },
            pendingRecoveryAuthorizationRequirement: {
                Self.protectedSettingsMutationRequirement(
                    container.protectedDomainRecoveryCoordinator.pendingRecoveryAuthorizationRequirement()
                )
            },
            recoverPendingMutation: {
                try await Self.recoverProtectedSettingsPendingMutation(
                    container: container,
                    authenticationContext: nil
                )
            },
            recoverPendingMutationWithContext: { authenticationContext in
                try await Self.recoverProtectedSettingsPendingMutation(
                    container: container,
                    authenticationContext: authenticationContext
                )
            },
            resetAuthorizationRequirement: {
                Self.protectedSettingsMutationRequirement(
                    container.protectedSettingsStore.resetAuthorizationRequirement()
                )
            },
            resetDomain: {
                try await container.protectedSettingsStore.resetDomain(
                    persistSharedRight: { secret in
                        try await container.protectedDataSessionCoordinator.persistSharedRight(secretData: secret)
                    },
                    removeSharedRight: { identifier in
                        try await container.protectedDataSessionCoordinator.removePersistedSharedRight(
                            identifier: identifier
                        )
                    },
                    firstDomainSharedRightCleaner: firstDomainSharedRightCleaner,
                    currentWrappingRootKey: {
                        try container.protectedDataSessionCoordinator.wrappingRootKeyData()
                    }
                )
            }
        )

        _launchConfiguration = State(initialValue: launchConfiguration)
        _container = State(initialValue: container)
        _loadWarningCoordinator = State(initialValue: AppLoadWarningCoordinator(initialWarning: startupSnapshot.loadError))
        _startupSnapshot = State(initialValue: startupSnapshot)
        _protectedSettingsHost = State(initialValue: protectedSettingsHost)
        _localDataResetRestartCoordinator = State(initialValue: LocalDataResetRestartCoordinator())
        _tutorialStore = State(initialValue: tutorialStore)
        _incomingURLImportCoordinator = State(initialValue: incomingURLImportCoordinator)
    }

    private static func protectedSettingsMutationRequirement(
        _ requirement: ProtectedDataMutationAuthorizationRequirement
    ) -> ProtectedSettingsHost.MutationAuthorizationRequirement {
        switch requirement {
        case .notRequired:
            .notRequired
        case .wrappingRootKeyRequired:
            .wrappingRootKeyRequired
        case .frameworkRecoveryNeeded:
            .frameworkRecoveryNeeded
        }
    }

    @MainActor
    private static func recoverProtectedSettingsPendingMutation(
        container: AppContainer,
        authenticationContext: LAContext?
    ) async throws -> ProtectedSettingsHost.RecoveryOutcome {
        var recoveryHandlers: [any ProtectedDomainRecoveryHandler] = [
            container.privateKeyControlStore,
            container.protectedSettingsStore,
            container.protectedDataFrameworkSentinelStore
        ]
        if let keyMetadataDomainStore = container.keyMetadataDomainStore {
            recoveryHandlers.append(keyMetadataDomainStore)
        }
        if let contactsDomainStore = container.contactsDomainStore {
            recoveryHandlers.append(contactsDomainStore)
        }
        let outcome = try await container.protectedDomainRecoveryCoordinator.recoverPendingMutation(
            handlers: recoveryHandlers,
            authenticationContext: authenticationContext,
            removeSharedRight: { identifier in
                try await container.protectedDataSessionCoordinator.removePersistedSharedRight(
                    identifier: identifier
                )
            }
        )
        switch outcome {
        case .resumedToSteadyState:
            return .resumedToSteadyState
        case .retryablePending:
            return .retryablePending
        case .resetRequired:
            return .resetRequired
        case .frameworkRecoveryNeeded:
            return .frameworkRecoveryNeeded
        }
    }

    // MARK: - Scene

    var body: some Scene {
        #if os(macOS)
        Window(
            AppProductIdentity.localizedDisplayName,
            id: mainWindowID
        ) {
            mainWindowSceneContent
        }
        .defaultSize(width: 900, height: 560)
        .windowResizability(.contentMinSize)
        .commands {
            // File > New Window stays disabled inside MacKeyboardCommands,
            // which replaces the New group with key actions.
            MacKeyboardCommands(navigationState: macShellNavigationState)
            // Restore the ⌘, Settings menu item that the standalone Settings scene used to
            // provide automatically; in the single-window design it selects the Settings tab.
            CommandGroup(replacing: .appSettings) {
                Button(String(localized: "settings.title", defaultValue: "Settings…")) {
                    macShellNavigationState.selectedTab = .settings
                }
                .keyboardShortcut(",", modifiers: .command)
            }
        }
        #elseif os(visionOS)
        Window(
            AppProductIdentity.localizedDisplayName,
            id: mainWindowID
        ) {
            mainWindowSceneContent
        }
        #else
        WindowGroup {
            mainWindowSceneContent
        }
        #endif
    }

    @ViewBuilder
    private var mainWindowContent: some View {
        #if os(macOS)
        switch launchConfiguration.root {
        case .main:
            MacAppShellView(
                navigationState: macShellNavigationState,
                opensAuthModeConfirmation: launchConfiguration.opensAuthModeConfirmation
            )
        case .tutorial:
            TutorialView(
                presentationContext: .inApp,
                initialModule: launchConfiguration.tutorialModule
            )
        }
        #else
        ContentView()
        #endif
    }

    @ViewBuilder
    private var mainWindowSceneContent: some View {
        LocalDataResetRestartGate(
            coordinator: localDataResetRestartCoordinator,
            terminateAction: LocalDataResetRestartAction.terminateCurrentProcess
        ) {
            ImportConfirmationSheetHost(coordinator: incomingURLImportCoordinator.importConfirmationCoordinator) {
                mainWindowContent
                    .task {
                        await prepareUITestContactsIfNeeded()
                    }
                    .cosmeticPrivacyCover(isCovered: container.appLockController.isCosmeticallyCovered)
                    .overlay {
                        if container.appLockController.isLocked {
                            AppLockSurfaceView(appLockController: container.appLockController)
                        }
                    }
                    .appLifecycleObserver(
                        appLockController: container.appLockController
                    )
                    .environment(container.appLockController)
                    .environment(container.config)
                    .environment(container.protectedOrdinarySettingsCoordinator)
                    .environment(container.keyManagement)
                    .environment(container.contactService)
                    .environment(container.encryptionService)
                    .environment(container.decryptionService)
                    .environment(container.signingService)
                    .environment(container.certificateSignatureService)
                    .environment(container.qrService)
                    .environment(container.selfTestService)
                    .environment(container.authManager)
                    .environment(container.appSessionOrchestrator)
                    .environment(\.localDataResetService, container.localDataResetService)
                    .environment(\.localDataResetRestartCoordinator, localDataResetRestartCoordinator)
                    .environment(\.appAccessPolicySwitchAction, appAccessPolicySwitchAction)
                    .environment(\.protectedSettingsHost, protectedSettingsHost)
                    .environment(tutorialStore)
                    #if os(iOS) || os(visionOS)
                    .environment(\.iosPresentationController, iosPresentationControllerValue)
                    #endif
            }
        }
        #if os(iOS) || os(visionOS)
        .sheet(item: onboardingPresentationBinding, onDismiss: {
            iosPresentationState.completePendingTutorialLaunchIfNeeded()
        }) { presentation in
            onboardingPresentationView(for: presentation)
        }
        .fullScreenCover(item: tutorialPresentationBinding) { presentation in
            tutorialPresentationView(for: presentation)
        }
        .task {
            presentInitialIOSFlowIfNeeded()
        }
        .onChange(of: container.protectedOrdinarySettingsCoordinator.state) { _, _ in
            guard !localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset else { return }
            if container.protectedOrdinarySettingsCoordinator.hasCompletedOnboarding == false,
               iosPresentationState.activePresentation == nil {
                iosPresentationState.activePresentation = .onboarding(initialPage: 0, context: .firstRun)
            }
        }
        #endif
        .incomingURLImportAlerts(coordinator: incomingURLImportCoordinator)
        .appLoadWarningAlert(coordinator: loadWarningCoordinator)
        .onAppear {
            presentPendingLoadWarningIfPossible(source: "initialState")
        }
        .onChange(of: loadWarningPresentationState) { _, _ in
            presentPendingLoadWarningIfPossible(source: "presentationStateChange")
        }
        .onChange(of: container.config.postUnlockRecoveryLoadWarning) { _, warning in
            guard let warning else { return }
            loadWarningCoordinator.enqueue(warning)
            container.config.clearPostUnlockRecoveryLoadWarning()
            presentPendingLoadWarningIfPossible(source: "postUnlockRecovery")
        }
        .onOpenURL { url in
            incomingURLRouter.handle(url)
        }
    }

    @MainActor
    private func prepareUITestContactsIfNeeded() async {
        guard launchConfiguration.usesUITestAppContainer,
              !launchConfiguration.requiresManualAuthentication else {
            return
        }
        _ = await container.prepareUITestContactsIfNeeded()
    }

    private var appAccessPolicySwitchAction: SettingsScreenModel.AppAccessPolicySwitchAction {
        { newPolicy in
            try await container.makeAppAccessPolicySwitchWorkflow().run(to: newPolicy)
        }
    }

    private var loadWarningPresentationState: LoadWarningPresentationState {
        LoadWarningPresentationState(
            isAppLocked: container.appLockController.isLocked,
            isAuthenticating: container.appLockController.isAuthenticating,
            isLockCoverVisible: container.appLockController.isCosmeticallyCovered,
            hasAuthenticatedSession: container.appSessionOrchestrator.lastAuthenticationDate != nil,
            allowsPreAuthenticationPresentation: launchConfiguration.usesUITestAppContainer
                && !launchConfiguration.requiresManualAuthentication
        )
    }

    private func presentPendingLoadWarningIfPossible(source: String) {
        loadWarningCoordinator.presentPendingIfPossible(
            source: source,
            presentationState: loadWarningPresentationState,
            isRestartRequiredAfterLocalDataReset: localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset
        )
    }

    private var incomingURLRouter: AppSceneIncomingURLRouter {
        AppSceneIncomingURLRouter(
            incomingURLImportCoordinator: incomingURLImportCoordinator,
            tutorialStore: tutorialStore,
            localDataResetRestartCoordinator: localDataResetRestartCoordinator
        )
    }

    #if os(iOS) || os(visionOS)
    private var onboardingPresentationBinding: Binding<IOSPresentation?> {
        Binding(
            get: {
                guard !localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset else {
                    return nil
                }
                guard case .onboarding? = iosPresentationState.activePresentation else {
                    return nil
                }
                return iosPresentationState.activePresentation
            },
            set: { newValue in
                if let newValue {
                    iosPresentationState.activePresentation = newValue
                } else if case .onboarding? = iosPresentationState.activePresentation {
                    iosPresentationState.activePresentation = nil
                }
            }
        )
    }

    private var tutorialPresentationBinding: Binding<IOSPresentation?> {
        Binding(
            get: {
                guard !localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset else {
                    return nil
                }
                guard case .tutorial? = iosPresentationState.activePresentation else {
                    return nil
                }
                return iosPresentationState.activePresentation
            },
            set: { newValue in
                if let newValue {
                    iosPresentationState.activePresentation = newValue
                } else if case .tutorial? = iosPresentationState.activePresentation {
                    iosPresentationState.activePresentation = nil
                }
            }
        )
    }

    @ViewBuilder
    private func onboardingPresentationView(for presentation: IOSPresentation) -> some View {
        if case .onboarding(let initialPage, let context) = presentation {
            OnboardingView(
                initialPage: initialPage,
                presentationContext: context
            )
            .environment(container.config)
            .environment(container.protectedOrdinarySettingsCoordinator)
            .environment(tutorialStore)
            .environment(\.iosPresentationController, iosPresentationControllerValue)
            .interactiveDismissDisabled(
                context == .firstRun
                    && container.protectedOrdinarySettingsCoordinator.hasCompletedOnboarding != true
            )
        }
    }

    @ViewBuilder
    private func tutorialPresentationView(for presentation: IOSPresentation) -> some View {
        if case .tutorial(let presentationContext) = presentation {
            TutorialView(
                presentationContext: presentationContext,
                initialModule: launchConfiguration.root == .tutorial ? launchConfiguration.tutorialModule : nil
            )
                .environment(container.config)
                .environment(container.protectedOrdinarySettingsCoordinator)
                .environment(tutorialStore)
                .environment(container.appSessionOrchestrator)
                .environment(\.iosPresentationController, iosPresentationControllerValue)
        }
    }

    private var iosPresentationControllerValue: IOSPresentationController {
        IOSPresentationController(
            present: { presentation in
                iosPresentationState.activePresentation = presentation
            },
            dismiss: {
                iosPresentationState.activePresentation = nil
            },
            handoffToTutorialAfterOnboardingDismiss: { presentationContext in
                iosPresentationState.requestTutorialLaunchFromOnboarding(presentationContext)
            }
        )
    }

    private func presentInitialIOSFlowIfNeeded() {
        guard !localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset else { return }
        guard iosPresentationState.activePresentation == nil else { return }

        switch launchConfiguration.root {
        case .tutorial:
            iosPresentationState.activePresentation = .tutorial(presentationContext: .inApp)
        case .main:
            if container.protectedOrdinarySettingsCoordinator.hasCompletedOnboarding == false {
                iosPresentationState.activePresentation = .onboarding(initialPage: 0, context: .firstRun)
            }
        }
    }
    #endif

}

#if os(iOS)
private final class CypherAirKeyboardPolicyDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier
    ) -> Bool {
        extensionPointIdentifier != .keyboard
    }
}
#endif

// MARK: - App Alerts

@MainActor
private extension View {
    func incomingURLImportAlerts(
        coordinator: IncomingURLImportCoordinator
    ) -> some View {
        self
            .importErrorAlert(coordinator: coordinator)
            .tutorialImportBlockedAlert(coordinator: coordinator)
    }

    func importErrorAlert(
        coordinator: IncomingURLImportCoordinator
    ) -> some View {
        alert(
            String(localized: "import.error.alertTitle", defaultValue: "Import Failed"),
            isPresented: Binding(
                get: { coordinator.importError != nil },
                set: { if !$0 { coordinator.dismissImportError() } }
            )
        ) {
            Button(String(localized: "import.error.ok", defaultValue: "OK")) {
                coordinator.dismissImportError()
            }
        } message: {
            Text(coordinator.importErrorDescription)
        }
    }

    func tutorialImportBlockedAlert(
        coordinator: IncomingURLImportCoordinator
    ) -> some View {
        alert(
            String(localized: "import.tutorialBlocked.title", defaultValue: "Close Tutorial to Import"),
            isPresented: Binding(
                get: { coordinator.isTutorialImportBlocked },
                set: { if !$0 { coordinator.dismissTutorialImportBlocked() } }
            )
        ) {
            Button(String(localized: "import.error.ok", defaultValue: "OK")) {
                coordinator.dismissTutorialImportBlocked()
            }
        } message: {
            Text(String(
                localized: "import.tutorialBlocked.message",
                defaultValue: "CypherAir X does not import real contacts while the Guided Tutorial is open. Close the tutorial, then open the QR link again."
            ))
        }
    }

    func appLoadWarningAlert(
        coordinator: AppLoadWarningCoordinator
    ) -> some View {
        alert(
            String(localized: "app.loadError.title", defaultValue: "Load Warning"),
            isPresented: Binding(
                get: { coordinator.presentedWarning != nil },
                set: { if !$0 { coordinator.dismissPresentedWarning() } }
            ),
            presenting: coordinator.presentedWarning
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                coordinator.dismissPresentedWarning()
            }
        } message: { warning in
            Text(warning)
        }
    }
}
