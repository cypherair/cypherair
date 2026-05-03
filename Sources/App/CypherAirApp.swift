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
    @State private var macTutorialLaunchRelay = MacTutorialLaunchRelay()
    @State private var macTutorialHostAvailability = MacTutorialHostAvailability()
    #endif
    #if os(iOS) || os(visionOS)
    @State private var iosPresentationState = TutorialOnboardingHandoffState()
    #endif

    // MARK: - Init

    init() {
        let launchConfiguration = AppLaunchConfiguration()
        let container: AppContainer
        if launchConfiguration.isUITestMode || launchConfiguration.isXCTestHost {
            container = AppContainer.makeUITest(
                requiresManualAuthentication: launchConfiguration.requiresManualAuthentication,
                preloadContact: launchConfiguration.preloadsUITestContact,
                authTraceEnabled: launchConfiguration.isAuthTraceEnabled
            )
        } else {
            container = AppContainer.makeDefault(
                authTraceEnabled: launchConfiguration.isAuthTraceEnabled
            )
        }
        if (launchConfiguration.isUITestMode || launchConfiguration.isXCTestHost)
            && !launchConfiguration.requiresManualAuthentication {
            container.appSessionOrchestrator.recordAuthentication()
        }
        if launchConfiguration.shouldSkipOnboarding {
            container.protectedOrdinarySettingsCoordinator.applyOnboardingCompletionOverrideForTesting(true)
        }
        container.authLifecycleTraceStore?.record(
            category: .lifecycle,
            name: "app.init.containerReady",
            metadata: [
                "root": launchConfiguration.root.rawValue,
                "uiTestMode": launchConfiguration.isUITestMode ? "true" : "false",
                "xctestHost": launchConfiguration.isXCTestHost ? "true" : "false",
                "requiresManualAuthentication": launchConfiguration.requiresManualAuthentication ? "true" : "false",
                "authTraceEnabled": launchConfiguration.isAuthTraceEnabled ? "true" : "false"
            ]
        )
        let tutorialStore = TutorialSessionStore()
        let incomingURLImportCoordinator = IncomingURLImportCoordinator(
            importLoader: PublicKeyImportLoader(qrService: container.qrService),
            importWorkflow: ContactImportWorkflow(contactService: container.contactService)
        )
        let startupCoordinator = AppStartupCoordinator()
        container.authLifecycleTraceStore?.record(
            category: .lifecycle,
            name: "app.init.preAuthBootstrap.start"
        )
        let startupSnapshot = startupCoordinator.performPreAuthBootstrap(using: container)
        container.authLifecycleTraceStore?.record(
            category: .lifecycle,
            name: "app.init.preAuthBootstrap.finish",
            metadata: [
                "bootstrapOutcome": Self.traceValue(for: startupSnapshot.bootstrapOutcome),
                "frameworkState": Self.traceValue(for: startupSnapshot.protectedDataFrameworkState),
                "hasLoadError": startupSnapshot.loadError == nil ? "false" : "true"
            ]
        )
        let firstDomainSharedRightCleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: container.protectedDataStorageRoot,
            hasPersistedSharedRight: { identifier in
                container.protectedDataSessionCoordinator.hasPersistedRootSecret(identifier: identifier)
            },
            removePersistedSharedRight: { identifier in
                try await container.protectedDataSessionCoordinator.removePersistedSharedRight(identifier: identifier)
            },
            traceStore: container.authLifecycleTraceStore
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
            migrationAuthorizationRequirement: {
                Self.protectedSettingsMutationRequirement(
                    container.protectedSettingsStore.migrationAuthorizationRequirement()
                )
            },
            ensureCommittedAndMigrateSettingsIfNeeded: {
                try await container.protectedSettingsStore.ensureCommittedAndMigrateSettingsIfNeeded(
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
            },
            traceStore: container.authLifecycleTraceStore
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
            String(localized: "app.name", defaultValue: "CypherAir"),
            id: mainWindowID
        ) {
            mainWindowSceneContent
        }
        .defaultSize(width: 900, height: 650)
        .windowResizability(.contentMinSize)
        .commands {
            // Disable File > New Window on macOS.
            // CypherAir uses a single-window design; multiple windows would create
            // independent privacy screen states leading to inconsistent security behavior.
            CommandGroup(replacing: .newItem) { }
        }
        #elseif os(visionOS)
        Window(
            String(localized: "app.name", defaultValue: "CypherAir"),
            id: mainWindowID
        ) {
            mainWindowSceneContent
        }
        #else
        WindowGroup {
            mainWindowSceneContent
        }
        #endif

        #if os(macOS)
        Settings {
            LocalDataResetRestartGate(
                coordinator: localDataResetRestartCoordinator,
                terminateAction: LocalDataResetRestartAction.terminateCurrentProcess
            ) {
                MacSettingsRootView(
                    tutorialLaunchRelay: macTutorialLaunchRelay,
                    tutorialHostAvailability: macTutorialHostAvailability
                )
                .optionalTint(container.protectedOrdinarySettingsCoordinator.colorTheme.accentColor)
                .environment(container.config)
                .environment(container.protectedOrdinarySettingsCoordinator)
                .environment(container.authManager)
                .environment(container.keyManagement)
                .environment(container.selfTestService)
                .environment(\.localDataResetService, container.localDataResetService)
                .environment(\.localDataResetRestartCoordinator, localDataResetRestartCoordinator)
                .environment(\.appAccessPolicySwitchAction, appAccessPolicySwitchAction)
                .environment(\.authLifecycleTraceStore, container.authLifecycleTraceStore)
                .environment(\.authenticationShieldCoordinator, container.authenticationShieldCoordinator)
                .environment(tutorialStore)
                .authenticationShieldHost(
                    container.authenticationShieldCoordinator,
                    handlesLifecycleEvents: true
                )
            }
        }
        #endif
    }

    @ViewBuilder
    private var mainWindowContent: some View {
        #if os(macOS)
        switch launchConfiguration.root {
        case .main:
            MacAppShellView(
                tutorialLaunchRelay: macTutorialLaunchRelay,
                tutorialHostAvailability: macTutorialHostAvailability
            )
        case .settings:
            MacSettingsRootView(
                launchConfiguration: launchConfiguration,
                tutorialLaunchRelay: macTutorialLaunchRelay,
                tutorialHostAvailability: macTutorialHostAvailability,
                presentationHostMode: .mainWindow
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
                    .onAppear {
                        container.authLifecycleTraceStore?.record(
                            category: .lifecycle,
                            name: "mainWindow.content.appear",
                            metadata: [
                                "root": launchConfiguration.root.rawValue,
                                "hasLoadWarning": loadWarningCoordinator.presentedWarning == nil ? "false" : "true"
                            ]
                        )
                    }
                    .privacyScreen()
                    .optionalTint(container.protectedOrdinarySettingsCoordinator.colorTheme.accentColor)
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
                    .environment(\.authLifecycleTraceStore, container.authLifecycleTraceStore)
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
        .alert(
            String(localized: "import.error.alertTitle", defaultValue: "Import Failed"),
            isPresented: Binding(
                get: { incomingURLImportCoordinator.importError != nil },
                set: { if !$0 { incomingURLImportCoordinator.dismissImportError() } }
            )
        ) {
            Button(String(localized: "import.error.ok", defaultValue: "OK")) {
                incomingURLImportCoordinator.dismissImportError()
            }
        } message: {
            if let importError = incomingURLImportCoordinator.importError {
                Text(importError.localizedDescription)
            }
        }
        .alert(
            String(localized: "addcontact.keyUpdate.title", defaultValue: "Key Update Detected"),
            isPresented: Binding(
                get: { incomingURLImportCoordinator.pendingKeyUpdateRequest != nil },
                set: { if !$0 { incomingURLImportCoordinator.cancelPendingKeyUpdate() } }
            ),
            presenting: incomingURLImportCoordinator.pendingKeyUpdateRequest
        ) { request in
            Button(String(localized: "addcontact.keyUpdate.confirm", defaultValue: "Replace Key"), role: .destructive) {
                incomingURLImportCoordinator.confirmPendingKeyUpdate()
            }
            Button(String(localized: "addcontact.keyUpdate.cancel", defaultValue: "Cancel"), role: .cancel) {
                incomingURLImportCoordinator.cancelPendingKeyUpdate()
            }
        } message: { request in
            Text(String(localized: "addcontact.keyUpdate.message",
                        defaultValue: "This contact (\(request.pendingUpdate.existingContact.displayName)) has a new key with a different fingerprint. Verify with the contact before accepting. Replace the existing key?"))
        }
        .alert(
            String(localized: "import.tutorialBlocked.title", defaultValue: "Close Tutorial to Import"),
            isPresented: Binding(
                get: { incomingURLImportCoordinator.isTutorialImportBlocked },
                set: { if !$0 { incomingURLImportCoordinator.dismissTutorialImportBlocked() } }
            )
        ) {
            Button(String(localized: "import.error.ok", defaultValue: "OK")) {
                incomingURLImportCoordinator.dismissTutorialImportBlocked()
            }
        } message: {
            Text(String(
                localized: "import.tutorialBlocked.message",
                defaultValue: "CypherAir does not import real contacts while the Guided Tutorial is open. Close the tutorial, then open the QR link again."
            ))
        }
        .alert(
            String(localized: "app.loadError.title", defaultValue: "Load Warning"),
            isPresented: Binding(
                get: { loadWarningCoordinator.presentedWarning != nil },
                set: { if !$0 { loadWarningCoordinator.dismissPresentedWarning() } }
            )
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                loadWarningCoordinator.dismissPresentedWarning()
            }
        } message: {
            if let presentedWarning = loadWarningCoordinator.presentedWarning {
                Text(presentedWarning)
            }
        }
        .onAppear {
            presentPendingLoadWarningIfPossible(source: "initialState")
        }
        .onChange(of: loadWarningCoordinator.presentedWarning != nil) { _, isPresented in
            container.authLifecycleTraceStore?.record(
                category: .lifecycle,
                name: isPresented ? "loadWarning.presented" : "loadWarning.dismissed",
                metadata: ["source": "stateChange"]
            )
        }
        .onChange(of: loadWarningPresentationState) { _, _ in
            presentPendingLoadWarningIfPossible(source: "presentationStateChange")
        }
        .onChange(of: container.keyManagement.legacyMetadataMigrationLoadWarning) { _, warning in
            guard let warning else { return }
            loadWarningCoordinator.enqueue(warning)
            container.keyManagement.clearLegacyMetadataMigrationLoadWarning()
            presentPendingLoadWarningIfPossible(source: "legacyMetadataMigration")
        }
        .onChange(of: container.config.postUnlockRecoveryLoadWarning) { _, warning in
            guard let warning else { return }
            loadWarningCoordinator.enqueue(warning)
            container.config.clearPostUnlockRecoveryLoadWarning()
            presentPendingLoadWarningIfPossible(source: "postUnlockRecovery")
        }
        .environment(\.authenticationShieldCoordinator, container.authenticationShieldCoordinator)
        .authenticationShieldHost(
            container.authenticationShieldCoordinator,
            handlesLifecycleEvents: true
        )
        .onOpenURL { url in
            incomingURLRouter.handle(url)
        }
        #if os(macOS)
        .onAppear {
            syncMacTutorialHostAvailability()
        }
        .onChange(of: incomingURLImportCoordinator.importConfirmationCoordinator.request?.id) { _, _ in
            syncMacTutorialHostAvailability()
        }
        .onChange(of: incomingURLImportCoordinator.importError != nil) { _, _ in
            syncMacTutorialHostAvailability()
        }
        .onChange(of: incomingURLImportCoordinator.pendingKeyUpdateRequest?.id) { _, _ in
            syncMacTutorialHostAvailability()
        }
        .onChange(of: incomingURLImportCoordinator.isTutorialImportBlocked) { _, _ in
            syncMacTutorialHostAvailability()
        }
        .onChange(of: loadWarningCoordinator.presentedWarning != nil) { _, _ in
            syncMacTutorialHostAvailability()
        }
        #endif
    }

    private var appAccessPolicySwitchAction: SettingsScreenModel.AppAccessPolicySwitchAction {
        { newPolicy in
            let currentPolicy = container.config.appSessionAuthenticationPolicy
            guard newPolicy != currentPolicy else {
                return
            }

            var didTraceFinish = false
            do {
                if container.protectedDataSessionCoordinator.hasPersistedRootSecret() {
                    let authenticationPolicy = AppSessionAuthenticationPolicy
                        .strictestPolicyForRootSecretReprotection(
                            from: currentPolicy,
                            to: newPolicy
                        )
                    container.authLifecycleTraceStore?.record(
                        category: .operation,
                        name: "appAccessPolicy.switch.start",
                        metadata: [
                            "currentPolicy": currentPolicy.rawValue,
                            "newPolicy": newPolicy.rawValue,
                            "authPolicy": authenticationPolicy.rawValue,
                            "hasRootSecret": "true"
                        ]
                    )
                    let result = try await container.authManager.evaluateAppSession(
                        policy: authenticationPolicy,
                        reason: String(
                            localized: "settings.appAccessPolicy.change.reason",
                            defaultValue: "Authenticate to change App Access Protection."
                        ),
                        source: "appAccessPolicy.switch"
                    )
                    guard result.isAuthenticated else {
                        throw AuthenticationError.failed
                    }
                    defer {
                        result.context?.invalidate()
                    }

                    try container.protectedDataSessionCoordinator.reprotectPersistedRootSecretIfPresent(
                        from: currentPolicy,
                        to: newPolicy,
                        authenticationContext: result.context
                    )
                    container.appSessionOrchestrator.discardProtectedDataAuthorizationHandoffContextForPolicyChange()
                    container.authLifecycleTraceStore?.record(
                        category: .operation,
                        name: "appAccessPolicy.switch.finish",
                        metadata: ["result": "success", "newPolicy": newPolicy.rawValue, "hasRootSecret": "true"]
                    )
                    didTraceFinish = true
                } else {
                    container.authLifecycleTraceStore?.record(
                        category: .operation,
                        name: "appAccessPolicy.switch.start",
                        metadata: [
                            "currentPolicy": currentPolicy.rawValue,
                            "newPolicy": newPolicy.rawValue,
                            "authPolicy": newPolicy.rawValue,
                            "hasRootSecret": "false"
                        ]
                    )
                    guard container.authManager.canEvaluate(appSessionPolicy: newPolicy) else {
                        container.authLifecycleTraceStore?.record(
                            category: .operation,
                            name: "appAccessPolicy.switch.finish",
                            metadata: ["result": "biometricsUnavailable", "newPolicy": newPolicy.rawValue, "hasRootSecret": "false"]
                        )
                        didTraceFinish = true
                        throw AuthenticationError.appAccessBiometricsUnavailable
                    }
                    container.appSessionOrchestrator.discardProtectedDataAuthorizationHandoffContextForPolicyChange()
                    container.authLifecycleTraceStore?.record(
                        category: .operation,
                        name: "appAccessPolicy.switch.finish",
                        metadata: ["result": "success", "newPolicy": newPolicy.rawValue, "hasRootSecret": "false"]
                    )
                    didTraceFinish = true
                }
            } catch {
                if !didTraceFinish {
                    container.authLifecycleTraceStore?.record(
                        category: .operation,
                        name: "appAccessPolicy.switch.finish",
                        metadata: ["result": "error", "newPolicy": newPolicy.rawValue, "errorType": String(describing: type(of: error))]
                    )
                }
                throw error
            }
        }
    }

    private var loadWarningPresentationState: LoadWarningPresentationState {
        LoadWarningPresentationState(
            isShieldVisible: container.authenticationShieldCoordinator.isVisible,
            isAuthenticating: container.appSessionOrchestrator.isAuthenticating,
            isPrivacyScreenBlurred: container.appSessionOrchestrator.isPrivacyScreenBlurred,
            hasAuthenticatedSession: container.appSessionOrchestrator.lastAuthenticationDate != nil,
            allowsPreAuthenticationPresentation: launchConfiguration.isUITestMode
                && !launchConfiguration.requiresManualAuthentication
        )
    }

    private func presentPendingLoadWarningIfPossible(source: String) {
        loadWarningCoordinator.presentPendingIfPossible(
            source: source,
            presentationState: loadWarningPresentationState,
            isRestartRequiredAfterLocalDataReset: localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset,
            traceStore: container.authLifecycleTraceStore
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
        case .main, .settings:
            if container.protectedOrdinarySettingsCoordinator.hasCompletedOnboarding == false {
                iosPresentationState.activePresentation = .onboarding(initialPage: 0, context: .firstRun)
            }
        }
    }
    #endif

    #if os(macOS)
    private func syncMacTutorialHostAvailability() {
        macTutorialHostAvailability.setAppLevelBlocker(
            .importConfirmationSheet,
            isActive: incomingURLImportCoordinator.importConfirmationCoordinator.request != nil
        )
        macTutorialHostAvailability.setAppLevelBlocker(
            .importErrorAlert,
            isActive: incomingURLImportCoordinator.importError != nil
        )
        macTutorialHostAvailability.setAppLevelBlocker(
            .keyUpdateAlert,
            isActive: incomingURLImportCoordinator.pendingKeyUpdateRequest != nil
        )
        macTutorialHostAvailability.setAppLevelBlocker(
            .tutorialImportBlockedAlert,
            isActive: incomingURLImportCoordinator.isTutorialImportBlocked
        )
        macTutorialHostAvailability.setAppLevelBlocker(
            .loadWarningAlert,
            isActive: loadWarningCoordinator.presentedWarning != nil
        )
    }
    #endif

    private static func traceValue(for outcome: ProtectedDataBootstrapOutcome) -> String {
        switch outcome {
        case .emptySteadyState(_, let didBootstrap):
            didBootstrap ? "emptySteadyState.bootstrapped" : "emptySteadyState.existing"
        case .loadedRegistry(_, let recoveryDisposition):
            "loadedRegistry.\(traceValue(for: recoveryDisposition))"
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        }
    }

    private static func traceValue(for recoveryDisposition: ProtectedDataRecoveryDisposition) -> String {
        switch recoveryDisposition {
        case .resumeSteadyState:
            "resumeSteadyState"
        case .continuePendingMutation:
            "continuePendingMutation"
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        }
    }

    private static func traceValue(for state: ProtectedDataFrameworkState) -> String {
        switch state {
        case .sessionLocked:
            "sessionLocked"
        case .sessionAuthorized:
            "sessionAuthorized"
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        case .restartRequired:
            "restartRequired"
        }
    }

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

// MARK: - Optional Tint

private extension View {
    /// Apply `.tint()` only when a color is provided; omit entirely for `nil`
    /// so SwiftUI uses the system `Color.accentColor`.
    @ViewBuilder
    func optionalTint(_ color: Color?) -> some View {
        if let color {
            self.tint(color)
        } else {
            self
        }
    }
}
