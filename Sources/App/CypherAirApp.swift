import SwiftUI
#if os(iOS)
import UIKit
#endif

struct LoadWarningPresentationState: Equatable {
    let isShieldVisible: Bool
    let isAuthenticating: Bool
    let isPrivacyScreenBlurred: Bool
    let hasAuthenticatedSession: Bool
    let allowsPreAuthenticationPresentation: Bool
}

enum LoadWarningPresentationGate {
    static func canPresent(_ state: LoadWarningPresentationState) -> Bool {
        guard !state.isShieldVisible,
              !state.isAuthenticating,
              !state.isPrivacyScreenBlurred else {
            return false
        }
        return state.hasAuthenticatedSession || state.allowsPreAuthenticationPresentation
    }
}

@main
struct CypherAirApp: App {
    #if os(iOS)
    @UIApplicationDelegateAdaptor(CypherAirKeyboardPolicyDelegate.self)
    private var keyboardPolicyDelegate
    #endif

    // MARK: - Shared Dependencies

    @State private var container: AppContainer

    @State private var loadError: String?
    @State private var pendingLoadError: String?
    @State private var startupSnapshot: AppStartupCoordinator.AppStartupBootstrapSnapshot
    @State private var protectedSettingsHost: ProtectedSettingsHost
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
        if launchConfiguration.isUITestMode {
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
        if launchConfiguration.isUITestMode && !launchConfiguration.requiresManualAuthentication {
            container.appSessionOrchestrator.recordAuthentication()
        }
        if launchConfiguration.shouldSkipOnboarding {
            container.config.hasCompletedOnboarding = true
        }
        container.authLifecycleTraceStore?.record(
            category: .lifecycle,
            name: "app.init.containerReady",
            metadata: [
                "root": launchConfiguration.root.rawValue,
                "uiTestMode": launchConfiguration.isUITestMode ? "true" : "false",
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
                do {
                    let registry = try container.protectedDomainRecoveryCoordinator.loadCurrentRegistry()
                    let authenticationContext = container.appSessionOrchestrator
                        .consumeAuthenticatedContextForProtectedData()
                    guard interactionMode == .allowInteraction || authenticationContext != nil else {
                        return .cancelledOrDenied
                    }
                    defer {
                        authenticationContext?.invalidate()
                    }
                    let result = await container.protectedDataSessionCoordinator.beginProtectedDataAuthorization(
                        registry: registry,
                        localizedReason: localizedReason,
                        authenticationContext: authenticationContext
                    )
                    switch result {
                    case .authorized:
                        return .authorized
                    case .cancelledOrDenied:
                        return .cancelledOrDenied
                    case .frameworkRecoveryNeeded:
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
            migrateLegacyClipboardNoticeIfNeeded: {
                try await container.protectedSettingsStore.migrateLegacyClipboardNoticeIfNeeded(
                    persistSharedRight: { secret in
                        try await container.protectedDataSessionCoordinator.persistSharedRight(secretData: secret)
                    },
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
                let outcome = try await container.protectedDomainRecoveryCoordinator.recoverPendingMutation(
                    handlers: [
                        container.protectedSettingsStore,
                        container.protectedDataFrameworkSentinelStore
                    ],
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
                    currentWrappingRootKey: {
                        try container.protectedDataSessionCoordinator.wrappingRootKeyData()
                    }
                )
            },
            traceStore: container.authLifecycleTraceStore
        )

        _launchConfiguration = State(initialValue: launchConfiguration)
        _container = State(initialValue: container)
        _loadError = State(initialValue: nil)
        _pendingLoadError = State(initialValue: startupSnapshot.loadError)
        _startupSnapshot = State(initialValue: startupSnapshot)
        _protectedSettingsHost = State(initialValue: protectedSettingsHost)
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
            MacSettingsRootView(
                tutorialLaunchRelay: macTutorialLaunchRelay,
                tutorialHostAvailability: macTutorialHostAvailability
            )
            .optionalTint(container.config.colorTheme.accentColor)
            .environment(container.config)
            .environment(container.authManager)
            .environment(container.keyManagement)
            .environment(container.selfTestService)
            .environment(\.localDataResetService, container.localDataResetService)
            .environment(\.appAccessPolicySwitchAction, appAccessPolicySwitchAction)
            .environment(\.authLifecycleTraceStore, container.authLifecycleTraceStore)
            .environment(\.authenticationShieldCoordinator, container.authenticationShieldCoordinator)
            .environment(tutorialStore)
            .authenticationShieldHost(
                container.authenticationShieldCoordinator,
                handlesLifecycleEvents: true
            )
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
        ImportConfirmationSheetHost(coordinator: incomingURLImportCoordinator.importConfirmationCoordinator) {
            mainWindowContent
                .onAppear {
                    container.authLifecycleTraceStore?.record(
                        category: .lifecycle,
                        name: "mainWindow.content.appear",
                        metadata: [
                            "root": launchConfiguration.root.rawValue,
                            "hasLoadWarning": loadError == nil ? "false" : "true"
                        ]
                    )
                }
                .privacyScreen()
                .optionalTint(container.config.colorTheme.accentColor)
                .environment(container.config)
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
                .environment(\.appAccessPolicySwitchAction, appAccessPolicySwitchAction)
                .environment(\.authLifecycleTraceStore, container.authLifecycleTraceStore)
                .environment(\.protectedSettingsHost, protectedSettingsHost)
                .environment(tutorialStore)
                #if os(iOS) || os(visionOS)
                .environment(\.iosPresentationController, iosPresentationControllerValue)
                #endif
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
        .onChange(of: container.config.hasCompletedOnboarding) { _, hasCompletedOnboarding in
            if !hasCompletedOnboarding,
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
                get: { loadError != nil },
                set: { if !$0 { loadError = nil } }
            )
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                loadError = nil
            }
        } message: {
            if let loadError {
                Text(loadError)
            }
        }
        .onAppear {
            presentPendingLoadWarningIfPossible(source: "initialState")
        }
        .onChange(of: loadError != nil) { _, isPresented in
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
            pendingLoadError = warning
            container.keyManagement.clearLegacyMetadataMigrationLoadWarning()
            presentPendingLoadWarningIfPossible(source: "legacyMetadataMigration")
        }
        .environment(\.authenticationShieldCoordinator, container.authenticationShieldCoordinator)
        .authenticationShieldHost(
            container.authenticationShieldCoordinator,
            handlesLifecycleEvents: true
        )
        .onOpenURL { url in
            incomingURLImportCoordinator.handleIncomingURL(
                url,
                isTutorialPresentationActive: tutorialStore.isTutorialPresentationActive
            )
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
        .onChange(of: loadError != nil) { _, _ in
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
        guard loadError == nil, let pendingLoadError else { return }
        let presentationState = loadWarningPresentationState
        guard LoadWarningPresentationGate.canPresent(presentationState) else {
            container.authLifecycleTraceStore?.record(
                category: .lifecycle,
                name: "loadWarning.pending",
                metadata: [
                    "source": source,
                    "shieldVisible": presentationState.isShieldVisible ? "true" : "false",
                    "isAuthenticating": presentationState.isAuthenticating ? "true" : "false",
                    "privacyBlurred": presentationState.isPrivacyScreenBlurred ? "true" : "false",
                    "hasAuthenticatedSession": presentationState.hasAuthenticatedSession ? "true" : "false",
                    "allowsPreAuthenticationPresentation": presentationState.allowsPreAuthenticationPresentation ? "true" : "false"
                ]
            )
            return
        }

        self.pendingLoadError = nil
        loadError = pendingLoadError
    }

    #if os(iOS) || os(visionOS)
    private var onboardingPresentationBinding: Binding<IOSPresentation?> {
        Binding(
            get: {
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
            .environment(tutorialStore)
            .environment(\.iosPresentationController, iosPresentationControllerValue)
            .interactiveDismissDisabled(context == .firstRun && !container.config.hasCompletedOnboarding)
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
                .environment(tutorialStore)
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
        guard iosPresentationState.activePresentation == nil else { return }

        switch launchConfiguration.root {
        case .tutorial:
            iosPresentationState.activePresentation = .tutorial(presentationContext: .inApp)
        case .main, .settings:
            if !container.config.hasCompletedOnboarding {
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
            isActive: loadError != nil
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

struct AppLaunchConfiguration {
    enum Root: String {
        case main
        case settings
        case tutorial
    }

    let root: Root
    let shouldSkipOnboarding: Bool
    let tutorialModule: TutorialModuleID?
    let isUITestMode: Bool
    let requiresManualAuthentication: Bool
    let opensAuthModeConfirmation: Bool
    let preloadsUITestContact: Bool
    let isAuthTraceEnabled: Bool

    init(processInfo: ProcessInfo = .processInfo) {
        let environment = processInfo.environment
        self.root = Root(rawValue: environment["UITEST_ROOT"] ?? "main") ?? .main
        self.isUITestMode = environment["UITEST_ROOT"] != nil || environment["UITEST_SKIP_ONBOARDING"] != nil
        self.requiresManualAuthentication = environment["UITEST_REQUIRE_MANUAL_AUTH"] == "1"
        self.opensAuthModeConfirmation = environment["UITEST_OPEN_AUTHMODE_CONFIRMATION"] == "1"
        self.preloadsUITestContact = environment["UITEST_PRELOAD_CONTACT"] == "1"
        self.isAuthTraceEnabled = environment["CYPHERAIR_DEBUG_AUTH_TRACE"] == "1"
        self.shouldSkipOnboarding = environment["UITEST_SKIP_ONBOARDING"] == "1" || root != .main
        self.tutorialModule = environment["UITEST_TUTORIAL_TASK"].flatMap { value in
            switch value {
            case "understandSandbox", "sandbox": .sandbox
            case "generateAliceKey", "createDemoIdentity": .createDemoIdentity
            case "importBobKey", "addDemoContact": .addDemoContact
            case "composeAndEncryptMessage", "encryptDemoMessage": .encryptDemoMessage
            case "parseRecipients", "decryptMessage", "decryptAndVerify": .decryptAndVerify
            case "exportBackup", "backupKey": .backupKey
            case "enableHighSecurity": .enableHighSecurity
            default: nil
            }
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
