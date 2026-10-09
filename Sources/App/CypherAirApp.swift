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

    @State private var container: AppContainer
    @State private var tutorialStore: TutorialSessionStore
    @State private var incomingURLImportCoordinator: IncomingURLImportCoordinator
    @State private var launchConfiguration: AppLaunchConfiguration
    #if os(macOS)
    @State private var macShellNavigationState = MacShellNavigationState()
    #endif
    #if os(iOS) || os(visionOS)
    @State private var iosPresentationState = TutorialOnboardingHandoffState()
    #endif

    init() {
        #if os(macOS)
        ScreenCaptureExclusion.install()
        #endif
        let launchConfiguration = AppLaunchConfiguration()
        let container: AppContainer
        #if DEBUG
        if launchConfiguration.usesUITestAppContainer {
            container = AppContainer.makeUITest()
            container.startUITestSession(
                passphrase: launchConfiguration.uiTestVaultPassphrase,
                startsUnlocked: launchConfiguration.bootsPreAuthenticated,
                preloadContact: launchConfiguration.preloadsUITestContact
                    && !launchConfiguration.requiresManualAuthentication
            )
        } else {
            container = AppContainer.makeDefault()
        }
        #else
        container = AppContainer.makeDefault()
        #endif
        if launchConfiguration.shouldSkipOnboarding {
            container.appSettings.applyOnboardingCompletionOverrideForTesting(true)
        }
        container.sweepTemporaryArtifactsAtLaunch()
        let tutorialStore = TutorialSessionStore()
        let incomingURLImportCoordinator = IncomingURLImportCoordinator(
            importLoader: PublicKeyImportLoader(qrService: container.qrService),
            importWorkflow: ContactImportWorkflow(contactService: container.contactService)
        )
        _launchConfiguration = State(initialValue: launchConfiguration)
        _container = State(initialValue: container)
        _tutorialStore = State(initialValue: tutorialStore)
        _incomingURLImportCoordinator = State(initialValue: incomingURLImportCoordinator)
    }

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
            MacKeyboardCommands(navigationState: macShellNavigationState)
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
            MacAppShellView(navigationState: macShellNavigationState)
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
            coordinator: container.localDataResetRestartCoordinator,
            terminateAction: LocalDataResetRestartAction.terminateCurrentProcess
        ) {
            ImportConfirmationSheetHost(coordinator: incomingURLImportCoordinator.importConfirmationCoordinator) {
                mainWindowContent
                    .appLockShieldWindow(
                        appLockController: container.appLockController,
                        services: container.lockSurfaceServices
                    )
                    .appLifecycleObserver(
                        appLockController: container.appLockController
                    )
                    .environment(container.appLockController)
                    .environment(container.appSettings)
                    .environment(container.keyManagement)
                    .environment(container.contactService)
                    .environment(container.encryptionService)
                    .environment(container.decryptionService)
                    .environment(container.signingService)
                    .environment(container.certificateSignatureService)
                    .environment(container.qrService)
                    .environment(container.selfTestService)
                    .environment(container.appSessionOrchestrator)
                    .environment(\.localDataResetService, container.localDataResetService)
                    .environment(\.localDataResetRestartCoordinator, container.localDataResetRestartCoordinator)
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
        .onChange(of: container.appSettings.snapshot) { _, _ in
            guard !container.localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset else { return }
            if container.appSettings.hasCompletedOnboarding == false,
               iosPresentationState.activePresentation == nil {
                iosPresentationState.activePresentation = .onboarding(initialPage: 0, context: .firstRun)
            }
        }
        #endif
        .incomingURLImportAlerts(coordinator: incomingURLImportCoordinator)
        .onOpenURL { url in
            incomingURLRouter.handle(url)
        }
    }

    private var incomingURLRouter: AppSceneIncomingURLRouter {
        AppSceneIncomingURLRouter(
            incomingURLImportCoordinator: incomingURLImportCoordinator,
            tutorialStore: tutorialStore,
            localDataResetRestartCoordinator: container.localDataResetRestartCoordinator
        )
    }

    #if os(iOS) || os(visionOS)
    private var onboardingPresentationBinding: Binding<IOSPresentation?> {
        Binding(
            get: {
                guard !container.localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset else {
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
                guard !container.localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset else {
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
            .environment(container.appSettings)
            .environment(tutorialStore)
            .environment(\.iosPresentationController, iosPresentationControllerValue)
            .interactiveDismissDisabled(
                context == .firstRun
                    && container.appSettings.hasCompletedOnboarding != true
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
            .environment(container.appSettings)
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
        guard !container.localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset else { return }
        guard iosPresentationState.activePresentation == nil else { return }
        switch launchConfiguration.root {
        case .tutorial:
            iosPresentationState.activePresentation = .tutorial(presentationContext: .inApp)
        case .main:
            if container.appSettings.hasCompletedOnboarding == false {
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
}
