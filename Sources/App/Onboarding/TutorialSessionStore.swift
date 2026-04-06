import Foundation
import SwiftUI

@MainActor
@Observable
final class TutorialSessionStore {
    @ObservationIgnored
    private weak var appConfiguration: AppConfiguration?

    private(set) var session = TutorialSessionState()
    private(set) var container: TutorialSandboxContainer?
    private(set) var navigation = TutorialNavigationState()
    private(set) var errorMessage: String?

    var selectedTab: AppShellTab { navigation.selectedTab }
    var routePath: [AppRoute] { navigation.path(for: navigation.selectedTab) }
    var activeModal: TutorialModal? { navigation.activeModal }
    var visibleTab: AppShellTab { navigation.visibleSurface.tab }
    var visibleRoute: AppRoute? { navigation.visibleSurface.route }
    var isInspectorPresented: Bool { navigation.isInspectorPresented }
    var configurationFactory: TutorialConfigurationFactory { TutorialConfigurationFactory(store: self) }
    var blocklist = TutorialUnsafeRouteBlocklist()

    var nextModule: TutorialModuleID? {
        session.nextIncompleteModule
    }

    var hasCompletedAllModules: Bool {
        session.hasCompletedAllModules
    }

    var lifecycleState: TutorialLifecycleState {
        session.lifecycleState
    }

    var hostSurface: TutorialHostSurface {
        session.surface
    }

    var currentModule: TutorialModuleID? {
        session.activeModule
    }

    var isShowingCompletionView: Bool {
        session.surface == .completion
    }

    var isShowingSandboxAcknowledgement: Bool {
        session.surface == .sandboxAcknowledgement
    }

    var pendingCompletionPromptModule: TutorialModuleID? {
        session.pendingCompletionPromptModule
    }

    var canFinishFromCompletionSurface: Bool {
        session.lifecycleState == .stepsCompleted
    }

    var requiresLeaveConfirmation: Bool {
        session.lifecycleState == .inProgress || session.lifecycleState == .stepsCompleted
    }

    var isReplayUnlocked: Bool {
        if session.lifecycleState == .finished {
            return true
        }
        guard let appConfiguration else { return false }
        return appConfiguration.guidedTutorialCompletionState != .neverCompleted
    }

    var sideEffectInterceptor: TutorialSideEffectInterceptor? {
        guard session.hasStartedSession else { return nil }

        return TutorialSideEffectInterceptor(
            interceptClipboardWrite: { _, _ in
                true
            },
            interceptDataExport: { _, _, _ in
                true
            },
            interceptFileExport: { _, _, _ in
                true
            }
        )
    }

    var surfaceConfiguration: TutorialSurfaceConfiguration {
        TutorialSurfaceConfiguration(
            activeModule: session.activeModule,
            blocklist: blocklist,
            sideEffectInterceptor: sideEffectInterceptor ?? .passthrough
        )
    }

    func isCompleted(_ module: TutorialModuleID) -> Bool {
        session.moduleStates[module]?.isCompleted == true
    }

    func canOpen(_ module: TutorialModuleID) -> Bool {
        if isCompleted(module) || isReplayUnlocked {
            return true
        }

        guard let index = TutorialModuleID.allCases.firstIndex(of: module) else { return false }
        if index == 0 {
            return true
        }

        let previousModules = TutorialModuleID.allCases.prefix(index)
        return previousModules.allSatisfy { isCompleted($0) }
    }

    func configurePersistence(appConfiguration: AppConfiguration) {
        self.appConfiguration = appConfiguration
    }

    func prepareForPresentation(launchOrigin: TutorialLaunchOrigin) {
        session.launchOrigin = launchOrigin
        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptModule = nil
        clearNavigationState()

        if session.lifecycleState == .finished {
            resetTutorial()
            session.launchOrigin = launchOrigin
        } else if session.hasStartedSession && container == nil {
            recreateContainer()
            session.surface = .hub
        } else {
            session.surface = .hub
        }
    }

    func openModule(_ requestedModule: TutorialModuleID) async {
        guard canOpen(requestedModule) else { return }

        ensureSession()

        if requestedModule == .sandbox {
            openSandboxAcknowledgement()
            return
        }

        if requestedModule == .addDemoContact {
            await ensureBobPrepared()
        }

        resetNavigationState(for: requestedModule)
        session.pendingCompletionPromptModule = nil
        session.surface = .workspace(module: requestedModule)
        refreshLifecycleState()
        errorMessage = nil
    }

    func openSandboxAcknowledgement() {
        ensureSession()
        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptModule = nil
        clearNavigationState()
        session.surface = .sandboxAcknowledgement
        refreshLifecycleState()
    }

    func confirmSandboxAcknowledgement() {
        complete(.sandbox)
        if let nextModule = session.nextIncompleteModule {
            Task { @MainActor in
                await openModule(nextModule)
            }
        } else {
            showCompletionView()
        }
    }

    func returnToOverview() {
        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptModule = nil
        clearNavigationState()
        session.surface = .hub
    }

    func showCompletionView() {
        guard session.hasCompletedAllModules else {
            returnToOverview()
            return
        }

        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptModule = nil
        clearNavigationState()
        session.surface = .completion
        refreshLifecycleState()
    }

    func dismissCompletionView() {
        session.surface = .hub
    }

    func dismissCompletionPrompt() {
        session.pendingCompletionPromptModule = nil
    }

    func handlePrimaryCompletionPromptAction() {
        guard let promptModule = session.pendingCompletionPromptModule else { return }
        session.pendingCompletionPromptModule = nil

        if promptModule == .enableHighSecurity {
            showCompletionView()
        } else {
            returnToOverview()
        }
    }

    func resetTutorial() {
        container?.cleanup()
        container = nil
        session = TutorialSessionState()
        navigation = TutorialNavigationState()
        errorMessage = nil
    }

    func markFinishedTutorial() {
        appConfiguration?.markGuidedTutorialCompletedCurrentVersion()
        session.lifecycleState = .finished
    }

    func finishAndCleanupTutorial() {
        container?.cleanup()
        container = nil
        session = TutorialSessionState()
        navigation = TutorialNavigationState()
        errorMessage = nil
    }

    func selectTab(_ tab: AppShellTab) {
        guard navigation.selectedTab != tab else { return }
        navigation.selectedTab = tab
        navigation.activeModal = nil
        navigation.visibleSurface.tab = tab
        navigation.visibleSurface.route = routePath(for: tab).last
    }

    func setRoutePath(_ path: [AppRoute]) {
        setRoutePath(path, for: navigation.selectedTab)
    }

    func routePath(for tab: AppShellTab) -> [AppRoute] {
        navigation.path(for: tab)
    }

    func setRoutePath(_ path: [AppRoute], for tab: AppShellTab) {
        navigation.pathsByTab[tab] = path
        if navigation.selectedTab == tab {
            navigation.visibleSurface.tab = tab
            navigation.visibleSurface.route = path.last
        }
    }

    func routePathBinding(for tab: AppShellTab) -> Binding<[AppRoute]> {
        Binding(
            get: { self.routePath(for: tab) },
            set: { self.setRoutePath($0, for: tab) }
        )
    }

    func presentImportConfirmation(_ request: ImportConfirmationRequest) {
        navigation.activeModal = .importConfirmation(request)
    }

    func presentAuthModeConfirmation(_ request: AuthModeChangeConfirmationRequest) {
        navigation.activeModal = .authModeConfirmation(request)
    }

    func presentLeaveConfirmation(onLeave: @escaping @MainActor () -> Void) {
        navigation.activeModal = .leaveConfirmation(
            TutorialLeaveConfirmationRequest(
                onContinue: { [weak self] in
                    self?.dismissModal()
                },
                onLeave: { [weak self] in
                    self?.dismissModal()
                    self?.returnToOverview()
                    onLeave()
                }
            )
        )
    }

    func dismissModal() {
        navigation.activeModal = nil
    }

    func noteVisibleSurface(tab: AppShellTab, route: AppRoute?) {
        navigation.visibleSurface = TutorialVisibleSurface(tab: tab, route: route)
    }

    func noteGuidance(_ guidance: TutorialGuidancePayload?) {
        session.currentGuidance = guidance
    }

    func setInspectorPresented(_ isPresented: Bool) {
        navigation.isInspectorPresented = isPresented
    }

    func noteAliceGenerated(_ identity: PGPKeyIdentity) async {
        session.artifacts.aliceIdentity = identity
        complete(.createDemoIdentity)
        await ensureBobPrepared()
    }

    func noteBobImported(_ contact: Contact) {
        session.artifacts.bobContact = contact
        complete(.addDemoContact)
    }

    func noteEncrypted(_ ciphertext: Data) {
        session.artifacts.encryptedMessage = String(data: ciphertext, encoding: .utf8)
        complete(.encryptDemoMessage)
    }

    func noteParsed(_ result: DecryptionService.Phase1Result) {
        session.artifacts.parseResult = result
    }

    func noteDecrypted(
        plaintext: Data,
        verification: SignatureVerification
    ) {
        session.artifacts.decryptedMessage = String(data: plaintext, encoding: .utf8)
        session.artifacts.decryptedVerification = verification
        complete(.decryptAndVerify)
    }

    func noteBackupExported(_ backupData: Data) {
        session.artifacts.backupArmoredKey = String(data: backupData, encoding: .utf8)
        complete(.backupKey)
    }

    func noteHighSecurityEnabled(_ mode: AuthenticationMode) {
        session.artifacts.authMode = mode
        complete(.enableHighSecurity)
    }

    #if DEBUG
    func markCompletedForTesting(_ module: TutorialModuleID) {
        complete(module)
    }
    #endif

    func navigateToPostGenerationPrompt(_ identity: PGPKeyIdentity) {
        var path = routePath(for: navigation.selectedTab)
        path.append(.postGenerationPrompt(identity: identity))
        setRoutePath(path, for: navigation.selectedTab)
    }

    private func complete(_ module: TutorialModuleID) {
        session.moduleStates[module]?.isCompleted = true
        if module != .sandbox {
            session.pendingCompletionPromptModule = module
        }
        refreshLifecycleState()
    }

    private func ensureSession() {
        if container == nil {
            recreateContainer()
        }

        if session.sessionID == nil {
            session.sessionID = TutorialSessionID()
            session.lifecycleState = .inProgress
        }
    }

    private func recreateContainer() {
        do {
            container = try TutorialSandboxContainer()
            errorMessage = nil
        } catch {
            container = nil
            errorMessage = error.localizedDescription
        }
    }

    private func refreshLifecycleState() {
        if session.lifecycleState == .finished {
            return
        }

        if session.hasCompletedAllModules {
            session.lifecycleState = .stepsCompleted
        } else if session.hasStartedSession {
            session.lifecycleState = .inProgress
        } else {
            session.lifecycleState = .notStarted
        }
    }

    private func resetNavigationState(for module: TutorialModuleID) {
        navigation = TutorialNavigationState()
        navigation.selectedTab = module.tab
        navigation.visibleSurface.tab = navigation.selectedTab
    }

    private func clearNavigationState() {
        navigation = TutorialNavigationState()
    }

    private func ensureBobPrepared() async {
        guard let container else { return }
        if session.artifacts.bobIdentity != nil, session.artifacts.bobArmoredPublicKey != nil {
            return
        }

        do {
            let bob = try await container.keyManagement.generateKey(
                name: "Bob Demo",
                email: "bob@demo.invalid",
                expirySeconds: nil,
                profile: .advanced,
                authMode: .standard
            )
            session.artifacts.bobIdentity = bob
            if let armored = try? container.keyManagement.exportPublicKey(fingerprint: bob.fingerprint),
               let armoredString = String(data: armored, encoding: .utf8) {
                session.artifacts.bobArmoredPublicKey = armoredString
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
