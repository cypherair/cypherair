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

    var nextTask: TutorialTaskID? {
        session.nextIncompleteTask
    }

    var hasCompletedAllTasks: Bool {
        session.hasCompletedAllTasks
    }

    var flowPhase: TutorialFlowPhase {
        session.flowPhase
    }

    var isShowingCompletionView: Bool {
        session.isShowingCompletionView
    }

    var isShowingSandboxAcknowledgement: Bool {
        session.flowPhase == .sandboxAcknowledgement
    }

    var pendingCompletionPromptTask: TutorialTaskID? {
        session.pendingCompletionPromptTask
    }

    func isCompleted(_ task: TutorialTaskID) -> Bool {
        session.taskStates[task]?.isCompleted == true
    }

    func configurePersistence(appConfiguration: AppConfiguration) {
        self.appConfiguration = appConfiguration
    }

    func ensureSession() {
        if container == nil {
            recreateContainer()
        }
    }

    func prepareForPresentation() {
        ensureSession()
        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptTask = nil
        session.flowPhase = .overview
        clearNavigationState()
    }

    func openTask(_ requestedTask: TutorialTaskID) async {
        ensureSession()

        if requestedTask == .understandSandbox {
            openSandboxAcknowledgement()
            return
        }

        let task = requestedTask
        if task == .importBobKey {
            await ensureBobPrepared()
        }

        resetNavigationState(for: task)
        session.pendingCompletionPromptTask = nil
        session.flowPhase = .sandbox(task: task)
        errorMessage = nil
    }

    func openSandboxAcknowledgement() {
        ensureSession()
        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptTask = nil
        clearNavigationState()
        session.flowPhase = .sandboxAcknowledgement
    }

    func confirmSandboxAcknowledgement() {
        complete(.understandSandbox)
        returnToOverview()
    }

    func returnToOverview() {
        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptTask = nil
        clearNavigationState()
        session.flowPhase = .overview
    }

    func showCompletionView() {
        guard session.hasCompletedAllTasks else {
            returnToOverview()
            return
        }

        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptTask = nil
        clearNavigationState()
        session.flowPhase = .completion
    }

    func dismissCompletionView() {
        session.pendingCompletionPromptTask = nil
        session.flowPhase = .overview
    }

    func dismissCompletionPrompt() {
        session.pendingCompletionPromptTask = nil
    }

    func handlePrimaryCompletionPromptAction() {
        guard let promptTask = session.pendingCompletionPromptTask else { return }
        session.pendingCompletionPromptTask = nil

        if promptTask == TutorialTaskID.allCases.last {
            showCompletionView()
        } else {
            returnToOverview()
        }
    }

    func resetTutorial() {
        container?.cleanup()
        recreateContainer()
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

    func dismissModal() {
        navigation.activeModal = nil
    }

    func noteVisibleSurface(tab: AppShellTab, route: AppRoute?) {
        navigation.visibleSurface = TutorialVisibleSurface(tab: tab, route: route)
    }

    func setInspectorPresented(_ isPresented: Bool) {
        navigation.isInspectorPresented = isPresented
    }

    func noteAliceGenerated(_ identity: PGPKeyIdentity) async {
        session.artifacts.aliceIdentity = identity
        complete(.generateAliceKey)
        await ensureBobPrepared()
    }

    func noteBobImported(_ contact: Contact) {
        session.artifacts.bobContact = contact
        complete(.importBobKey)
    }

    func noteEncrypted(_ ciphertext: Data) {
        session.artifacts.encryptedMessage = String(data: ciphertext, encoding: .utf8)
        complete(.composeAndEncryptMessage)
    }

    func noteParsed(_ result: DecryptionService.Phase1Result) {
        session.artifacts.parseResult = result
        complete(.parseRecipients)
    }

    func noteDecrypted(
        plaintext: Data,
        verification: SignatureVerification
    ) {
        session.artifacts.decryptedMessage = String(data: plaintext, encoding: .utf8)
        session.artifacts.decryptedVerification = verification
        complete(.decryptMessage)
    }

    func noteBackupExported(_ backupData: Data) {
        session.artifacts.backupArmoredKey = String(data: backupData, encoding: .utf8)
        complete(.exportBackup)
    }

    func noteHighSecurityEnabled(_ mode: AuthenticationMode) {
        session.artifacts.authMode = mode
        complete(.enableHighSecurity)
    }

    #if DEBUG
    func markCompletedForTesting(_ task: TutorialTaskID) {
        complete(task)
    }
    #endif

    private func complete(_ task: TutorialTaskID) {
        session.taskStates[task]?.isCompleted = true
        if task != .understandSandbox {
            session.pendingCompletionPromptTask = task
        }
        if session.hasCompletedAllTasks {
            appConfiguration?.markGuidedTutorialCompletedCurrentVersion()
        }
    }

    private func recreateContainer() {
        do {
            container = try TutorialSandboxContainer()
            session = TutorialSessionState()
            navigation = TutorialNavigationState()
            errorMessage = nil
        } catch {
            container = nil
            session = TutorialSessionState()
            navigation = TutorialNavigationState()
            errorMessage = error.localizedDescription
        }
    }

    private func resetNavigationState(for task: TutorialTaskID) {
        navigation = TutorialNavigationState()
        navigation.selectedTab = initialSelection(for: task)
        navigation.visibleSurface.tab = navigation.selectedTab
    }

    private func clearNavigationState() {
        navigation = TutorialNavigationState()
    }

    private func initialSelection(for task: TutorialTaskID) -> AppShellTab {
        switch task {
        case .generateAliceKey, .exportBackup:
            .keys
        case .importBobKey:
            .contacts
        case .composeAndEncryptMessage, .parseRecipients, .decryptMessage, .understandSandbox:
            .home
        case .enableHighSecurity:
            .settings
        }
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

    func navigateToPostGenerationPrompt(_ identity: PGPKeyIdentity) {
        var path = routePath(for: navigation.selectedTab)
        path.append(.postGenerationPrompt(identity: identity))
        setRoutePath(path, for: navigation.selectedTab)
    }
}
