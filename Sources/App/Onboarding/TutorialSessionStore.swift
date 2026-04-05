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

    var isShowingCompletionView: Bool {
        session.isShowingCompletionView
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

    func openTask(_ requestedTask: TutorialTaskID) async {
        ensureSession()

        let task: TutorialTaskID
        if !isCompleted(.understandSandbox) {
            complete(.understandSandbox)
            task = requestedTask == .understandSandbox ? .generateAliceKey : requestedTask
        } else {
            task = requestedTask == .understandSandbox ? (nextTask ?? .generateAliceKey) : requestedTask
        }

        if task == .importBobKey {
            await ensureBobPrepared()
        }

        resetNavigationState(for: task)
        session.activeTask = task
        session.isShellPresented = true
        session.isShowingCompletionView = false
        errorMessage = nil
    }

    func dismissShell() {
        session.isShellPresented = false
        session.activeTask = nil
        clearNavigationState()
        if session.hasCompletedAllTasks {
            session.isShowingCompletionView = true
        }
    }

    func dismissCompletionView() {
        session.isShowingCompletionView = false
    }

    func resetTutorial() {
        container?.cleanup()
        recreateContainer()
    }

    func selectTab(_ tab: AppShellTab) {
        guard navigation.selectedTab != tab else { return }
        navigation.selectedTab = tab
        navigation.activeModal = nil
        navigation.visibleSurface.tab = tab
        navigation.visibleSurface.route = navigation.path(for: tab).last
    }

    func setRoutePath(_ path: [AppRoute]) {
        navigation.pathsByTab[navigation.selectedTab] = path
        navigation.visibleSurface.route = path.last
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
        var path = navigation.path(for: navigation.selectedTab)
        path.append(.postGenerationPrompt(identity: identity))
        navigation.pathsByTab[navigation.selectedTab] = path
        navigation.visibleSurface.route = path.last
    }
}
