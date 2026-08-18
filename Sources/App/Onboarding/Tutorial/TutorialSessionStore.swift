import Foundation
import SwiftUI

@MainActor
@Observable
final class TutorialSessionStore {
    @ObservationIgnored
    private weak var protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator?
    @ObservationIgnored
    private let openTutorialContacts: @MainActor (TutorialSandboxContainer) async throws -> Void

    private(set) var session = TutorialSessionState()
    private(set) var container: TutorialSandboxContainer?
    private(set) var navigation = TutorialNavigationState()
    private(set) var errorMessage: String?
    private(set) var isTutorialPresentationActive = false
    private(set) var openingModule: TutorialModuleID?
    @ObservationIgnored
    private let launchChoreography: AppLaunchConfiguration.TutorialChoreography?
    private var didPerformLaunchChoreography = false

    var selectedTab: AppShellTab { navigation.selectedTab }
    var routePath: [AppRoute] { navigation.path(for: navigation.selectedTab) }
    var activeModal: TutorialModal? { navigation.activeModal }
    var visibleRoute: AppRoute? { navigation.visibleSurface.route }
    var isInspectorPresented: Bool { navigation.isInspectorPresented }
    var isOpeningModule: Bool { openingModule != nil }
    var configurationFactory: TutorialConfigurationFactory { TutorialConfigurationFactory(store: self) }
    var blocklist = TutorialUnsafeRouteBlocklist()

    init(
        launchChoreography: AppLaunchConfiguration.TutorialChoreography? = nil,
        openTutorialContacts: @escaping @MainActor (TutorialSandboxContainer) async throws -> Void = { container in
            try await container.openContactsIfNeeded()
        }
    ) {
        self.launchChoreography = launchChoreography
        self.openTutorialContacts = openTutorialContacts
    }

    var nextModule: TutorialModuleID? {
        session.nextIncompleteModule
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

    var pendingCompletionPromptModule: TutorialModuleID? {
        session.pendingCompletionPromptModule
    }

    var requiresLeaveConfirmation: Bool {
        session.lifecycleState == .inProgress || session.lifecycleState == .stepsCompleted
    }

    var isReplayUnlocked: Bool {
        if session.lifecycleState == .finished {
            return true
        }
        return protectedOrdinarySettings?.hasCompletedGuidedTutorial ?? false
    }

    /// The sandbox session's lifetime is the container's: one object is created
    /// when the session begins and destroyed when it ends, and its identity is
    /// the race token every async continuation checks.
    var hasStartedSession: Bool {
        container != nil
    }

    var outputInterceptionPolicy: OutputInterceptionPolicy? {
        guard hasStartedSession else { return nil }

        return OutputInterceptionPolicy(
            interceptClipboardCopy: { _, _, _ in
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

    func configurePersistence(protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator) {
        self.protectedOrdinarySettings = protectedOrdinarySettings
    }

    func setTutorialPresentationActive(_ isActive: Bool) {
        isTutorialPresentationActive = isActive
    }

    func prepareForPresentation(launchOrigin: TutorialLaunchOrigin) {
        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptModule = nil
        clearNavigationState()

        if session.lifecycleState == .finished {
            endSession()
        }
        session.surface = .hub
    }

    func openModule(_ requestedModule: TutorialModuleID) async {
        guard canOpen(requestedModule) else { return }
        guard beginOpeningModule(requestedModule) else { return }
        defer {
            openingModule = nil
        }

        let activeContainer = beginSessionIfNeeded()
        guard await openContactsIfNeeded(for: activeContainer) else {
            return
        }

        if requestedModule == .sandbox {
            openSandboxAcknowledgement()
            return
        }

        if requestedModule == .addDemoContact {
            await ensureBobPrepared(container: activeContainer)
            guard isCurrentTutorialSession(activeContainer) else {
                return
            }
        }

        resetNavigationState(for: requestedModule)
        session.pendingCompletionPromptModule = nil
        session.surface = .workspace(module: requestedModule)
        refreshLifecycleState()
        errorMessage = nil
    }

    func openSandboxAcknowledgement() {
        _ = beginSessionIfNeeded()
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

    /// The single session-lifetime teardown: destroy the sandbox container and
    /// every piece of session and navigation state with it. Reset, finish, and
    /// a failed contacts open all end the session through here.
    func endSession() {
        container?.cleanup()
        container = nil
        session = TutorialSessionState()
        navigation = TutorialNavigationState()
        errorMessage = nil
    }

    /// Persist tutorial completion and mark the lifecycle finished. Returns
    /// whether completion actually reached persistence — the write can fail
    /// when the real settings domain is locked or saving throws, and callers
    /// see that instead of a silent no-op.
    @discardableResult
    func markFinishedTutorial() -> Bool {
        let persisted = protectedOrdinarySettings?.markGuidedTutorialCompleted() == true
        session.lifecycleState = .finished
        return persisted
    }

    func selectTab(_ tab: AppShellTab) {
        guard navigation.selectedTab != tab else { return }
        navigation.selectedTab = tab
        navigation.activeModal = nil
        navigation.visibleSurface.tab = tab
        navigation.visibleSurface.route = routePath(for: tab).last
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
            set: { newPath in
                // Ignore the outgoing stack's teardown write when the shell
                // switches tabs; it would erase the stored per-tab path.
                guard self.navigation.selectedTab == tab else { return }
                self.setRoutePath(newPath, for: tab)
            }
        )
    }

    @discardableResult
    func presentImportConfirmation(_ request: ImportConfirmationRequest) -> Bool {
        guard navigation.activeModal == nil else {
            return false
        }
        navigation.activeModal = .importConfirmation(request)
        return true
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

    func setInspectorPresented(_ isPresented: Bool) {
        navigation.isInspectorPresented = isPresented
    }

    func noteAliceGenerated(_ identity: PGPKeyIdentity) async {
        session.artifacts.aliceIdentity = identity
        complete(.createDemoIdentity)
        await ensureBobPrepared()
    }

    func noteBobImported(_ contact: ContactIdentitySummary) {
        session.artifacts.bobContact = contact
        complete(.addDemoContact)
    }

    func noteEncrypted(_ ciphertext: Data) {
        session.artifacts.encryptedMessage = String(data: ciphertext, encoding: .utf8)
        complete(.encryptDemoMessage)
    }

    func noteParsed(_ result: DecryptionPhase1Result) {
        session.artifacts.parseResult = result
    }

    func noteDecrypted(
        plaintext: Data,
        verification: DetailedSignatureVerification
    ) {
        complete(.decryptAndVerify)
    }

    func noteBackupExported(_ backupData: Data) {
        complete(.backupKey)
    }

    func noteHighSecurityEnabled(_ mode: AuthenticationMode) {
        complete(.enableHighSecurity)
    }

    #if DEBUG
    func markCompletedForTesting(_ module: TutorialModuleID) {
        complete(module)
    }
    #endif

    /// Stage the surface a UI-test launch asked for, once per process. The
    /// request comes from `AppLaunchConfiguration` — behind its Release kill
    /// switch, so a Release store always holds nil — not from an environment
    /// read of this store's own, and it applies through every presentation
    /// route (window root, cover, Settings sheet).
    func performLaunchChoreographyIfRequested() async -> Bool {
        guard let choreography = launchChoreography,
              !didPerformLaunchChoreography else {
            return false
        }
        didPerformLaunchChoreography = true

        switch choreography {
        case .completionSurface:
            _ = beginSessionIfNeeded()
            for module in TutorialModuleID.allCases {
                complete(module)
            }
            session.pendingCompletionPromptModule = nil
            showCompletionView()
            return true
        case .authModeConfirmation:
            _ = beginSessionIfNeeded()
            for module in TutorialModuleID.allCases
            where module.rawValue < TutorialModuleID.enableHighSecurity.rawValue {
                complete(module)
            }
            await openModule(.enableHighSecurity)
            presentAuthModeConfirmation(
                SettingsAuthModeRequestBuilder.makeRequest(
                    for: .highSecurity,
                    hasBackup: false,
                    onConfirm: { [weak self] in
                        self?.noteHighSecurityEnabled(.highSecurity)
                    },
                    onCancel: {}
                )
            )
            return true
        case .contactDetailSurface:
            _ = beginSessionIfNeeded()
            complete(.sandbox)
            complete(.createDemoIdentity)
            await openModule(.addDemoContact)

            do {
                guard let container else {
                    return false
                }

                await ensureBobPrepared()
                guard let bobArmoredPublicKey = session.artifacts.bobArmoredPublicKey else {
                    return false
                }

                let result = try container.contactService.importContact(
                    publicKeyData: Data(bobArmoredPublicKey.utf8)
                )
                let contact: ContactIdentitySummary
                switch result {
                case .added(let added, _),
                     .addedWithCandidate(let added, _, _),
                     .duplicate(let added, _),
                     .updated(let added, _):
                    contact = added
                }

                noteBobImported(contact)
                selectTab(.contacts)
                setRoutePath(
                    [.contactDetail(contactId: contact.contactId)],
                    for: .contacts
                )
                return true
            } catch {
                errorMessage = error.localizedDescription
                return false
            }
        }
    }

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

    private func beginOpeningModule(_ module: TutorialModuleID) -> Bool {
        guard openingModule == nil else { return false }
        openingModule = module
        return true
    }

    /// The single session-lifetime start: the sandbox container is created
    /// here and nowhere else, and its identity is the session's race token.
    private func beginSessionIfNeeded() -> TutorialSandboxContainer {
        if let container {
            return container
        }
        let newContainer = TutorialSandboxContainer()
        container = newContainer
        session.lifecycleState = .inProgress
        errorMessage = nil
        return newContainer
    }

    private func openContactsIfNeeded(
        for activeContainer: TutorialSandboxContainer
    ) async -> Bool {
        do {
            try await openTutorialContacts(activeContainer)
            guard isCurrentTutorialSession(activeContainer) else {
                return false
            }
            errorMessage = nil
            return true
        } catch is CancellationError {
            return false
        } catch {
            if container === activeContainer {
                endSession()
            }
            errorMessage = error.localizedDescription
            return false
        }
    }

    private func isCurrentTutorialSession(
        _ expectedContainer: TutorialSandboxContainer
    ) -> Bool {
        !Task.isCancelled && container === expectedContainer
    }

    private func refreshLifecycleState() {
        if session.lifecycleState == .finished {
            return
        }

        if session.hasCompletedAllModules {
            session.lifecycleState = .stepsCompleted
        } else if hasStartedSession {
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
        guard let container else {
            return
        }
        await ensureBobPrepared(container: container)
    }

    private func ensureBobPrepared(
        container activeContainer: TutorialSandboxContainer
    ) async {
        guard isCurrentTutorialSession(activeContainer) else {
            return
        }
        if session.artifacts.bobIdentity != nil, session.artifacts.bobArmoredPublicKey != nil {
            return
        }

        do {
            let bob = try await activeContainer.keyManagement.generateKey(
                name: String(
                    localized: "guidedTutorial.demoName.bob",
                    defaultValue: "Bob Demo"
                ),
                email: "bob@demo.invalid",
                expirySeconds: nil,
                family: .portableEd25519X25519
            )
            guard isCurrentTutorialSession(activeContainer) else {
                return
            }
            session.artifacts.bobIdentity = bob
            if let armored = try? activeContainer.keyManagement.exportPublicKey(fingerprint: bob.fingerprint),
               let armoredString = String(data: armored, encoding: .utf8) {
                session.artifacts.bobArmoredPublicKey = armoredString
            }
        } catch is CancellationError {
            return
        } catch {
            guard isCurrentTutorialSession(activeContainer) else {
                return
            }
            errorMessage = error.localizedDescription
        }
    }
}
