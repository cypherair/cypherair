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
    private var openingModuleToken: UUID?
    #if DEBUG
    private var didPrepareUITestCompletionSurface = false
    private var didPrepareUITestAuthModeConfirmation = false
    #endif

    var selectedTab: AppShellTab { navigation.selectedTab }
    var routePath: [AppRoute] { navigation.path(for: navigation.selectedTab) }
    var activeModal: TutorialModal? { navigation.activeModal }
    var visibleRoute: AppRoute? { navigation.visibleSurface.route }
    var isInspectorPresented: Bool { navigation.isInspectorPresented }
    var isOpeningModule: Bool { openingModule != nil }
    var configurationFactory: TutorialConfigurationFactory { TutorialConfigurationFactory(store: self) }
    var blocklist = TutorialUnsafeRouteBlocklist()

    init(
        openTutorialContacts: @escaping @MainActor (TutorialSandboxContainer) async throws -> Void = { container in
            try await container.openContactsIfNeeded()
        }
    ) {
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
        guard let completionState = protectedOrdinarySettings?.guidedTutorialCompletionState else {
            return false
        }
        return completionState != .neverCompleted
    }

    var outputInterceptionPolicy: OutputInterceptionPolicy? {
        guard session.hasStartedSession else { return nil }

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
            resetTutorial()
        } else if session.hasStartedSession && container == nil {
            recreateContainer()
            session.surface = .hub
        } else {
            session.surface = .hub
        }
    }

    func openModule(_ requestedModule: TutorialModuleID) async {
        guard canOpen(requestedModule) else { return }
        guard let openingToken = beginOpeningModule(requestedModule) else { return }
        defer {
            finishOpeningModule(openingToken)
        }

        ensureSession()
        guard let activeContainer = container,
              let activeSessionID = session.sessionID else {
            return
        }
        guard await openContactsIfNeeded(
            for: activeContainer,
            sessionID: activeSessionID
        ) else {
            return
        }

        if requestedModule == .sandbox {
            openSandboxAcknowledgement()
            return
        }

        if requestedModule == .addDemoContact {
            await ensureBobPrepared(
                container: activeContainer,
                sessionID: activeSessionID
            )
            guard isCurrentTutorialSession(
                container: activeContainer,
                sessionID: activeSessionID
            ) else {
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
        ensureSession()
        navigation.activeModal = nil
        errorMessage = nil
        session.pendingCompletionPromptModule = nil
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
        // Preserve the live navigation tree until the workspace is no longer rendered.
        // On macOS, tearing down routed tutorial content before switching surfaces can
        // trip SwiftUI/AttributeGraph into a tagged-memory fault during teardown.
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

    func resetTutorial() {
        container?.cleanup()
        container = nil
        session = TutorialSessionState()
        navigation = TutorialNavigationState()
        errorMessage = nil
        clearOpeningModule()
    }

    func markFinishedTutorial() {
        protectedOrdinarySettings?.markGuidedTutorialCompletedCurrentVersion()
        session.lifecycleState = .finished
    }

    func finishAndCleanupTutorial() {
        container?.cleanup()
        container = nil
        session = TutorialSessionState()
        navigation = TutorialNavigationState()
        errorMessage = nil
        clearOpeningModule()
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

    func prepareUITestContactDetailSurfaceIfRequested(
        processInfo: ProcessInfo = .processInfo
    ) async -> Bool {
        guard processInfo.environment["UITEST_TUTORIAL_CONTACT_DETAIL"] == "1" else {
            return false
        }

        ensureSession()
        markCompletedForTesting(.sandbox)
        markCompletedForTesting(.createDemoIdentity)
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

    func prepareUITestCompletionSurfaceIfRequested(
        processInfo: ProcessInfo = .processInfo
    ) -> Bool {
        guard processInfo.environment["UITEST_TUTORIAL_COMPLETION"] == "1",
              !didPrepareUITestCompletionSurface else {
            return false
        }

        didPrepareUITestCompletionSurface = true
        ensureSession()
        for module in TutorialModuleID.allCases {
            markCompletedForTesting(module)
        }
        session.pendingCompletionPromptModule = nil
        showCompletionView()
        return true
    }

    func prepareUITestAuthModeConfirmationIfRequested(
        processInfo: ProcessInfo = .processInfo
    ) async -> Bool {
        guard processInfo.environment["UITEST_TUTORIAL_AUTHMODE_CONFIRMATION"] == "1",
              !didPrepareUITestAuthModeConfirmation else {
            return false
        }

        didPrepareUITestAuthModeConfirmation = true
        ensureSession()
        for module in TutorialModuleID.allCases where module.rawValue < TutorialModuleID.enableHighSecurity.rawValue {
            markCompletedForTesting(module)
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

    private func beginOpeningModule(_ module: TutorialModuleID) -> UUID? {
        guard openingModule == nil else { return nil }
        let token = UUID()
        openingModule = module
        openingModuleToken = token
        return token
    }

    private func finishOpeningModule(_ token: UUID) {
        guard openingModuleToken == token else { return }
        clearOpeningModule()
    }

    private func clearOpeningModule() {
        openingModule = nil
        openingModuleToken = nil
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

    private func openContactsIfNeeded(
        for activeContainer: TutorialSandboxContainer,
        sessionID activeSessionID: TutorialSessionID
    ) async -> Bool {
        guard isCurrentTutorialSession(
            container: activeContainer,
            sessionID: activeSessionID
        ) else {
            return false
        }

        do {
            try await openTutorialContacts(activeContainer)
            guard isCurrentTutorialSession(
                container: activeContainer,
                sessionID: activeSessionID
            ) else {
                return false
            }
            errorMessage = nil
            return true
        } catch is CancellationError {
            return false
        } catch {
            if container === activeContainer {
                activeContainer.cleanup()
                container = nil
            }
            errorMessage = error.localizedDescription
            return false
        }
    }

    private func isCurrentTutorialSession(
        container expectedContainer: TutorialSandboxContainer,
        sessionID expectedSessionID: TutorialSessionID
    ) -> Bool {
        !Task.isCancelled
            && container === expectedContainer
            && session.sessionID == expectedSessionID
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
        guard let container,
              let sessionID = session.sessionID else {
            return
        }
        await ensureBobPrepared(container: container, sessionID: sessionID)
    }

    private func ensureBobPrepared(
        container activeContainer: TutorialSandboxContainer,
        sessionID activeSessionID: TutorialSessionID
    ) async {
        guard isCurrentTutorialSession(
            container: activeContainer,
            sessionID: activeSessionID
        ) else {
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
                family: .modernSoftwareV6
            )
            guard isCurrentTutorialSession(
                container: activeContainer,
                sessionID: activeSessionID
            ) else {
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
            guard isCurrentTutorialSession(
                container: activeContainer,
                sessionID: activeSessionID
            ) else {
                return
            }
            errorMessage = error.localizedDescription
        }
    }
}
