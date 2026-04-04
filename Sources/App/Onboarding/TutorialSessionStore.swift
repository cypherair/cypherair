import Foundation
import SwiftUI

enum TutorialPhaseID: Int, CaseIterable, Identifiable {
    case sandboxIntro
    case createDemoKey
    case addDemoContact
    case encryptMessage
    case decryptAndVerify
    case protectKeys

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .sandboxIntro:
            String(localized: "guidedTutorial.phase.intro", defaultValue: "Sandbox Intro")
        case .createDemoKey:
            String(localized: "guidedTutorial.phase.key", defaultValue: "Create Demo Key")
        case .addDemoContact:
            String(localized: "guidedTutorial.phase.contact", defaultValue: "Add Demo Contact")
        case .encryptMessage:
            String(localized: "guidedTutorial.phase.encrypt", defaultValue: "Encrypt Message")
        case .decryptAndVerify:
            String(localized: "guidedTutorial.phase.decrypt", defaultValue: "Decrypt & Verify")
        case .protectKeys:
            String(localized: "guidedTutorial.phase.protect", defaultValue: "Protect Keys")
        }
    }

    var tasks: [TutorialTaskID] {
        TutorialTaskID.allCases.filter { $0.phase == self }
    }
}

enum TutorialTaskID: CaseIterable, Hashable, Identifiable {
    case understandSandbox
    case generateAliceKey
    case importBobKey
    case composeAndEncryptMessage
    case parseRecipients
    case decryptMessage
    case exportBackup
    case enableHighSecurity

    var id: Self { self }

    var phase: TutorialPhaseID {
        switch self {
        case .understandSandbox:
            .sandboxIntro
        case .generateAliceKey:
            .createDemoKey
        case .importBobKey:
            .addDemoContact
        case .composeAndEncryptMessage:
            .encryptMessage
        case .parseRecipients, .decryptMessage:
            .decryptAndVerify
        case .exportBackup, .enableHighSecurity:
            .protectKeys
        }
    }

    var title: String {
        switch self {
        case .understandSandbox:
            String(localized: "guidedTutorial.task.intro", defaultValue: "Understand the sandbox")
        case .generateAliceKey:
            String(localized: "guidedTutorial.task.generate", defaultValue: "Generate Alice's key")
        case .importBobKey:
            String(localized: "guidedTutorial.task.import", defaultValue: "Import Bob's contact")
        case .composeAndEncryptMessage:
            String(localized: "guidedTutorial.task.encrypt", defaultValue: "Compose and encrypt a message")
        case .parseRecipients:
            String(localized: "guidedTutorial.task.parse", defaultValue: "Check recipients")
        case .decryptMessage:
            String(localized: "guidedTutorial.task.decrypt", defaultValue: "Decrypt and verify")
        case .exportBackup:
            String(localized: "guidedTutorial.task.backup", defaultValue: "Export a backup")
        case .enableHighSecurity:
            String(localized: "guidedTutorial.task.highSecurity", defaultValue: "Enable High Security")
        }
    }
}

struct TutorialArtifacts {
    var aliceIdentity: PGPKeyIdentity?
    var bobIdentity: PGPKeyIdentity?
    var bobArmoredPublicKey: String?
    var bobContact: Contact?
    var encryptedMessage: String?
    var parseResult: DecryptionService.Phase1Result?
    var decryptedMessage: String?
    var decryptedVerification: SignatureVerification?
    var backupArmoredKey: String?
    var authMode: AuthenticationMode = .standard
}

struct TutorialTaskState {
    var isCompleted = false
}

struct TutorialSessionState {
    var taskStates: [TutorialTaskID: TutorialTaskState] = Dictionary(
        uniqueKeysWithValues: TutorialTaskID.allCases.map { ($0, TutorialTaskState()) }
    )
    var artifacts = TutorialArtifacts()
    var activeTask: TutorialTaskID?
    var isShellPresented = false
    var isShowingCompletionView = false

    var completedCount: Int {
        taskStates.values.filter(\.isCompleted).count
    }

    var progressValue: Double {
        Double(completedCount) / Double(TutorialTaskID.allCases.count)
    }

    var nextIncompleteTask: TutorialTaskID? {
        TutorialTaskID.allCases.first { taskStates[$0]?.isCompleted != true }
    }

    var hasCompletedAllTasks: Bool {
        nextIncompleteTask == nil
    }
}

struct TutorialGuidance {
    let title: String
    let body: String
    let target: TutorialAnchorID?
}

enum TutorialModal: Identifiable {
    case importConfirmation(ImportConfirmationRequest)
    case postGenerationPrompt(PGPKeyIdentity)
    case authModeConfirmation(AuthModeChangeConfirmationRequest)

    var id: String {
        switch self {
        case .importConfirmation(let request):
            "import-\(request.id.uuidString)"
        case .postGenerationPrompt(let identity):
            "postgen-\(identity.fingerprint)"
        case .authModeConfirmation(let request):
            "auth-\(request.id.uuidString)"
        }
    }
}

@MainActor
@Observable
final class TutorialSessionStore {
    @ObservationIgnored
    private weak var appConfiguration: AppConfiguration?

    private(set) var session = TutorialSessionState()
    private(set) var container: TutorialSandboxContainer?
    private(set) var selectedTab: AppShellTab = .home
    private(set) var routePath: [AppRoute] = []
    private(set) var activeModal: TutorialModal?
    private(set) var visibleTab: AppShellTab = .home
    private(set) var visibleRoute: AppRoute?
    private(set) var errorMessage: String?

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
        guard selectedTab != tab else { return }
        selectedTab = tab
        routePath.removeAll()
        activeModal = nil
        visibleTab = tab
        visibleRoute = nil
    }

    func setRoutePath(_ path: [AppRoute]) {
        routePath = path
        visibleRoute = path.last
    }

    func presentImportConfirmation(_ request: ImportConfirmationRequest) {
        activeModal = .importConfirmation(request)
    }

    func presentPostGenerationPrompt(_ identity: PGPKeyIdentity) {
        activeModal = .postGenerationPrompt(identity)
    }

    func presentAuthModeConfirmation(_ request: AuthModeChangeConfirmationRequest) {
        activeModal = .authModeConfirmation(request)
    }

    func dismissModal() {
        activeModal = nil
    }

    func noteVisibleSurface(tab: AppShellTab, route: AppRoute?) {
        visibleTab = tab
        visibleRoute = route
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

    func keyGenerationConfiguration() -> KeyGenerationView.Configuration {
        KeyGenerationView.Configuration(
            prefilledName: "Alice Demo",
            prefilledEmail: "alice@demo.invalid",
            lockedProfile: .advanced,
            lockedExpiryMonths: 24,
            postGenerationBehavior: .externalPrompt,
            onGenerated: { [weak self] identity in
                Task { @MainActor in
                    await self?.noteAliceGenerated(identity)
                }
            },
            onPostGenerationPromptRequested: { [weak self] identity in
                self?.presentPostGenerationPrompt(identity)
            }
        )
    }

    func addContactConfiguration() -> AddContactView.Configuration {
        AddContactView.Configuration(
            allowedImportModes: [.paste],
            prefilledArmoredText: session.artifacts.bobArmoredPublicKey,
            verificationPolicy: .verifiedOnly,
            onImported: { [weak self] contact in
                self?.noteBobImported(contact)
            },
            onImportConfirmationRequested: { [weak self] request in
                self?.presentImportConfirmation(request)
            }
        )
    }

    func encryptConfiguration() -> EncryptView.Configuration {
        EncryptView.Configuration(
            allowedModes: [.text],
            prefilledPlaintext: String(
                localized: "guidedTutorial.encrypt.prefill",
                defaultValue: "Hi Bob, this is a sandbox message from Alice. It is signed and encrypted inside the guided tutorial."
            ),
            initialRecipientFingerprints: session.artifacts.bobContact.map { [$0.fingerprint] } ?? [],
            initialSignerFingerprint: session.artifacts.aliceIdentity?.fingerprint,
            signingPolicy: .fixed(true),
            encryptToSelfPolicy: .fixed(false),
            onEncrypted: { [weak self] ciphertext in
                self?.noteEncrypted(ciphertext)
            }
        )
    }

    func decryptConfiguration(for task: TutorialTaskID) -> DecryptView.Configuration {
        DecryptView.Configuration(
            allowedModes: [.text],
            prefilledCiphertext: session.artifacts.encryptedMessage,
            initialPhase1Result: task == .decryptMessage ? session.artifacts.parseResult : nil,
            onParsed: { [weak self] result in
                self?.noteParsed(result)
            },
            onDecrypted: { [weak self] plaintext, verification in
                self?.noteDecrypted(plaintext: plaintext, verification: verification)
            }
        )
    }

    func backupConfiguration() -> BackupKeyView.Configuration {
        BackupKeyView.Configuration(
            resultPresentation: .inline,
            onExported: { [weak self] data in
                self?.noteBackupExported(data)
            }
        )
    }

    func settingsConfiguration() -> SettingsView.Configuration {
        SettingsView.Configuration(
            onAuthModeConfirmationRequested: { [weak self] request in
                self?.presentAuthModeConfirmation(request)
            }
        )
    }

    func guidance(
        sizeClass: UserInterfaceSizeClass?,
        selectedTab: AppShellTab
    ) -> TutorialGuidance? {
        guard activeModal == nil else { return nil }
        guard let task = session.activeTask else { return nil }

        switch task {
        case .generateAliceKey:
            if selectedTab != .keys {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.keys", defaultValue: "Open the Keys tab to continue."),
                    target: nil
                )
            }
            if visibleRoute == nil {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.keys.entry", defaultValue: "Tap the real Generate Key entry to open the key form."),
                    target: .keysGenerateButton
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.keys.form", defaultValue: "Review the prefilled Alice identity and generate the key."),
                target: nil
            )

        case .importBobKey:
            if selectedTab != .contacts {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.contacts", defaultValue: "Open the Contacts tab to continue."),
                    target: nil
                )
            }
            if visibleRoute == nil {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.contacts.entry", defaultValue: "Tap Add Contact to import Bob's sandbox public key."),
                    target: .contactsAddButton
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.contacts.form", defaultValue: "Confirm Bob's key details and add the contact."),
                target: nil
            )

        case .composeAndEncryptMessage:
            if sizeClass == .compact {
                if selectedTab != .home {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.nav.homeEncrypt", defaultValue: "Open the Home tab to reach the Encrypt shortcut."),
                        target: nil
                    )
                }
                if visibleRoute == nil {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.home.encrypt", defaultValue: "Use the real Encrypt shortcut to open the message form."),
                        target: .homeEncryptAction
                    )
                }
            } else if selectedTab != .encrypt {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.encrypt", defaultValue: "Open Encrypt from the Tools section to continue."),
                    target: nil
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.encrypt.form", defaultValue: "Bob is preselected. Review the draft and encrypt the message."),
                target: nil
            )

        case .parseRecipients:
            if sizeClass == .compact {
                if selectedTab != .home {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.nav.homeDecrypt", defaultValue: "Open the Home tab to reach the Decrypt shortcut."),
                        target: nil
                    )
                }
                if visibleRoute == nil {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.home.decrypt", defaultValue: "Use the real Decrypt shortcut to inspect the encrypted message."),
                        target: .homeDecryptAction
                    )
                }
            } else if selectedTab != .decrypt {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.decrypt", defaultValue: "Open Decrypt from the Tools section to continue."),
                    target: nil
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.decrypt.parse", defaultValue: "Check the recipients first. The task completes once the sandbox key matches."),
                target: nil
            )

        case .decryptMessage:
            if sizeClass == .compact {
                if selectedTab != .home {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.nav.homeDecrypt", defaultValue: "Open the Home tab to reach the Decrypt shortcut."),
                        target: nil
                    )
                }
                if visibleRoute == nil {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.home.decrypt", defaultValue: "Use the real Decrypt shortcut to inspect the encrypted message."),
                        target: .homeDecryptAction
                    )
                }
            } else if selectedTab != .decrypt {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.decrypt", defaultValue: "Open Decrypt from the Tools section to continue."),
                    target: nil
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.decrypt.form", defaultValue: "Decrypt the sandbox message and review the signature result."),
                target: nil
            )

        case .exportBackup:
            if selectedTab != .keys {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.keys", defaultValue: "Open the Keys tab to continue."),
                    target: nil
                )
            }
            if visibleRoute == nil, let fingerprint = session.artifacts.aliceIdentity?.fingerprint {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.keys.alice", defaultValue: "Open Alice's key from My Keys to continue."),
                    target: .keyRow(fingerprint: fingerprint)
                )
            }
            if case .keyDetail(let fingerprint)? = visibleRoute,
               fingerprint == session.artifacts.aliceIdentity?.fingerprint {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.backup.entry", defaultValue: "Use the real Export Backup action from Alice's key detail page."),
                    target: .keyDetailBackupButton
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.backup.form", defaultValue: "Enter a passphrase and generate the sandbox backup."),
                target: nil
            )

        case .enableHighSecurity:
            if selectedTab != .settings {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.settings", defaultValue: "Open the Settings tab to continue."),
                    target: nil
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.settings.auth", defaultValue: "Switch the authentication mode to High Security and confirm the warning."),
                target: .settingsAuthModePicker
            )

        case .understandSandbox:
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.intro.body", defaultValue: "This walkthrough runs entirely in a sandbox. Your real keys, contacts, settings, files, and exports are never touched."),
                target: nil
            )
        }
    }

    private func complete(_ task: TutorialTaskID) {
        session.taskStates[task]?.isCompleted = true
        if session.hasCompletedAllTasks {
            appConfiguration?.markGuidedTutorialCompletedCurrentVersion()
        }
    }

    #if DEBUG
    func markCompletedForTesting(_ task: TutorialTaskID) {
        complete(task)
    }
    #endif

    private func recreateContainer() {
        do {
            container = try TutorialSandboxContainer()
            session = TutorialSessionState()
            selectedTab = .home
            routePath = []
            activeModal = nil
            visibleTab = .home
            visibleRoute = nil
            errorMessage = nil
        } catch {
            container = nil
            session = TutorialSessionState()
            selectedTab = .home
            routePath = []
            activeModal = nil
            visibleTab = .home
            visibleRoute = nil
            errorMessage = error.localizedDescription
        }
    }

    private func resetNavigationState(for task: TutorialTaskID) {
        selectedTab = initialSelection(for: task)
        routePath.removeAll()
        activeModal = nil
        visibleTab = selectedTab
        visibleRoute = nil
    }

    private func clearNavigationState() {
        selectedTab = .home
        routePath.removeAll()
        activeModal = nil
        visibleTab = .home
        visibleRoute = nil
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
}
