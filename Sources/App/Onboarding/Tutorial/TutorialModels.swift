import Foundation

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

struct TutorialVisibleSurface {
    var tab: AppShellTab = .home
    var route: AppRoute?
}

enum TutorialFlowPhase: Equatable {
    case overview
    case sandboxAcknowledgement
    case sandbox(task: TutorialTaskID)
    case completion
}

struct TutorialNavigationState {
    var selectedTab: AppShellTab = .home
    var pathsByTab: [AppShellTab: [AppRoute]] = Dictionary(
        uniqueKeysWithValues: AppShellTab.allCases.map { ($0, []) }
    )
    var activeModal: TutorialModal?
    var visibleSurface = TutorialVisibleSurface()
    var isInspectorPresented = true

    func path(for tab: AppShellTab) -> [AppRoute] {
        pathsByTab[tab] ?? []
    }
}

struct TutorialSessionState {
    var taskStates: [TutorialTaskID: TutorialTaskState] = Dictionary(
        uniqueKeysWithValues: TutorialTaskID.allCases.map { ($0, TutorialTaskState()) }
    )
    var artifacts = TutorialArtifacts()
    var flowPhase: TutorialFlowPhase = .overview
    var pendingCompletionPromptTask: TutorialTaskID?

    var activeTask: TutorialTaskID? {
        if case .sandbox(let task) = flowPhase {
            return task
        }
        return nil
    }

    var isShellPresented: Bool {
        if case .sandbox = flowPhase {
            return true
        }
        return false
    }

    var isShowingCompletionView: Bool {
        flowPhase == .completion
    }

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
    case authModeConfirmation(AuthModeChangeConfirmationRequest)

    var id: String {
        switch self {
        case .importConfirmation(let request):
            "import-\(request.id.uuidString)"
        case .authModeConfirmation(let request):
            "auth-\(request.id.uuidString)"
        }
    }
}
