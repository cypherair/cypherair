import Foundation
import SwiftUI

enum TutorialModuleID: Int, CaseIterable, Hashable, Identifiable {
    case sandbox
    case createDemoIdentity
    case addDemoContact
    case encryptDemoMessage
    case decryptAndVerify
    case backupKey
    case enableHighSecurity

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .sandbox:
            String(localized: "guidedTutorial.module.sandbox", defaultValue: "Understand the Sandbox")
        case .createDemoIdentity:
            String(localized: "guidedTutorial.module.identity", defaultValue: "Create a Demo Identity")
        case .addDemoContact:
            String(localized: "guidedTutorial.module.contact", defaultValue: "Add a Demo Contact")
        case .encryptDemoMessage:
            String(localized: "guidedTutorial.module.encrypt", defaultValue: "Encrypt a Demo Message")
        case .decryptAndVerify:
            String(localized: "guidedTutorial.module.decrypt", defaultValue: "Decrypt and Verify")
        case .backupKey:
            String(localized: "guidedTutorial.module.backup", defaultValue: "Back Up a Key")
        case .enableHighSecurity:
            String(localized: "guidedTutorial.module.highSecurity", defaultValue: "Enable High Security")
        }
    }

    var realAppLocation: String? {
        switch self {
        case .sandbox:
            nil
        case .createDemoIdentity, .backupKey:
            String(localized: "guidedTutorial.location.keys", defaultValue: "Keys")
        case .addDemoContact:
            String(localized: "guidedTutorial.location.contacts", defaultValue: "Contacts")
        case .encryptDemoMessage:
            String(localized: "guidedTutorial.location.encrypt", defaultValue: "Encrypt")
        case .decryptAndVerify:
            String(localized: "guidedTutorial.location.decrypt", defaultValue: "Decrypt")
        case .enableHighSecurity:
            String(localized: "guidedTutorial.location.settings", defaultValue: "Settings")
        }
    }

    var detail: String {
        switch self {
        case .sandbox:
            String(localized: "guidedTutorial.module.sandbox.detail", defaultValue: "Confirm that tutorial data is isolated from your real workspace.")
        case .createDemoIdentity:
            String(localized: "guidedTutorial.module.identity.detail", defaultValue: "Generate a sandbox key through the real key-generation flow.")
        case .addDemoContact:
            String(localized: "guidedTutorial.module.contact.detail", defaultValue: "Import Bob's demo public key into sandbox contacts.")
        case .encryptDemoMessage:
            String(localized: "guidedTutorial.module.encrypt.detail", defaultValue: "Use the real encrypt page to protect a demo message.")
        case .decryptAndVerify:
            String(localized: "guidedTutorial.module.decrypt.detail", defaultValue: "Check recipients, authenticate, and verify the signed message.")
        case .backupKey:
            String(localized: "guidedTutorial.module.backup.detail", defaultValue: "Create a passphrase-protected backup artifact inside the sandbox.")
        case .enableHighSecurity:
            String(localized: "guidedTutorial.module.highSecurity.detail", defaultValue: "Practice switching auth mode after backing up the sandbox key.")
        }
    }

    var tab: AppShellTab {
        switch self {
        case .sandbox, .encryptDemoMessage, .decryptAndVerify:
            .home
        case .createDemoIdentity, .backupKey:
            .keys
        case .addDemoContact:
            .contacts
        case .enableHighSecurity:
            .settings
        }
    }

    var readyMarker: String {
        TutorialAutomationContract.moduleReadyMarker(self)
    }

    var launchControlIdentifier: String {
        TutorialAutomationContract.moduleLaunchIdentifier(self)
    }
}

enum TutorialLifecycleState: Equatable {
    case notStarted
    case inProgress
    case stepsCompleted
    case finished
}

enum TutorialLaunchOrigin: Equatable {
    case onboardingFirstRun
    case inApp
}

typealias TutorialPresentationContext = TutorialLaunchOrigin

struct TutorialSessionID: Hashable {
    let rawValue: UUID

    init(rawValue: UUID = UUID()) {
        self.rawValue = rawValue
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

struct TutorialModuleState {
    var isCompleted = false
}

struct TutorialVisibleSurface {
    var tab: AppShellTab = .home
    var route: AppRoute?
}

enum TutorialHostSurface: Equatable {
    case hub
    case sandboxAcknowledgement
    case workspace(module: TutorialModuleID)
    case completion
}

struct TutorialBlockedSurface {
    let title: String
    let message: String
    let systemImage: String
}

struct TutorialUnsafeRouteBlocklist {
    func blockedRoute(for route: AppRoute) -> TutorialBlockedSurface? {
        switch route {
        case .importKey:
            TutorialBlockedSurface(
                title: String(localized: "guidedTutorial.blocked.importKey.title", defaultValue: "Private Key Import Unavailable"),
                message: String(localized: "guidedTutorial.blocked.importKey.body", defaultValue: "Importing a real private key is disabled in the tutorial sandbox."),
                systemImage: "key.badge.exclamationmark"
            )
        case .qrPhotoImport:
            TutorialBlockedSurface(
                title: String(localized: "guidedTutorial.blocked.photo.title", defaultValue: "Photo Import Unavailable"),
                message: String(localized: "guidedTutorial.blocked.photo.body", defaultValue: "The tutorial does not use the photo picker. Use the sandbox sample flow instead."),
                systemImage: "photo.badge.exclamationmark"
            )
        case .selfTest:
            TutorialBlockedSurface(
                title: String(localized: "guidedTutorial.blocked.selfTest.title", defaultValue: "Self-Test Unavailable"),
                message: String(localized: "guidedTutorial.blocked.selfTest.body", defaultValue: "Self-Test is outside the guided tutorial path and is not available in the sandbox workspace."),
                systemImage: "checkmark.circle.trianglebadge.exclamationmark"
            )
        case .appIcon:
            TutorialBlockedSurface(
                title: String(localized: "guidedTutorial.blocked.appIcon.title", defaultValue: "App Icon Unavailable"),
                message: String(localized: "guidedTutorial.blocked.appIcon.body", defaultValue: "App icon changes affect the real app and are unavailable inside the tutorial sandbox."),
                systemImage: "app.badge"
            )
        default:
            nil
        }
    }

    func blockedRoot(for tab: AppShellTab) -> TutorialBlockedSurface? {
        switch tab {
        case .sign:
            TutorialBlockedSurface(
                title: String(localized: "guidedTutorial.blocked.sign.title", defaultValue: "Sign Unavailable"),
                message: String(localized: "guidedTutorial.blocked.sign.body", defaultValue: "Signing is outside the guided tutorial path and is hidden to keep the sandbox focused."),
                systemImage: "signature"
            )
        case .verify:
            TutorialBlockedSurface(
                title: String(localized: "guidedTutorial.blocked.verify.title", defaultValue: "Verify Unavailable"),
                message: String(localized: "guidedTutorial.blocked.verify.body", defaultValue: "Verification outside the decrypt lesson is hidden to keep the tutorial focused."),
                systemImage: "checkmark.seal"
            )
        default:
            nil
        }
    }
}

enum TutorialExportKind {
    case ciphertext
    case publicKey
    case revocation
    case backup
    case generic
}

struct TutorialSideEffectInterceptor {
    var interceptClipboardWrite: (@MainActor (String, AppConfiguration) -> Bool)?
    var interceptDataExport: (@MainActor (Data, String, TutorialExportKind) throws -> Bool)?
    var interceptFileExport: (@MainActor (URL, String, TutorialExportKind) -> Bool)?

    static let passthrough = TutorialSideEffectInterceptor()
}

struct TutorialSurfaceConfiguration {
    let activeModule: TutorialModuleID?
    let blocklist: TutorialUnsafeRouteBlocklist
    let sideEffectInterceptor: TutorialSideEffectInterceptor
}

struct TutorialSecuritySimulationStack {
    let authManager: AuthenticationManager
    let mockSecureEnclave: MockSecureEnclave
    let mockKeychain: MockKeychain
    let mockAuthenticator: MockAuthenticator
}

enum TutorialAutomationContract {
    static let hubReadyMarker = "tutorial.hub.ready"
    static let sandboxAcknowledgementReadyMarker = "tutorial.sandbox.ready"
    static let completionReadyMarker = "tutorial.completion.ready"
    static let leaveConfirmationReadyMarker = "tutorial.leave.ready"

    static func moduleReadyMarker(_ module: TutorialModuleID) -> String {
        "tutorial.module.\(module.rawValue).ready"
    }

    static func moduleLaunchIdentifier(_ module: TutorialModuleID) -> String {
        "tutorial.module.\(module.rawValue).open"
    }
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
    var specVersion = GuidedTutorialVersion.current
    var launchOrigin: TutorialLaunchOrigin = .inApp
    var lifecycleState: TutorialLifecycleState = .notStarted
    var sessionID: TutorialSessionID?
    var moduleStates: [TutorialModuleID: TutorialModuleState] = Dictionary(
        uniqueKeysWithValues: TutorialModuleID.allCases.map { ($0, TutorialModuleState()) }
    )
    var artifacts = TutorialArtifacts()
    var surface: TutorialHostSurface = .hub
    var pendingCompletionPromptModule: TutorialModuleID?
    var currentGuidance: TutorialGuidancePayload?

    var activeModule: TutorialModuleID? {
        if case .workspace(let module) = surface {
            return module
        }
        return nil
    }

    var isWorkspacePresented: Bool {
        if case .workspace = surface {
            return true
        }
        return false
    }

    var hasStartedSession: Bool {
        sessionID != nil
    }

    var completedCount: Int {
        moduleStates.values.filter(\.isCompleted).count
    }

    var progressValue: Double {
        Double(completedCount) / Double(TutorialModuleID.allCases.count)
    }

    var nextIncompleteModule: TutorialModuleID? {
        TutorialModuleID.allCases.first { moduleStates[$0]?.isCompleted != true }
    }

    var hasCompletedAllModules: Bool {
        nextIncompleteModule == nil
    }
}

struct TutorialGuidancePayload {
    let module: TutorialModuleID
    let title: String
    let body: String
    let realAppLocation: String?
    let target: TutorialAnchorID?
}

struct TutorialLeaveConfirmationRequest: Identifiable {
    let id = UUID()
    let onContinue: @MainActor () -> Void
    let onLeave: @MainActor () -> Void
}

enum TutorialModal: Identifiable {
    case importConfirmation(ImportConfirmationRequest)
    case authModeConfirmation(AuthModeChangeConfirmationRequest)
    case leaveConfirmation(TutorialLeaveConfirmationRequest)

    var id: String {
        switch self {
        case .importConfirmation(let request):
            "import-\(request.id.uuidString)"
        case .authModeConfirmation(let request):
            "auth-\(request.id.uuidString)"
        case .leaveConfirmation(let request):
            "leave-\(request.id.uuidString)"
        }
    }
}

private struct TutorialSideEffectInterceptorKey: EnvironmentKey {
    static let defaultValue: TutorialSideEffectInterceptor? = nil
}

extension EnvironmentValues {
    var tutorialSideEffectInterceptor: TutorialSideEffectInterceptor? {
        get { self[TutorialSideEffectInterceptorKey.self] }
        set { self[TutorialSideEffectInterceptorKey.self] = newValue }
    }
}
