import Foundation
#if canImport(XCTest) && canImport(CypherAir)
@testable import CypherAir
#endif

enum TutorialLayerID: String, CaseIterable, Hashable, Codable {
    case core
    case advanced
}

enum TutorialLaunchOrigin: String, Hashable, Codable {
    case onboardingFirstRun
    case inApp
}

enum TutorialModuleID: String, CaseIterable, Identifiable, Codable, Hashable {
    case sandbox
    case demoIdentity
    case demoContact
    case encryptMessage
    case decryptAndVerify
    case backupKey
    case enableHighSecurity

    var id: String { rawValue }

    var layer: TutorialLayerID {
        switch self {
        case .sandbox, .demoIdentity, .demoContact, .encryptMessage, .decryptAndVerify:
            .core
        case .backupKey, .enableHighSecurity:
            .advanced
        }
    }

    var title: String {
        switch self {
        case .sandbox:
            String(localized: "tutorial.module.sandbox.title", defaultValue: "Understand the Tutorial Sandbox")
        case .demoIdentity:
            String(localized: "tutorial.module.identity.title", defaultValue: "Create a Demo Identity")
        case .demoContact:
            String(localized: "tutorial.module.contact.title", defaultValue: "Add a Demo Contact")
        case .encryptMessage:
            String(localized: "tutorial.module.encrypt.title", defaultValue: "Encrypt a Demo Message")
        case .decryptAndVerify:
            String(localized: "tutorial.module.decrypt.title", defaultValue: "Decrypt and Verify")
        case .backupKey:
            String(localized: "tutorial.module.backup.title", defaultValue: "Back Up a Key")
        case .enableHighSecurity:
            String(localized: "tutorial.module.highSecurity.title", defaultValue: "Enable High Security")
        }
    }

    var summary: String {
        switch self {
        case .sandbox:
            String(localized: "tutorial.module.sandbox.summary", defaultValue: "Learn what the tutorial can and cannot touch before you start.")
        case .demoIdentity:
            String(localized: "tutorial.module.identity.summary", defaultValue: "Generate the demo key that represents you inside this tutorial.")
        case .demoContact:
            String(localized: "tutorial.module.contact.summary", defaultValue: "Add the demo contact whose public key you will encrypt to.")
        case .encryptMessage:
            String(localized: "tutorial.module.encrypt.summary", defaultValue: "Write a message, choose the demo contact, and produce protected output.")
        case .decryptAndVerify:
            String(localized: "tutorial.module.decrypt.summary", defaultValue: "Inspect who the message is for, then decrypt and review the signature result.")
        case .backupKey:
            String(localized: "tutorial.module.backup.summary", defaultValue: "Practice creating a protected key backup without exporting a real file.")
        case .enableHighSecurity:
            String(localized: "tutorial.module.highSecurity.summary", defaultValue: "Learn what High Security mode changes and why backup matters first.")
        }
    }

    var realAppLocationLabel: String {
        switch self {
        case .sandbox:
            String(localized: "tutorial.location.hub", defaultValue: "Tutorial Hub")
        case .demoIdentity, .backupKey:
            String(localized: "tutorial.location.keys", defaultValue: "Keys")
        case .demoContact:
            String(localized: "tutorial.location.contacts", defaultValue: "Contacts")
        case .encryptMessage:
            String(localized: "tutorial.location.encrypt", defaultValue: "Encrypt")
        case .decryptAndVerify:
            String(localized: "tutorial.location.decrypt", defaultValue: "Decrypt")
        case .enableHighSecurity:
            String(localized: "tutorial.location.settings", defaultValue: "Settings")
        }
    }

    var mappingNote: String {
        switch self {
        case .sandbox:
            String(localized: "tutorial.mapping.sandbox", defaultValue: "In the real app, you will work with your own keys and messages, not this demo workspace.")
        case .demoIdentity:
            String(localized: "tutorial.mapping.identity", defaultValue: "In the real app, you create your own key from the Keys area when you are ready.")
        case .demoContact:
            String(localized: "tutorial.mapping.contact", defaultValue: "In the real app, Contacts stores the public keys you encrypt to.")
        case .encryptMessage:
            String(localized: "tutorial.mapping.encrypt", defaultValue: "In the real app, Encrypt creates the protected output you send to other people.")
        case .decryptAndVerify:
            String(localized: "tutorial.mapping.decrypt", defaultValue: "In the real app, Decrypt first identifies the matching key and then unlocks the message.")
        case .backupKey:
            String(localized: "tutorial.mapping.backup", defaultValue: "In the real app, backup exports a passphrase-protected file outside tutorial mode.")
        case .enableHighSecurity:
            String(localized: "tutorial.mapping.highSecurity", defaultValue: "In the real app, High Security removes passcode fallback and requires biometric-only confirmation.")
        }
    }

    var prerequisiteModules: [TutorialModuleID] {
        switch self {
        case .enableHighSecurity:
            [.backupKey]
        default:
            []
        }
    }

    static var coreModules: [TutorialModuleID] {
        allCases.filter { $0.layer == .core }
    }

    static var advancedModules: [TutorialModuleID] {
        allCases.filter { $0.layer == .advanced }
    }
}

enum TutorialLifecycleState: Equatable {
    case notStarted
    case coreInProgress
    case coreStepsCompleted
    case coreFinished
    case moduleInProgress(TutorialModuleID)
    case moduleCompleted(TutorialModuleID)
}

struct TutorialSessionID: Hashable, Codable {
    let rawValue: String

    init() {
        self.rawValue = UUID().uuidString
    }
}

struct TutorialModalGuidance: Equatable {
    let whyThisExists: String
    let expectedAction: String
    let nextStep: String
}

struct TutorialGuidancePayload: Equatable {
    let module: TutorialModuleID
    let title: String
    let goal: String
    let realAppLocationLabel: String
    let detail: String
    let target: TutorialAnchorID?
    let modalGuidance: TutorialModalGuidance?
}

enum TutorialCompletionKind: Equatable {
    case core
    case module(TutorialModuleID)
}

enum TutorialSurface: Equatable {
    case hub
    case workspace(TutorialModuleID)
    case completion(TutorialCompletionKind)
}

struct TutorialCapabilityPolicy {
    enum Capability: String, CaseIterable {
        case fileImport
        case fileExport
        case photoPickerImport
        case shareSheetExport
        case clipboardWrite
        case urlHandoff
        case realSettingsMutation
        case realAuthenticationPrompt
    }

    func allows(_ capability: Capability) -> Bool {
        switch capability {
        case .fileImport,
             .fileExport,
             .photoPickerImport,
             .shareSheetExport,
             .clipboardWrite,
             .urlHandoff,
             .realSettingsMutation,
             .realAuthenticationPrompt:
            false
        }
    }
}

enum TutorialAutomationContract {
    enum Ready {
        static let onboardingPageOne = "onboarding.page1.ready"
        static let onboardingPageTwo = "onboarding.page2.ready"
        static let onboardingPageThree = "onboarding.page3.ready"
        static let hub = "tutorial.hub.ready"
        static let sandbox = "tutorial.module.sandbox.ready"
        static let demoIdentity = "tutorial.module.identity.ready"
        static let demoContact = "tutorial.module.contact.ready"
        static let encrypt = "tutorial.module.encrypt.ready"
        static let decrypt = "tutorial.module.decrypt.ready"
        static let backup = "tutorial.module.backup.ready"
        static let highSecurity = "tutorial.module.highSecurity.ready"
        static let coreCompletion = "tutorial.completion.core.ready"
        static let moduleCompletion = "tutorial.completion.module.ready"
        static let leaveConfirmation = "tutorial.leave.ready"
        static let authModal = "tutorial.modal.auth.ready"
    }

    enum Identifier {
        static let onboardingStartTutorial = "onboarding.startTutorial"
        static let onboardingSkipTutorial = "onboarding.skipTutorial"
        static let hubPrimaryAction = "tutorial.hub.primary"
        static let hubReplayCore = "tutorial.hub.replayCore"
        static let hubModuleButtonPrefix = "tutorial.hub.module."
        static let returnButton = "tutorial.return"
        static let closeButton = "tutorial.close"
        static let finishButton = "tutorial.finish"
        static let exploreAdvancedButton = "tutorial.exploreAdvanced"
        static let primaryAction = "tutorial.primaryAction"
        static let secondaryAction = "tutorial.secondaryAction"
        static let leaveContinue = "tutorial.leave.continue"
        static let leaveConfirm = "tutorial.leave.confirm"
        static let modalConfirm = "tutorial.modal.confirm"
        static let modalCancel = "tutorial.modal.cancel"
        static let guidanceRestore = "tutorial.guidance.restore"
    }
}

extension AppConfiguration {
    var completedGuidedTutorialModulesCurrentVersion: Set<TutorialModuleID> {
        guard guidedTutorialCompletedModulesVersion == GuidedTutorialVersion.current else {
            return []
        }
        return Set(guidedTutorialCompletedModules.compactMap(TutorialModuleID.init(rawValue:)))
    }
}
