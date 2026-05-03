import Foundation

struct AppLaunchConfiguration {
    enum Root: String {
        case main
        case settings
        case tutorial
    }

    let root: Root
    let shouldSkipOnboarding: Bool
    let tutorialModule: TutorialModuleID?
    let isUITestMode: Bool
    let isXCTestHost: Bool
    let requiresManualAuthentication: Bool
    let opensAuthModeConfirmation: Bool
    let preloadsUITestContact: Bool
    let isAuthTraceEnabled: Bool

    init(processInfo: ProcessInfo = .processInfo) {
        let environment = processInfo.environment
        self.root = Root(rawValue: environment["UITEST_ROOT"] ?? "main") ?? .main
        self.isUITestMode = environment["UITEST_ROOT"] != nil || environment["UITEST_SKIP_ONBOARDING"] != nil
        self.isXCTestHost = Self.detectXCTestHost(processInfo: processInfo)
        self.requiresManualAuthentication = environment["UITEST_REQUIRE_MANUAL_AUTH"] == "1"
        self.opensAuthModeConfirmation = environment["UITEST_OPEN_AUTHMODE_CONFIRMATION"] == "1"
        self.preloadsUITestContact = environment["UITEST_PRELOAD_CONTACT"] == "1"
        self.isAuthTraceEnabled = environment["CYPHERAIR_DEBUG_AUTH_TRACE"] == "1"
        self.shouldSkipOnboarding = environment["UITEST_SKIP_ONBOARDING"] == "1" || root != .main
        self.tutorialModule = environment["UITEST_TUTORIAL_TASK"].flatMap { value in
            switch value {
            case "understandSandbox", "sandbox": .sandbox
            case "generateAliceKey", "createDemoIdentity": .createDemoIdentity
            case "importBobKey", "addDemoContact": .addDemoContact
            case "composeAndEncryptMessage", "encryptDemoMessage": .encryptDemoMessage
            case "parseRecipients", "decryptMessage", "decryptAndVerify": .decryptAndVerify
            case "exportBackup", "backupKey": .backupKey
            case "enableHighSecurity": .enableHighSecurity
            default: nil
            }
        }
    }

    private static func detectXCTestHost(processInfo: ProcessInfo) -> Bool {
        if processInfo.environment["XCTestConfigurationFilePath"] != nil {
            return true
        }
        return Bundle.allBundles.contains { bundle in
            bundle.bundlePath.hasSuffix(".xctest")
        }
    }
}
