import Foundation

struct AppLaunchConfiguration {
    enum Root: String {
        case main
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

    var usesUITestAppContainer: Bool {
        isUITestMode || isXCTestHost
    }

    init(
        processInfo: ProcessInfo = .processInfo,
        allowsUITestLaunchOverrides: Bool = Self.defaultAllowsUITestLaunchOverrides
    ) {
        let environment = processInfo.environment
        self.init(
            environment: environment,
            detectsXCTestHost: Self.detectXCTestHost(processInfo: processInfo),
            allowsUITestLaunchOverrides: allowsUITestLaunchOverrides
        )
    }

    init(
        environment: [String: String],
        detectsXCTestHost: Bool = false,
        allowsUITestLaunchOverrides: Bool = Self.defaultAllowsUITestLaunchOverrides
    ) {
        self.isAuthTraceEnabled = environment["CYPHERAIR_DEBUG_AUTH_TRACE"] == "1"

        guard allowsUITestLaunchOverrides else {
            self.root = .main
            self.isUITestMode = false
            self.isXCTestHost = false
            self.requiresManualAuthentication = false
            self.opensAuthModeConfirmation = false
            self.preloadsUITestContact = false
            self.shouldSkipOnboarding = false
            self.tutorialModule = nil
            return
        }

        self.root = Root(rawValue: environment["UITEST_ROOT"] ?? "main") ?? .main
        self.isUITestMode = environment["UITEST_ROOT"] != nil || environment["UITEST_SKIP_ONBOARDING"] != nil
        self.isXCTestHost = detectsXCTestHost
        self.requiresManualAuthentication = environment["UITEST_REQUIRE_MANUAL_AUTH"] == "1"
        self.opensAuthModeConfirmation = environment["UITEST_OPEN_AUTHMODE_CONFIRMATION"] == "1"
        self.preloadsUITestContact = environment["UITEST_PRELOAD_CONTACT"] == "1"
        self.shouldSkipOnboarding = environment["UITEST_SKIP_ONBOARDING"] == "1" || root != .main
        self.tutorialModule = environment["UITEST_TUTORIAL_TASK"].flatMap(Self.tutorialModule(for:))
    }

    private static func detectXCTestHost(processInfo: ProcessInfo) -> Bool {
        if processInfo.environment["XCTestConfigurationFilePath"] != nil {
            return true
        }
        return Bundle.allBundles.contains { bundle in
            bundle.bundlePath.hasSuffix(".xctest")
        }
    }

    private static var defaultAllowsUITestLaunchOverrides: Bool {
        #if DEBUG
        true
        #else
        false
        #endif
    }

    private static func tutorialModule(for value: String) -> TutorialModuleID? {
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
