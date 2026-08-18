import Foundation

struct AppLaunchConfiguration {
    enum Root: String {
        case main
        case tutorial
    }

    /// UI-test choreography that stages a specific tutorial surface at launch.
    /// Parsed here — behind the same Release kill switch as every other
    /// launch override — and handed to `TutorialView`, which asks the session
    /// store to perform it.
    enum TutorialChoreography {
        case completionSurface
        case authModeConfirmation
        case contactDetailSurface
    }

    let root: Root
    let shouldSkipOnboarding: Bool
    let tutorialModule: TutorialModuleID?
    let tutorialChoreography: TutorialChoreography?
    let isUITestMode: Bool
    let isXCTestHost: Bool
    let requiresManualAuthentication: Bool
    /// Manual-auth UI-test variant that boots pre-authenticated (lock armed,
    /// auth bypass off) so UI tests can drive a real lock transition without a
    /// human biometric at launch. Meaningful only with
    /// `requiresManualAuthentication`; the derivation enforces that pairing.
    let manualAuthStartsUnlocked: Bool
    let opensAuthModeConfirmation: Bool
    let preloadsUITestContact: Bool

    var usesUITestAppContainer: Bool {
        isUITestMode || isXCTestHost
    }

    /// The UI-test container boots with the app session already authenticated
    /// and the lock armed: either nothing asked for a manual unlock, or the
    /// manual-auth variant asked to start unlocked so a UI test can drive a
    /// real lock transition without a human biometric at launch.
    var bootsPreAuthenticated: Bool {
        usesUITestAppContainer && (!requiresManualAuthentication || manualAuthStartsUnlocked)
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
        guard allowsUITestLaunchOverrides else {
            self.root = .main
            self.isUITestMode = false
            self.isXCTestHost = false
            self.requiresManualAuthentication = false
            self.manualAuthStartsUnlocked = false
            self.opensAuthModeConfirmation = false
            self.preloadsUITestContact = false
            self.shouldSkipOnboarding = false
            self.tutorialModule = nil
            self.tutorialChoreography = nil
            return
        }

        self.root = Root(rawValue: environment["UITEST_ROOT"] ?? "main") ?? .main
        self.isUITestMode = environment["UITEST_ROOT"] != nil || environment["UITEST_SKIP_ONBOARDING"] != nil
        self.isXCTestHost = detectsXCTestHost
        let requiresManualAuthentication = environment["UITEST_REQUIRE_MANUAL_AUTH"] == "1"
        self.requiresManualAuthentication = requiresManualAuthentication
        self.manualAuthStartsUnlocked = requiresManualAuthentication
            && environment["UITEST_MANUAL_AUTH_STARTS_UNLOCKED"] == "1"
        self.opensAuthModeConfirmation = environment["UITEST_OPEN_AUTHMODE_CONFIRMATION"] == "1"
        self.preloadsUITestContact = environment["UITEST_PRELOAD_CONTACT"] == "1"
        self.shouldSkipOnboarding = environment["UITEST_SKIP_ONBOARDING"] == "1" || root != .main
        self.tutorialModule = environment["UITEST_TUTORIAL_TASK"].flatMap(Self.tutorialModule(for:))
        self.tutorialChoreography = Self.tutorialChoreography(for: environment)
    }

    private static func tutorialChoreography(
        for environment: [String: String]
    ) -> TutorialChoreography? {
        if environment["UITEST_TUTORIAL_COMPLETION"] == "1" {
            return .completionSurface
        }
        if environment["UITEST_TUTORIAL_AUTHMODE_CONFIRMATION"] == "1" {
            return .authModeConfirmation
        }
        if environment["UITEST_TUTORIAL_CONTACT_DETAIL"] == "1" {
            return .contactDetailSurface
        }
        return nil
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
        case "createDemoIdentity": .createDemoIdentity
        case "addDemoContact": .addDemoContact
        case "enableHighSecurity": .enableHighSecurity
        default: nil
        }
    }
}
