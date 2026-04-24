import Foundation

enum GuidedTutorialVersion {
    static let current = 2
}

enum GuidedTutorialCompletionState: Equatable {
    case neverCompleted
    case completedCurrentVersion
    case completedPreviousVersion
}

/// App-wide configuration stored in UserDefaults.
/// Uses the key names defined in ARCHITECTURE.md Section 5.
@Observable
final class AppConfiguration {
    private let defaults: UserDefaults

    /// Current authentication mode.
    /// Note: UserDefaults persistence is handled by AuthenticationManager.switchMode()
    /// and crash recovery — not by didSet — to ensure the write occurs only after
    /// successful SE key re-wrapping.
    var authMode: AuthenticationMode

    /// App launch/resume and App Data root-secret authentication policy.
    var appSessionAuthenticationPolicy: AppSessionAuthenticationPolicy {
        didSet {
            defaults.set(appSessionAuthenticationPolicy.rawValue, forKey: Self.appSessionAuthenticationPolicyKey)
        }
    }

    /// Grace period in seconds before re-authentication is required.
    /// Valid values: 0, 60, 180, 300.
    var gracePeriod: Int {
        didSet {
            let validValues = Self.gracePeriodOptions.map { $0.value }
            if !validValues.contains(gracePeriod) {
                gracePeriod = AuthPreferences.defaultGracePeriod
            }
            defaults.set(gracePeriod, forKey: AuthPreferences.gracePeriodKey)
        }
    }

    /// Whether to encrypt messages to self by default.
    var encryptToSelf: Bool {
        didSet {
            defaults.set(encryptToSelf, forKey: Self.encryptToSelfKey)
        }
    }

    /// Whether to require device authentication on cold launch (default true).
    var requireAuthOnLaunch: Bool {
        didSet {
            defaults.set(requireAuthOnLaunch, forKey: Self.requireAuthOnLaunchKey)
        }
    }

    /// Whether the user has completed onboarding.
    var hasCompletedOnboarding: Bool {
        didSet {
            defaults.set(hasCompletedOnboarding, forKey: Self.onboardingCompleteKey)
        }
    }

    /// The latest Guided Tutorial version the user has completed.
    var guidedTutorialCompletedVersion: Int {
        didSet {
            defaults.set(guidedTutorialCompletedVersion, forKey: Self.guidedTutorialCompletedVersionKey)
        }
    }

    /// The selected color theme preset.
    var colorTheme: ColorTheme {
        didSet {
            defaults.set(colorTheme.rawValue, forKey: Self.colorThemeKey)
        }
    }

    /// Incremented when decrypted content should be cleared (e.g., grace period expired).
    var contentClearGeneration: Int = 0

    /// Request that views holding decrypted content clear it.
    func requestContentClear() {
        contentClearGeneration += 1
    }

    /// Timestamp of last successful authentication, for grace period calculation.
    var lastAuthenticationDate: Date?

    // MARK: - UserDefaults Keys

    static let encryptToSelfKey = "com.cypherair.preference.encryptToSelf"
    static let clipboardNoticeLegacyKey = "com.cypherair.preference.clipboardNotice"
    static let appSessionAuthenticationPolicyKey = "com.cypherair.preference.appSessionAuthenticationPolicy"
    private static let requireAuthOnLaunchKey = "com.cypherair.preference.requireAuthOnLaunch"
    private static let onboardingCompleteKey = "com.cypherair.preference.onboardingComplete"
    private static let guidedTutorialCompletedVersionKey = "com.cypherair.preference.guidedTutorialCompletedVersion"
    private static let colorThemeKey = "com.cypherair.preference.colorTheme"

    // MARK: - Initialization

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults

        // Auth mode
        let modeString = defaults.string(forKey: AuthPreferences.authModeKey) ?? AuthenticationMode.standard.rawValue
        self.authMode = AuthenticationMode(rawValue: modeString) ?? .standard

        let appSessionPolicyString = defaults.string(forKey: Self.appSessionAuthenticationPolicyKey)
            ?? AppSessionAuthenticationPolicy.userPresence.rawValue
        self.appSessionAuthenticationPolicy = AppSessionAuthenticationPolicy(rawValue: appSessionPolicyString)
            ?? .userPresence

        // Grace period (default 180s = 3 minutes)
        let storedGrace = defaults.object(forKey: AuthPreferences.gracePeriodKey) as? Int
        self.gracePeriod = storedGrace ?? AuthPreferences.defaultGracePeriod

        // Encrypt to self (default true)
        if defaults.object(forKey: Self.encryptToSelfKey) != nil {
            self.encryptToSelf = defaults.bool(forKey: Self.encryptToSelfKey)
        } else {
            self.encryptToSelf = true
        }

        // Require auth on launch (default true)
        if defaults.object(forKey: Self.requireAuthOnLaunchKey) != nil {
            self.requireAuthOnLaunch = defaults.bool(forKey: Self.requireAuthOnLaunchKey)
        } else {
            self.requireAuthOnLaunch = true
        }

        // Onboarding
        self.hasCompletedOnboarding = defaults.bool(forKey: Self.onboardingCompleteKey)

        // Guided Tutorial completion
        self.guidedTutorialCompletedVersion = defaults.integer(forKey: Self.guidedTutorialCompletedVersionKey)

        // Color theme (default: system accent — no tint override)
        if let themeRaw = defaults.string(forKey: Self.colorThemeKey),
           let theme = ColorTheme(rawValue: themeRaw) {
            self.colorTheme = theme
        } else {
            self.colorTheme = .systemDefault
        }
    }

    /// Check if the grace period has expired since last authentication.
    var isGracePeriodExpired: Bool {
        guard let lastAuth = lastAuthenticationDate else { return true }
        return Date().timeIntervalSince(lastAuth) > TimeInterval(gracePeriod)
    }

    /// Record a successful authentication.
    func recordAuthentication() {
        lastAuthenticationDate = Date()
    }

    var guidedTutorialCompletionState: GuidedTutorialCompletionState {
        if guidedTutorialCompletedVersion >= GuidedTutorialVersion.current {
            return .completedCurrentVersion
        }
        if guidedTutorialCompletedVersion > 0 {
            return .completedPreviousVersion
        }
        return .neverCompleted
    }

    var hasCompletedCurrentGuidedTutorialVersion: Bool {
        guidedTutorialCompletionState == .completedCurrentVersion
    }

    var hasCompletedPreviousGuidedTutorialVersion: Bool {
        guidedTutorialCompletionState == .completedPreviousVersion
    }

    var hasNeverCompletedGuidedTutorial: Bool {
        guidedTutorialCompletionState == .neverCompleted
    }

    func markGuidedTutorialCompletedCurrentVersion() {
        guidedTutorialCompletedVersion = GuidedTutorialVersion.current
    }

    /// Available grace period options (in seconds).
    static let gracePeriodOptions: [(label: String, value: Int)] = [
        (String(localized: "grace.immediately", defaultValue: "Immediately"), 0),
        (String(localized: "grace.1min", defaultValue: "1 minute"), 60),
        (String(localized: "grace.3min", defaultValue: "3 minutes"), 180),
        (String(localized: "grace.5min", defaultValue: "5 minutes"), 300)
    ]
}
