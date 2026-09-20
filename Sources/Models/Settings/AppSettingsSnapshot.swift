import Foundation

/// Everything the app persists as a setting: one sealed domain, nothing
/// readable before the passphrase.
struct AppSettingsSnapshot: Codable, Equatable, Sendable {
    static let schemaVersion = 1
    static let validGracePeriodValues = [0, 60, 180, 300]
    static let defaultGracePeriod = 180

    var gracePeriod: Int
    var hasCompletedOnboarding: Bool
    var encryptToSelf: Bool
    var signMessages: Bool
    var hasCompletedGuidedTutorial: Bool
    var clipboardNotice: Bool

    static var firstRun: AppSettingsSnapshot {
        AppSettingsSnapshot(
            gracePeriod: defaultGracePeriod,
            hasCompletedOnboarding: false,
            encryptToSelf: true,
            signMessages: true,
            hasCompletedGuidedTutorial: false,
            clipboardNotice: true
        )
    }

    mutating func normalize() {
        if !Self.validGracePeriodValues.contains(gracePeriod) {
            gracePeriod = Self.defaultGracePeriod
        }
    }
}
