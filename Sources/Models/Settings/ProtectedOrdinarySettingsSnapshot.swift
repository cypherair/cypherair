import Foundation

struct ProtectedOrdinarySettingsSnapshot: Codable, Equatable, Sendable {
    var gracePeriod: Int
    var hasCompletedOnboarding: Bool
    var encryptToSelf: Bool
    var hasCompletedGuidedTutorial: Bool

    static var firstRunDefaults: ProtectedOrdinarySettingsSnapshot {
        ProtectedOrdinarySettingsSnapshot(
            gracePeriod: AuthPreferences.defaultGracePeriod,
            hasCompletedOnboarding: false,
            encryptToSelf: true,
            hasCompletedGuidedTutorial: false
        )
    }

    mutating func normalize() {
        if !Self.validGracePeriodValues.contains(gracePeriod) {
            gracePeriod = AuthPreferences.defaultGracePeriod
        }
    }

    static var validGracePeriodValues: Set<Int> {
        Set(AppConfiguration.validGracePeriodValues)
    }
}
