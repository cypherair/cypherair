import Foundation

struct ProtectedOrdinarySettingsSnapshot: Equatable, Sendable {
    var gracePeriod: Int
    var hasCompletedOnboarding: Bool
    var colorTheme: ColorTheme
    var encryptToSelf: Bool
    var guidedTutorialCompletedVersion: Int

    static var firstRunDefaults: ProtectedOrdinarySettingsSnapshot {
        ProtectedOrdinarySettingsSnapshot(
            gracePeriod: AuthPreferences.defaultGracePeriod,
            hasCompletedOnboarding: false,
            colorTheme: .systemDefault,
            encryptToSelf: true,
            guidedTutorialCompletedVersion: 0
        )
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

    mutating func normalize() {
        if !Self.validGracePeriodValues.contains(gracePeriod) {
            gracePeriod = AuthPreferences.defaultGracePeriod
        }
        if guidedTutorialCompletedVersion < 0 {
            guidedTutorialCompletedVersion = 0
        }
    }

    static var validGracePeriodValues: Set<Int> {
        Set(AppConfiguration.gracePeriodOptions.map(\.value))
    }
}
