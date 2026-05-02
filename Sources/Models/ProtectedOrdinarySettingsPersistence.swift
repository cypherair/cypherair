import Foundation

protocol ProtectedOrdinarySettingsPersistence {
    func loadSnapshot() throws -> ProtectedOrdinarySettingsSnapshot
    func saveSnapshot(_ snapshot: ProtectedOrdinarySettingsSnapshot) throws
    func removePersistentValues()
}

enum ProtectedOrdinarySettingsLegacyKeys {
    static let gracePeriod = AuthPreferences.gracePeriodKey
    static let encryptToSelf = "com.cypherair.preference.encryptToSelf"
    static let onboardingComplete = "com.cypherair.preference.onboardingComplete"
    static let guidedTutorialCompletedVersion = "com.cypherair.preference.guidedTutorialCompletedVersion"
    static let colorTheme = "com.cypherair.preference.colorTheme"
}

final class LegacyOrdinarySettingsStore: ProtectedOrdinarySettingsPersistence {
    private let defaults: UserDefaults

    init(defaults: UserDefaults) {
        self.defaults = defaults
    }

    func loadSnapshot() -> ProtectedOrdinarySettingsSnapshot {
        let storedGracePeriod = defaults.object(
            forKey: ProtectedOrdinarySettingsLegacyKeys.gracePeriod
        ) as? Int
        let gracePeriod = storedGracePeriod ?? AuthPreferences.defaultGracePeriod

        let encryptToSelf: Bool
        if defaults.object(forKey: ProtectedOrdinarySettingsLegacyKeys.encryptToSelf) != nil {
            encryptToSelf = defaults.bool(forKey: ProtectedOrdinarySettingsLegacyKeys.encryptToSelf)
        } else {
            encryptToSelf = true
        }

        let colorTheme: ColorTheme
        if let rawTheme = defaults.string(forKey: ProtectedOrdinarySettingsLegacyKeys.colorTheme),
           let storedTheme = ColorTheme(rawValue: rawTheme) {
            colorTheme = storedTheme
        } else {
            colorTheme = .systemDefault
        }

        var snapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: gracePeriod,
            hasCompletedOnboarding: defaults.bool(
                forKey: ProtectedOrdinarySettingsLegacyKeys.onboardingComplete
            ),
            colorTheme: colorTheme,
            encryptToSelf: encryptToSelf,
            guidedTutorialCompletedVersion: defaults.integer(
                forKey: ProtectedOrdinarySettingsLegacyKeys.guidedTutorialCompletedVersion
            )
        )
        snapshot.normalize()
        return snapshot
    }

    func saveSnapshot(_ snapshot: ProtectedOrdinarySettingsSnapshot) {
        var normalized = snapshot
        normalized.normalize()
        defaults.set(normalized.gracePeriod, forKey: ProtectedOrdinarySettingsLegacyKeys.gracePeriod)
        defaults.set(normalized.encryptToSelf, forKey: ProtectedOrdinarySettingsLegacyKeys.encryptToSelf)
        defaults.set(
            normalized.hasCompletedOnboarding,
            forKey: ProtectedOrdinarySettingsLegacyKeys.onboardingComplete
        )
        defaults.set(
            normalized.guidedTutorialCompletedVersion,
            forKey: ProtectedOrdinarySettingsLegacyKeys.guidedTutorialCompletedVersion
        )
        defaults.set(normalized.colorTheme.rawValue, forKey: ProtectedOrdinarySettingsLegacyKeys.colorTheme)
    }

    func removePersistentValues() {
        for key in Self.persistentKeys {
            defaults.removeObject(forKey: key)
        }
    }

    static let persistentKeys: [String] = [
        ProtectedOrdinarySettingsLegacyKeys.gracePeriod,
        ProtectedOrdinarySettingsLegacyKeys.encryptToSelf,
        ProtectedOrdinarySettingsLegacyKeys.onboardingComplete,
        ProtectedOrdinarySettingsLegacyKeys.guidedTutorialCompletedVersion,
        ProtectedOrdinarySettingsLegacyKeys.colorTheme
    ]
}

final class ProtectedSettingsOrdinarySettingsPersistence: ProtectedOrdinarySettingsPersistence {
    private let protectedSettingsStore: ProtectedSettingsStore

    init(protectedSettingsStore: ProtectedSettingsStore) {
        self.protectedSettingsStore = protectedSettingsStore
    }

    func loadSnapshot() throws -> ProtectedOrdinarySettingsSnapshot {
        try protectedSettingsStore.ordinarySettingsSnapshot()
    }

    func saveSnapshot(_ snapshot: ProtectedOrdinarySettingsSnapshot) throws {
        try protectedSettingsStore.updateOrdinarySettingsSnapshot(snapshot)
    }

    func removePersistentValues() {
        protectedSettingsStore.resetOrdinarySettingsRuntimeStateAfterLocalDataReset()
    }
}
