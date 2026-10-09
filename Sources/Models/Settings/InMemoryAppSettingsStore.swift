/// Settings that live no longer than their container: the tutorial sandbox
/// and the UI-test graph.
final class InMemoryAppSettingsStore: AppSettingsPersistence {
    private var snapshot: AppSettingsSnapshot

    init(snapshot: AppSettingsSnapshot = .firstRun) {
        var normalized = snapshot
        normalized.normalize()
        self.snapshot = normalized
    }

    func load() -> AppSettingsSnapshot {
        snapshot
    }

    func save(_ snapshot: AppSettingsSnapshot) {
        var normalized = snapshot
        normalized.normalize()
        self.snapshot = normalized
    }
}
