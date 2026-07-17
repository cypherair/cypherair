import Foundation

/// Ephemeral ordinary-settings persistence for compositions whose settings
/// live no longer than the owning container, such as the tutorial sandbox and
/// the UI-test authenticated-bypass graph.
final class InMemoryOrdinarySettingsStore: ProtectedOrdinarySettingsPersistence {
    private var snapshot: ProtectedOrdinarySettingsSnapshot

    init(snapshot: ProtectedOrdinarySettingsSnapshot = .firstRunDefaults) {
        var normalized = snapshot
        normalized.normalize()
        self.snapshot = normalized
    }

    func loadSnapshot() -> ProtectedOrdinarySettingsSnapshot {
        snapshot
    }

    func saveSnapshot(_ snapshot: ProtectedOrdinarySettingsSnapshot) {
        var normalized = snapshot
        normalized.normalize()
        self.snapshot = normalized
    }

    func removePersistentValues() {
        snapshot = .firstRunDefaults
    }
}
