import Foundation

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
