import Foundation

protocol ProtectedOrdinarySettingsPersistence {
    func loadSnapshot() throws -> ProtectedOrdinarySettingsSnapshot
    func saveSnapshot(_ snapshot: ProtectedOrdinarySettingsSnapshot) throws
    func removePersistentValues()
}
