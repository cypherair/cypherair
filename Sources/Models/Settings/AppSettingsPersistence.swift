protocol AppSettingsPersistence {
    func load() throws -> AppSettingsSnapshot
    func save(_ snapshot: AppSettingsSnapshot) throws
}
