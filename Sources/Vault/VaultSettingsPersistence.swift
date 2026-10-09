import Vault

/// The settings domain, read from and written through the vault.
struct VaultSettingsPersistence: AppSettingsPersistence {
    let vault: AppVault

    func load() throws -> AppSettingsSnapshot {
        guard let settings = vault.settings else { throw VaultError.locked }
        return settings
    }

    func save(_ snapshot: AppSettingsSnapshot) throws {
        try vault.saveSettings(snapshot)
    }
}
