import Foundation

/// The settings for the current session: `nil` while locked, the persisted
/// snapshot once loaded. Every write goes through persistence first; a write
/// that fails leaves the loaded snapshot as it was.
@Observable
final class AppSettingsCoordinator {
    private let persistence: any AppSettingsPersistence
    private(set) var snapshot: AppSettingsSnapshot?

    @ObservationIgnored
    private var pendingOnboardingCompletionOverride: Bool?

    init(persistence: any AppSettingsPersistence) {
        self.persistence = persistence
    }

    var isLoaded: Bool { snapshot != nil }
    var gracePeriodForSession: Int? { snapshot?.gracePeriod }
    var hasCompletedOnboarding: Bool? { snapshot?.hasCompletedOnboarding }
    var encryptToSelf: Bool? { snapshot?.encryptToSelf }
    var signMessages: Bool? { snapshot?.signMessages }
    var hasCompletedGuidedTutorial: Bool? { snapshot?.hasCompletedGuidedTutorial }
    var clipboardNotice: Bool? { snapshot?.clipboardNotice }

    /// Reads the settings after unlock. A settings domain that cannot be read
    /// stays unloaded; the integrity report, not this coordinator, says why.
    func load() {
        guard var loaded = try? persistence.load() else {
            snapshot = nil
            return
        }
        let persisted = loaded
        if let pendingOnboardingCompletionOverride {
            loaded.hasCompletedOnboarding = pendingOnboardingCompletionOverride
        }
        loaded.normalize()
        if loaded != persisted {
            try? persistence.save(loaded)
        }
        snapshot = loaded
    }

    func relock() {
        snapshot = nil
    }

    func applyOnboardingCompletionOverrideForTesting(_ completed: Bool) {
        pendingOnboardingCompletionOverride = completed
        update { $0.hasCompletedOnboarding = completed }
    }

    func setGracePeriod(_ gracePeriod: Int) {
        update { $0.gracePeriod = gracePeriod }
    }

    func setEncryptToSelf(_ encryptToSelf: Bool) {
        update { $0.encryptToSelf = encryptToSelf }
    }

    func setSignMessages(_ signMessages: Bool) {
        update { $0.signMessages = signMessages }
    }

    func setHasCompletedOnboarding(_ hasCompletedOnboarding: Bool) {
        update { $0.hasCompletedOnboarding = hasCompletedOnboarding }
    }

    func markGuidedTutorialCompleted() {
        update { $0.hasCompletedGuidedTutorial = true }
    }

    func setClipboardNotice(_ enabled: Bool) {
        update { $0.clipboardNotice = enabled }
    }

    private func update(_ change: (inout AppSettingsSnapshot) -> Void) {
        guard var changed = snapshot else { return }
        change(&changed)
        changed.normalize()
        guard (try? persistence.save(changed)) != nil else { return }
        snapshot = changed
    }
}
