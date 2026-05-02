import Foundation

@Observable
final class ProtectedOrdinarySettingsCoordinator {
    enum State: Equatable {
        case locked
        case loaded(ProtectedOrdinarySettingsSnapshot)
        case recoveryRequired
    }

    private let persistence: ProtectedOrdinarySettingsPersistence
    private(set) var state: State = .locked

    @ObservationIgnored
    private var pendingOnboardingCompletionOverride: Bool?

    init(persistence: ProtectedOrdinarySettingsPersistence) {
        self.persistence = persistence
    }

    var snapshot: ProtectedOrdinarySettingsSnapshot? {
        guard case .loaded(let snapshot) = state else {
            return nil
        }
        return snapshot
    }

    var isLoaded: Bool {
        snapshot != nil
    }

    var gracePeriodForSession: Int? {
        snapshot?.gracePeriod
    }

    var hasCompletedOnboarding: Bool? {
        snapshot?.hasCompletedOnboarding
    }

    var colorTheme: ColorTheme {
        snapshot?.colorTheme ?? .systemDefault
    }

    var encryptToSelf: Bool? {
        snapshot?.encryptToSelf
    }

    var guidedTutorialCompletionState: GuidedTutorialCompletionState? {
        snapshot?.guidedTutorialCompletionState
    }

    func loadAfterAppAuthentication(
        protectedSettingsDomainState: ProtectedSettingsDomainState
    ) {
        switch protectedSettingsDomainState {
        case .unlocked:
            loadFromPersistence()
        case .locked, .recoveryNeeded, .pendingRetryRequired, .pendingResetRequired, .frameworkUnavailable:
            state = .recoveryRequired
        }
    }

    func loadForAuthenticatedTestBypass() {
        loadFromPersistence()
    }

    func relock() {
        state = .locked
    }

    func resetAfterLocalDataReset(preserveAuthentication: Bool) {
        persistence.removePersistentValues()
        pendingOnboardingCompletionOverride = nil
        state = preserveAuthentication ? .loaded(.firstRunDefaults) : .locked
    }

    func applyOnboardingCompletionOverrideForTesting(_ completed: Bool) {
        pendingOnboardingCompletionOverride = completed
        guard var snapshot else { return }
        snapshot.hasCompletedOnboarding = completed
        saveLoadedSnapshot(snapshot)
    }

    func setGracePeriod(_ gracePeriod: Int) {
        guard var snapshot else { return }
        snapshot.gracePeriod = gracePeriod
        saveLoadedSnapshot(snapshot)
    }

    func setEncryptToSelf(_ encryptToSelf: Bool) {
        guard var snapshot else { return }
        snapshot.encryptToSelf = encryptToSelf
        saveLoadedSnapshot(snapshot)
    }

    func setHasCompletedOnboarding(_ hasCompletedOnboarding: Bool) {
        guard var snapshot else { return }
        snapshot.hasCompletedOnboarding = hasCompletedOnboarding
        saveLoadedSnapshot(snapshot)
    }

    func setColorTheme(_ colorTheme: ColorTheme) {
        guard var snapshot else { return }
        snapshot.colorTheme = colorTheme
        saveLoadedSnapshot(snapshot)
    }

    func markGuidedTutorialCompletedCurrentVersion() {
        guard var snapshot else { return }
        snapshot.guidedTutorialCompletedVersion = GuidedTutorialVersion.current
        saveLoadedSnapshot(snapshot)
    }

    private func loadFromPersistence() {
        do {
            var snapshot = try persistence.loadSnapshot()
            let loadedSnapshot = snapshot
            if let pendingOnboardingCompletionOverride {
                snapshot.hasCompletedOnboarding = pendingOnboardingCompletionOverride
            }
            snapshot.normalize()
            if snapshot != loadedSnapshot {
                try persistence.saveSnapshot(snapshot)
            }
            state = .loaded(snapshot)
        } catch {
            state = .recoveryRequired
        }
    }

    private func saveLoadedSnapshot(_ snapshot: ProtectedOrdinarySettingsSnapshot) {
        var normalized = snapshot
        normalized.normalize()
        do {
            try persistence.saveSnapshot(normalized)
            state = .loaded(normalized)
        } catch {
            state = .recoveryRequired
        }
    }
}
