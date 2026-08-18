import SwiftUI

/// Everything real-world a view can mutate — the app session, the protected
/// settings host, the App Access Protection policy switch, and local data
/// reset — as one optional environment value.
///
/// Production composition injects it once at the shell root; the tutorial
/// mirror shell explicitly injects nil. Isolation is structural: a sandbox
/// screen cannot name a real mutator because the only value that carries them
/// is absent, and every member is non-optional so a world either has the whole
/// real workspace or none of it.
struct RealWorkspaceAccess {
    let sessionOrchestrator: AppSessionOrchestrator
    let protectedSettingsHost: ProtectedSettingsHost
    let appAccessPolicySwitchAction: SettingsScreenModel.AppAccessPolicySwitchAction
    let localDataResetService: LocalDataResetService
    let localDataResetRestartCoordinator: LocalDataResetRestartCoordinator
}

private struct RealWorkspaceAccessKey: EnvironmentKey {
    nonisolated(unsafe) static let defaultValue: RealWorkspaceAccess? = nil
}

extension EnvironmentValues {
    var realWorkspace: RealWorkspaceAccess? {
        get { self[RealWorkspaceAccessKey.self] }
        set { self[RealWorkspaceAccessKey.self] = newValue }
    }
}
