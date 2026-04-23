import SwiftUI

private struct AuthLifecycleTraceStoreKey: EnvironmentKey {
    static let defaultValue: AuthLifecycleTraceStore? = nil
}

extension EnvironmentValues {
    var authLifecycleTraceStore: AuthLifecycleTraceStore? {
        get { self[AuthLifecycleTraceStoreKey.self] }
        set { self[AuthLifecycleTraceStoreKey.self] = newValue }
    }
}
