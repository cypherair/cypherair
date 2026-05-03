#if os(macOS)
import AppKit
#endif

enum LocalDataResetRestartAction {
    @MainActor
    static func terminateCurrentProcess() {
        #if os(macOS)
        NSApplication.shared.terminate(nil)
        #endif
    }
}
