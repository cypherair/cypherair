import Foundation

/// Session-wide signals the screens observe: when to drop transient content
/// and when the session last authenticated.
@Observable
@MainActor
final class AppSessionOrchestrator {
    private(set) var contentClearGeneration = 0
    private(set) var lastAuthenticationDate: Date?

    func recordAuthentication() {
        lastAuthenticationDate = Date()
    }

    func requestContentClear() {
        contentClearGeneration += 1
    }

    func resetAfterLocalDataReset() {
        lastAuthenticationDate = nil
        contentClearGeneration += 1
    }
}
