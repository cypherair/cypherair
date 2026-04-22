import Foundation

/// Coordinates transient system-owned authentication prompts so app lifecycle
/// handlers can distinguish them from real background/resume events.
final class AuthenticationPromptCoordinator: @unchecked Sendable {
    private let lock = NSLock()
    private var promptDepth = 0

    var isPromptInProgress: Bool {
        lock.withLock {
            promptDepth > 0
        }
    }

    func beginPrompt() {
        lock.withLock {
            promptDepth += 1
        }
    }

    func endPrompt() {
        lock.withLock {
            guard promptDepth > 0 else {
                return
            }
            promptDepth -= 1
        }
    }

    func withPrompt<T>(_ operation: () throws -> T) rethrows -> T {
        beginPrompt()
        defer { endPrompt() }
        return try operation()
    }

    func withPrompt<T>(_ operation: () async throws -> T) async rethrows -> T {
        beginPrompt()
        defer { endPrompt() }
        return try await operation()
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
