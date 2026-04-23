import Foundation

/// Coordinates transient system-owned authentication prompts so app lifecycle
/// handlers can distinguish them from real background/resume events.
final class AuthenticationPromptCoordinator: @unchecked Sendable {
    private enum PromptKind {
        case privacy
        case operation
    }

    private let lock = NSLock()
    private var privacyPromptDepth = 0
    private var operationPromptDepth = 0

    var isPromptInProgress: Bool {
        lock.withLock {
            privacyPromptDepth > 0 || operationPromptDepth > 0
        }
    }

    var isPrivacyPromptInProgress: Bool {
        lock.withLock {
            privacyPromptDepth > 0
        }
    }

    var isOperationPromptInProgress: Bool {
        lock.withLock {
            operationPromptDepth > 0
        }
    }

    func beginPrivacyPrompt() {
        adjustPromptDepth(for: .privacy, delta: 1)
    }

    func endPrivacyPrompt() {
        adjustPromptDepth(for: .privacy, delta: -1)
    }

    func beginOperationPrompt() {
        adjustPromptDepth(for: .operation, delta: 1)
    }

    func endOperationPrompt() {
        adjustPromptDepth(for: .operation, delta: -1)
    }

    func withPrivacyPrompt<T>(_ operation: () throws -> T) rethrows -> T {
        beginPrivacyPrompt()
        defer { endPrivacyPrompt() }
        return try operation()
    }

    func withPrivacyPrompt<T>(_ operation: () async throws -> T) async rethrows -> T {
        beginPrivacyPrompt()
        defer { endPrivacyPrompt() }
        return try await operation()
    }

    func withOperationPrompt<T>(_ operation: () throws -> T) rethrows -> T {
        beginOperationPrompt()
        defer { endOperationPrompt() }
        return try operation()
    }

    func withOperationPrompt<T>(_ operation: () async throws -> T) async rethrows -> T {
        beginOperationPrompt()
        defer { endOperationPrompt() }
        return try await operation()
    }

    // Legacy operation-scoped aliases kept to minimize churn in tests and helper code.
    func beginPrompt() {
        beginOperationPrompt()
    }

    func endPrompt() {
        endOperationPrompt()
    }

    func withPrompt<T>(_ operation: () throws -> T) rethrows -> T {
        try withOperationPrompt(operation)
    }

    func withPrompt<T>(_ operation: () async throws -> T) async rethrows -> T {
        try await withOperationPrompt(operation)
    }

    private func adjustPromptDepth(for kind: PromptKind, delta: Int) {
        lock.withLock {
            switch kind {
            case .privacy:
                privacyPromptDepth = max(privacyPromptDepth + delta, 0)
            case .operation:
                operationPromptDepth = max(operationPromptDepth + delta, 0)
            }
        }
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
