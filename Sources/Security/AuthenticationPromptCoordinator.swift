import Foundation

/// Coordinates transient system-owned authentication prompts so app lifecycle
/// handlers can distinguish them from real background/resume events.
final class AuthenticationPromptCoordinator: @unchecked Sendable {
    private enum PromptKind {
        case privacy
        case operation
    }

    private let lock = NSLock()
    private let traceStore: AuthLifecycleTraceStore?
    private var privacyPromptDepth = 0
    private var operationPromptDepth = 0
    private var operationPromptAttemptGenerationValue: UInt64 = 0

    init(traceStore: AuthLifecycleTraceStore? = nil) {
        self.traceStore = traceStore
    }

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

    /// Monotonic generation for operation-authentication attempts.
    /// Increments when an operation prompt begins, even if the prompt ends before
    /// app lifecycle callbacks for that system-owned dialog are delivered.
    var operationPromptAttemptGeneration: UInt64 {
        lock.withLock {
            operationPromptAttemptGenerationValue
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
        let snapshot = lock.withLock { () -> (privacyDepth: Int, operationDepth: Int, operationGeneration: UInt64) in
            switch kind {
            case .privacy:
                privacyPromptDepth = max(privacyPromptDepth + delta, 0)
            case .operation:
                if delta > 0 {
                    operationPromptAttemptGenerationValue &+= 1
                }
                operationPromptDepth = max(operationPromptDepth + delta, 0)
            }
            return (privacyPromptDepth, operationPromptDepth, operationPromptAttemptGenerationValue)
        }

        traceStore?.record(
            category: .prompt,
            name: delta > 0 ? "prompt.begin" : "prompt.end",
            metadata: [
                "kind": kind == .privacy ? "privacy" : "operation",
                "privacyDepth": String(snapshot.privacyDepth),
                "operationDepth": String(snapshot.operationDepth),
                "operationGeneration": String(snapshot.operationGeneration),
                "active": snapshot.privacyDepth > 0 || snapshot.operationDepth > 0 ? "true" : "false"
            ]
        )
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
