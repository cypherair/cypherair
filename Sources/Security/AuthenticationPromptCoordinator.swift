import Foundation
import LocalAuthentication

/// Coordinates transient system-owned authentication prompts so app lifecycle
/// handlers can distinguish them from real background/resume events.
final class AuthenticationPromptCoordinator: @unchecked Sendable {
    struct OperationPromptToken: Equatable, Sendable {
        let promptID: UInt64
    }

    struct OperationAuthenticationPromptSnapshot: Equatable, Sendable {
        let generation: UInt64
        let sessionGeneration: UInt64
        let depth: Int
        let lastBeganAt: Date?
        let lastEndedAt: Date?

        init(
            generation: UInt64,
            sessionGeneration: UInt64? = nil,
            depth: Int,
            lastBeganAt: Date?,
            lastEndedAt: Date?
        ) {
            self.generation = generation
            self.sessionGeneration = sessionGeneration ?? generation
            self.depth = depth
            self.lastBeganAt = lastBeganAt
            self.lastEndedAt = lastEndedAt
        }
    }

    private enum PromptKind {
        case privacy
        case operation
    }

    private let lock = NSLock()
    /// Operation-prompt lifecycle hooks (the `.authenticating` rule's MainActor
    /// mirror). `…SessionBegan` fires when the operation-prompt stack
    /// goes 0 → 1; `…PromptsEnded` fires when it returns to 0. Both fire OUTSIDE
    /// the lock, on the thread that adjusted the depth; macOS wires them (via a
    /// main-actor hop) to `AppLockController.handleOperationPromptSessionBegan()` /
    /// `handleOperationPromptsEnded()`, which maintain the controller's own
    /// main-actor session counter — the race-free state `handleAwayEvent` consults.
    /// Write-once: assigned during container construction, before any prompt can
    /// begin; reassignment traps.
    var onOperationPromptSessionBegan: (@Sendable () -> Void)? {
        didSet { precondition(oldValue == nil, "onOperationPromptSessionBegan is write-once") }
    }
    var onOperationPromptsEnded: (@Sendable () -> Void)? {
        didSet { precondition(oldValue == nil, "onOperationPromptsEnded is write-once") }
    }
    private let now: @Sendable () -> Date
    private var privacyPromptDepth = 0
    private var operationPromptDepth = 0
    private var operationPromptAttemptGenerationValue: UInt64 = 0
    private var operationPromptSessionGenerationValue: UInt64 = 0
    private var lastOperationPromptBeganAt: Date?
    private var lastOperationPromptEndedAt: Date?
    private var nextPromptID: UInt64 = 1
    private var privacyPromptStack: [OperationPromptToken] = []
    private var operationPromptStack: [OperationPromptToken] = []

    init(
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.now = now
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

    var operationAuthenticationPromptSnapshot: OperationAuthenticationPromptSnapshot {
        lock.withLock {
            OperationAuthenticationPromptSnapshot(
                generation: operationPromptAttemptGenerationValue,
                sessionGeneration: operationPromptSessionGenerationValue,
                depth: operationPromptDepth,
                lastBeganAt: lastOperationPromptBeganAt,
                lastEndedAt: lastOperationPromptEndedAt
            )
        }
    }

    @discardableResult
    func beginPrivacyPrompt() -> OperationPromptToken {
        adjustPromptDepth(for: .privacy, delta: 1)
    }

    func endPrivacyPrompt(_ context: OperationPromptToken? = nil) {
        adjustPromptDepth(for: .privacy, delta: -1, context: context)
    }

    @discardableResult
    func beginOperationPrompt() -> OperationPromptToken {
        adjustPromptDepth(for: .operation, delta: 1)
    }

    func endOperationPrompt(_ context: OperationPromptToken? = nil) {
        adjustPromptDepth(for: .operation, delta: -1, context: context)
    }

    func withPrivacyPrompt<T>(
        _ operation: () async throws -> T
    ) async rethrows -> T {
        try await withPrivacyPrompt { _ in
            try await operation()
        }
    }

    func withPrivacyPrompt<T>(
        _ operation: (OperationPromptToken) async throws -> T
    ) async rethrows -> T {
        let context = beginPrivacyPrompt()
        await Task.yield()
        do {
            let result = try await operation(context)
            endPrivacyPrompt(context)
            return result
        } catch {
            endPrivacyPrompt(context)
            throw error
        }
    }

    func withOperationPrompt<T>(
        _ operation: () async throws -> T
    ) async rethrows -> T {
        try await withOperationPrompt { _ in
            try await operation()
        }
    }

    func withOperationPrompt<T>(
        _ operation: (OperationPromptToken) async throws -> T
    ) async rethrows -> T {
        let context = beginOperationPrompt()
        await Task.yield()
        do {
            let result = try await operation(context)
            endOperationPrompt(context)
            return result
        } catch {
            endOperationPrompt(context)
            throw error
        }
    }

    @discardableResult
    private func adjustPromptDepth(
        for kind: PromptKind,
        delta: Int,
        context: OperationPromptToken? = nil
    ) -> OperationPromptToken {
        let timestamp = now()
        let snapshot = lock.withLock { () -> (
            privacyDepth: Int,
            operationDepth: Int,
            operationGeneration: UInt64,
            operationSessionGeneration: UInt64,
            context: OperationPromptToken,
            operationSessionBegan: Bool,
            operationPromptsEnded: Bool
        ) in
            let resolvedContext: OperationPromptToken
            var operationSessionBegan = false
            var operationPromptsEnded = false
            switch kind {
            case .privacy:
                if delta > 0 {
                    resolvedContext = makeOperationPromptToken()
                    privacyPromptStack.append(resolvedContext)
                } else {
                    resolvedContext = popOperationPromptToken(
                        from: &privacyPromptStack,
                        matching: context
                    )
                }
                privacyPromptDepth = privacyPromptStack.count
            case .operation:
                if delta > 0 {
                    let startsNewOperationSession = operationPromptStack.isEmpty
                    resolvedContext = makeOperationPromptToken()
                    operationPromptStack.append(resolvedContext)
                    operationPromptAttemptGenerationValue &+= 1
                    if startsNewOperationSession {
                        operationPromptSessionGenerationValue = operationPromptAttemptGenerationValue
                        operationSessionBegan = true
                    }
                    lastOperationPromptBeganAt = timestamp
                    lastOperationPromptEndedAt = nil
                } else {
                    let wasOperationPromptInProgress = !operationPromptStack.isEmpty
                    resolvedContext = popOperationPromptToken(
                        from: &operationPromptStack,
                        matching: context
                    )
                    if wasOperationPromptInProgress, operationPromptStack.isEmpty {
                        lastOperationPromptEndedAt = timestamp
                        operationPromptsEnded = true
                    }
                }
                operationPromptDepth = operationPromptStack.count
            }
            return (
                privacyPromptDepth,
                operationPromptDepth,
                operationPromptAttemptGenerationValue,
                operationPromptSessionGenerationValue,
                resolvedContext,
                operationSessionBegan,
                operationPromptsEnded
            )
        }

        if snapshot.operationSessionBegan {
            onOperationPromptSessionBegan?()
        }
        if snapshot.operationPromptsEnded {
            onOperationPromptsEnded?()
        }
        return snapshot.context
    }

    private func makeOperationPromptToken() -> OperationPromptToken {
        defer { nextPromptID &+= 1 }
        return OperationPromptToken(promptID: nextPromptID)
    }

    private func popOperationPromptToken(
        from stack: inout [OperationPromptToken],
        matching context: OperationPromptToken?
    ) -> OperationPromptToken {
        guard let context else {
            return stack.popLast() ?? OperationPromptToken(promptID: 0)
        }

        if stack.last?.promptID == context.promptID {
            _ = stack.popLast()
            return context
        }

        if let index = stack.lastIndex(where: { $0.promptID == context.promptID }) {
            stack.remove(at: index)
        }
        return context
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
