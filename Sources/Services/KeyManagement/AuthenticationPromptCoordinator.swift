import Foundation

/// Coordinates the private-key operation prompts the app drives, so macOS app
/// lifecycle handlers can distinguish a system prompt's own app-resign from a
/// real away event.
final class AuthenticationPromptCoordinator: @unchecked Sendable {
    struct OperationPromptToken: Equatable, Sendable {
        let promptID: UInt64
    }

    private let lock = NSLock()
    /// Operation-prompt lifecycle hooks (the `.authenticating` rule's MainActor
    /// mirror). `…SessionBegan` fires when the operation-prompt stack
    /// goes 0 → 1; `…PromptsEnded` fires when it returns to 0. Both fire OUTSIDE
    /// the lock, on the thread that pushed or popped; macOS wires them (via a
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
    private var nextPromptID: UInt64 = 1
    /// Open prompts, innermost last. A stack rather than a counter so a nested
    /// prompt that ends out of order still removes its own entry.
    private var operationPromptStack: [OperationPromptToken] = []

    var isOperationPromptInProgress: Bool {
        lock.withLock {
            !operationPromptStack.isEmpty
        }
    }

    @discardableResult
    func beginOperationPrompt() -> OperationPromptToken {
        let (token, sessionBegan) = lock.withLock { () -> (OperationPromptToken, Bool) in
            let startsNewSession = operationPromptStack.isEmpty
            let token = makeOperationPromptToken()
            operationPromptStack.append(token)
            return (token, startsNewSession)
        }

        if sessionBegan {
            onOperationPromptSessionBegan?()
        }
        return token
    }

    func endOperationPrompt(_ context: OperationPromptToken? = nil) {
        let promptsEnded = lock.withLock { () -> Bool in
            let wasInProgress = !operationPromptStack.isEmpty
            popOperationPromptToken(matching: context)
            return wasInProgress && operationPromptStack.isEmpty
        }

        if promptsEnded {
            onOperationPromptsEnded?()
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

    private func makeOperationPromptToken() -> OperationPromptToken {
        defer { nextPromptID &+= 1 }
        return OperationPromptToken(promptID: nextPromptID)
    }

    private func popOperationPromptToken(matching context: OperationPromptToken?) {
        guard let context else {
            _ = operationPromptStack.popLast()
            return
        }

        if let index = operationPromptStack.lastIndex(where: { $0.promptID == context.promptID }) {
            operationPromptStack.remove(at: index)
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
