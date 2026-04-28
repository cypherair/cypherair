import Foundation
import LocalAuthentication

/// Coordinates transient system-owned authentication prompts so app lifecycle
/// handlers can distinguish them from real background/resume events.
final class AuthenticationPromptCoordinator: @unchecked Sendable {
    typealias ShieldEventHandler = @Sendable (AuthenticationShieldKind, Int) async -> Void

    struct PromptTraceContext: Equatable, Sendable {
        let promptID: UInt64
        let source: String
        let kind: String
    }

    private enum PromptKind {
        case privacy
        case operation

        var traceValue: String {
            switch self {
            case .privacy:
                "privacy"
            case .operation:
                "operation"
            }
        }
    }

    private let lock = NSLock()
    private let shieldEventHandler: ShieldEventHandler?
    private let traceStore: AuthLifecycleTraceStore?
    private var privacyPromptDepth = 0
    private var operationPromptDepth = 0
    private var operationPromptAttemptGenerationValue: UInt64 = 0
    private var nextPromptID: UInt64 = 1
    private var privacyPromptStack: [PromptTraceContext] = []
    private var operationPromptStack: [PromptTraceContext] = []

    init(
        shieldEventHandler: ShieldEventHandler? = nil,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.shieldEventHandler = shieldEventHandler
        self.traceStore = traceStore
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

    @discardableResult
    func beginPrivacyPrompt(source: String = "unspecified") -> PromptTraceContext {
        adjustPromptDepth(for: .privacy, delta: 1, source: source)
    }

    func endPrivacyPrompt(_ context: PromptTraceContext? = nil) {
        adjustPromptDepth(for: .privacy, delta: -1, context: context)
    }

    @discardableResult
    func beginOperationPrompt(source: String = "unspecified") -> PromptTraceContext {
        adjustPromptDepth(for: .operation, delta: 1, source: source)
    }

    func endOperationPrompt(_ context: PromptTraceContext? = nil) {
        adjustPromptDepth(for: .operation, delta: -1, context: context)
    }

    func withPrivacyPrompt<T>(
        source: String = "unspecified",
        _ operation: () async throws -> T
    ) async rethrows -> T {
        try await withPrivacyPrompt(source: source) { _ in
            try await operation()
        }
    }

    func withPrivacyPrompt<T>(
        source: String = "unspecified",
        _ operation: (PromptTraceContext) async throws -> T
    ) async rethrows -> T {
        let context = beginPrivacyPrompt(source: source)
        tracePrivacyPromptStage("prompt.privacy.handler.enter", context: context)
        await shieldEventHandler?(.privacy, 1)
        await Task.yield()
        do {
            tracePrivacyPromptStage("prompt.privacy.operation.await.start", context: context)
            let result = try await operation(context)
            tracePrivacyPromptStage("prompt.privacy.operation.await.finish", context: context)
            tracePrivacyPromptStage("prompt.privacy.endDepth.start", context: context)
            endPrivacyPrompt(context)
            tracePrivacyPromptStage("prompt.privacy.endDepth.finish", context: context)
            tracePrivacyPromptStage("prompt.privacy.shieldEnd.start", context: context)
            await shieldEventHandler?(.privacy, -1)
            tracePrivacyPromptStage("prompt.privacy.shieldEnd.finish", context: context)
            return result
        } catch {
            tracePrivacyPromptStage(
                "prompt.privacy.operation.await.throw",
                context: context,
                metadata: AuthErrorTraceMetadata.errorMetadata(error)
            )
            tracePromptError(context: context, error: error)
            tracePrivacyPromptStage("prompt.privacy.endDepth.start", context: context)
            endPrivacyPrompt(context)
            tracePrivacyPromptStage("prompt.privacy.endDepth.finish", context: context)
            tracePrivacyPromptStage("prompt.privacy.shieldEnd.start", context: context)
            await shieldEventHandler?(.privacy, -1)
            tracePrivacyPromptStage("prompt.privacy.shieldEnd.finish", context: context)
            throw error
        }
    }

    func withOperationPrompt<T>(
        source: String = "unspecified",
        _ operation: () async throws -> T
    ) async rethrows -> T {
        try await withOperationPrompt(source: source) { _ in
            try await operation()
        }
    }

    func withOperationPrompt<T>(
        source: String = "unspecified",
        _ operation: (PromptTraceContext) async throws -> T
    ) async rethrows -> T {
        let context = beginOperationPrompt(source: source)
        traceOperationPromptStage("prompt.operation.handler.enter", context: context)
        await shieldEventHandler?(.operation, 1)
        await Task.yield()
        do {
            traceOperationPromptStage("prompt.operation.operation.await.start", context: context)
            let result = try await operation(context)
            traceOperationPromptStage("prompt.operation.operation.await.finish", context: context)
            traceOperationPromptStage("prompt.operation.endDepth.start", context: context)
            endOperationPrompt(context)
            traceOperationPromptStage("prompt.operation.endDepth.finish", context: context)
            traceOperationPromptStage("prompt.operation.shieldEnd.start", context: context)
            await shieldEventHandler?(.operation, -1)
            traceOperationPromptStage("prompt.operation.shieldEnd.finish", context: context)
            return result
        } catch {
            traceOperationPromptStage(
                "prompt.operation.operation.await.throw",
                context: context,
                metadata: AuthErrorTraceMetadata.errorMetadata(error)
            )
            tracePromptError(context: context, error: error)
            traceOperationPromptStage("prompt.operation.endDepth.start", context: context)
            endOperationPrompt(context)
            traceOperationPromptStage("prompt.operation.endDepth.finish", context: context)
            traceOperationPromptStage("prompt.operation.shieldEnd.start", context: context)
            await shieldEventHandler?(.operation, -1)
            traceOperationPromptStage("prompt.operation.shieldEnd.finish", context: context)
            throw error
        }
    }

    @discardableResult
    private func adjustPromptDepth(
        for kind: PromptKind,
        delta: Int,
        source: String = "unspecified",
        context: PromptTraceContext? = nil
    ) -> PromptTraceContext {
        let snapshot = lock.withLock { () -> (
            privacyDepth: Int,
            operationDepth: Int,
            operationGeneration: UInt64,
            context: PromptTraceContext
        ) in
            let resolvedContext: PromptTraceContext
            switch kind {
            case .privacy:
                if delta > 0 {
                    resolvedContext = makePromptTraceContext(kind: kind, source: source)
                    privacyPromptStack.append(resolvedContext)
                } else {
                    resolvedContext = popPromptTraceContext(
                        from: &privacyPromptStack,
                        matching: context,
                        kind: kind
                    )
                }
                privacyPromptDepth = privacyPromptStack.count
            case .operation:
                if delta > 0 {
                    resolvedContext = makePromptTraceContext(kind: kind, source: source)
                    operationPromptStack.append(resolvedContext)
                    operationPromptAttemptGenerationValue &+= 1
                } else {
                    resolvedContext = popPromptTraceContext(
                        from: &operationPromptStack,
                        matching: context,
                        kind: kind
                    )
                }
                operationPromptDepth = operationPromptStack.count
            }
            return (privacyPromptDepth, operationPromptDepth, operationPromptAttemptGenerationValue, resolvedContext)
        }

        traceStore?.record(
            category: .prompt,
            name: delta > 0 ? "prompt.begin" : "prompt.end",
            metadata: [
                "promptID": String(snapshot.context.promptID),
                "source": snapshot.context.source,
                "kind": snapshot.context.kind,
                "privacyDepth": String(snapshot.privacyDepth),
                "operationDepth": String(snapshot.operationDepth),
                "operationGeneration": String(snapshot.operationGeneration),
                "active": snapshot.privacyDepth > 0 || snapshot.operationDepth > 0 ? "true" : "false"
            ]
        )
        return snapshot.context
    }

    private func makePromptTraceContext(
        kind: PromptKind,
        source: String
    ) -> PromptTraceContext {
        defer { nextPromptID &+= 1 }
        return PromptTraceContext(
            promptID: nextPromptID,
            source: source,
            kind: kind.traceValue
        )
    }

    private func tracePromptError(context: PromptTraceContext, error: Error) {
        var metadata = [
            "promptID": String(context.promptID),
            "source": context.source,
            "kind": context.kind,
            "errorType": String(describing: type(of: error))
        ]
        if let laError = error as? LAError {
            metadata["laCode"] = String(laError.errorCode)
            metadata["laCodeName"] = String(describing: laError.code)
        }
        traceStore?.record(
            category: .prompt,
            name: "prompt.error",
            metadata: metadata
        )
    }

    private func traceOperationPromptStage(
        _ name: String,
        context: PromptTraceContext,
        metadata: [String: String] = [:]
    ) {
        tracePromptStage(name, context: context, metadata: metadata)
    }

    private func tracePrivacyPromptStage(
        _ name: String,
        context: PromptTraceContext,
        metadata: [String: String] = [:]
    ) {
        tracePromptStage(name, context: context, metadata: metadata)
    }

    private func tracePromptStage(
        _ name: String,
        context: PromptTraceContext,
        metadata: [String: String]
    ) {
        var mergedMetadata = metadata
        mergedMetadata["promptID"] = String(context.promptID)
        mergedMetadata["source"] = context.source
        mergedMetadata["kind"] = context.kind
        mergedMetadata["isMainThread"] = Thread.isMainThread ? "true" : "false"
        traceStore?.record(
            category: .prompt,
            name: name,
            metadata: mergedMetadata
        )
    }

    private func popPromptTraceContext(
        from stack: inout [PromptTraceContext],
        matching context: PromptTraceContext?,
        kind: PromptKind
    ) -> PromptTraceContext {
        guard let context else {
            return stack.popLast() ?? PromptTraceContext(
                promptID: 0,
                source: "missing",
                kind: kind.traceValue
            )
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
