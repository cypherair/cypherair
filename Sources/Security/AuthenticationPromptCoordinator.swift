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

    struct OperationAuthenticationPromptSnapshot: Equatable, Sendable {
        static let idle = OperationAuthenticationPromptSnapshot(
            generation: 0,
            sessionGeneration: 0,
            depth: 0,
            lastBeganAt: nil,
            lastEndedAt: nil
        )

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

        var isInProgress: Bool {
            depth > 0
        }
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
    private let now: @Sendable () -> Date
    private var privacyPromptDepth = 0
    private var operationPromptDepth = 0
    private var operationPromptAttemptGenerationValue: UInt64 = 0
    private var operationPromptSessionGenerationValue: UInt64 = 0
    private var lastOperationPromptBeganAt: Date?
    private var lastOperationPromptEndedAt: Date?
    private var anyPromptAttemptGenerationValue: UInt64 = 0
    private var anyPromptSessionGenerationValue: UInt64 = 0
    private var lastAnyPromptBeganAt: Date?
    private var lastAnyPromptEndedAt: Date?
    private var nextPromptID: UInt64 = 1
    private var privacyPromptStack: [PromptTraceContext] = []
    private var operationPromptStack: [PromptTraceContext] = []

    init(
        shieldEventHandler: ShieldEventHandler? = nil,
        traceStore: AuthLifecycleTraceStore? = nil,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.shieldEventHandler = shieldEventHandler
        self.traceStore = traceStore
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

    /// Whether ANY app-owned authentication prompt — privacy OR operation — is in
    /// progress. Privacy prompts cover the app-session resume / auth-mode switch /
    /// App Access Protection change; operation prompts cover private-key
    /// signing/decryption.
    var isAnyAuthenticationPromptInProgress: Bool {
        lock.withLock {
            privacyPromptDepth + operationPromptDepth > 0
        }
    }

    /// Snapshot over the UNION of both prompt channels, shaped like the operation
    /// snapshot so the app-session lifecycle gate can consume it directly. The gate
    /// uses this to suppress the transient `.inactive`/`.active` a system biometric
    /// sheet causes on EITHER channel — a privacy-channel biometric (App Access /
    /// mode switch) is otherwise invisible to the operation-only snapshot.
    /// `lastEndedAt` is reported only once the combined depth returns to 0, so a
    /// nested cross-channel prompt never leaks a premature "ended" instant.
    var anyAuthenticationPromptSnapshot: OperationAuthenticationPromptSnapshot {
        lock.withLock {
            OperationAuthenticationPromptSnapshot(
                generation: anyPromptAttemptGenerationValue,
                sessionGeneration: anyPromptSessionGenerationValue,
                depth: privacyPromptDepth + operationPromptDepth,
                lastBeganAt: lastAnyPromptBeganAt,
                lastEndedAt: lastAnyPromptEndedAt
            )
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
        let timestamp = now()
        let snapshot = lock.withLock { () -> (
            privacyDepth: Int,
            operationDepth: Int,
            operationGeneration: UInt64,
            operationSessionGeneration: UInt64,
            context: PromptTraceContext
        ) in
            let resolvedContext: PromptTraceContext
            let combinedDepthBefore = privacyPromptStack.count + operationPromptStack.count
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
                    let startsNewOperationSession = operationPromptStack.isEmpty
                    resolvedContext = makePromptTraceContext(kind: kind, source: source)
                    operationPromptStack.append(resolvedContext)
                    operationPromptAttemptGenerationValue &+= 1
                    if startsNewOperationSession {
                        operationPromptSessionGenerationValue = operationPromptAttemptGenerationValue
                    }
                    lastOperationPromptBeganAt = timestamp
                    lastOperationPromptEndedAt = nil
                } else {
                    let wasOperationPromptInProgress = !operationPromptStack.isEmpty
                    resolvedContext = popPromptTraceContext(
                        from: &operationPromptStack,
                        matching: context,
                        kind: kind
                    )
                    if wasOperationPromptInProgress, operationPromptStack.isEmpty {
                        lastOperationPromptEndedAt = timestamp
                    }
                }
                operationPromptDepth = operationPromptStack.count
            }
            // Union (privacy + operation) prompt tracking. The lifecycle gate keys
            // off this so a system biometric sheet on EITHER channel suppresses the
            // transient resign/activate cycle it causes — regardless of how long the
            // biometric takes.
            let combinedDepthAfter = privacyPromptStack.count + operationPromptStack.count
            if delta > 0 {
                anyPromptAttemptGenerationValue &+= 1
                if combinedDepthBefore == 0 {
                    anyPromptSessionGenerationValue = anyPromptAttemptGenerationValue
                }
                lastAnyPromptBeganAt = timestamp
                lastAnyPromptEndedAt = nil
            } else if combinedDepthBefore > 0, combinedDepthAfter == 0 {
                lastAnyPromptEndedAt = timestamp
            }
            return (
                privacyPromptDepth,
                operationPromptDepth,
                operationPromptAttemptGenerationValue,
                operationPromptSessionGenerationValue,
                resolvedContext
            )
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
                "operationSessionGeneration": String(snapshot.operationSessionGeneration),
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
