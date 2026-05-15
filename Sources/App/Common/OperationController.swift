import Foundation
#if canImport(AppKit)
import AppKit
#endif
#if canImport(UIKit)
import UIKit
#endif

/// Shared async operation state for task lifecycle, cancellation, progress, and error mapping.
@MainActor
@Observable
final class OperationController {
    typealias BackgroundOperationRunner = @Sendable (@MainActor @escaping () async throws -> Void) async throws -> Void

    private let backgroundRunner: BackgroundOperationRunner
    private let progressFactory: () -> FileProgressReporter

    private(set) var isRunning = false
    private(set) var isCancelling = false
    private(set) var progress: FileProgressReporter?
    private(set) var error: CypherAirError?
    var isShowingError = false
    var isShowingClipboardNotice = false

    private var currentTask: Task<Void, Never>?
    private var currentOperationID: UInt64 = 0
    private var nextOperationID: UInt64 = 0

    init(
        backgroundRunner: @escaping BackgroundOperationRunner = PlatformBackgroundActivity.perform,
        progressFactory: @escaping () -> FileProgressReporter = { FileProgressReporter() }
    ) {
        self.backgroundRunner = backgroundRunner
        self.progressFactory = progressFactory
    }

    func run(
        mapError: @MainActor @Sendable @escaping (Error) -> CypherAirError,
        operation: @MainActor @escaping () async throws -> Void
    ) {
        execute(
            useBackgroundRunner: false,
            progress: nil,
            mapError: mapError,
            operation: operation
        )
    }

    func runFileOperation(
        mapError: @MainActor @Sendable @escaping (Error) -> CypherAirError,
        operation: @MainActor @escaping (FileProgressReporter) async throws -> Void
    ) {
        let progress = progressFactory()
        execute(
            useBackgroundRunner: true,
            progress: progress,
            mapError: mapError
        ) {
            try await operation(progress)
        }
    }

    func cancel() {
        guard currentTask != nil else { return }
        progress?.cancel()
        currentTask?.cancel()
        isCancelling = true
    }

    func cancelAndInvalidate() {
        progress?.cancel()
        currentTask?.cancel()
        nextOperationID &+= 1
        currentOperationID = nextOperationID
        progress = nil
        isRunning = false
        isCancelling = false
        currentTask = nil
        dismissError()
        isShowingClipboardNotice = false
    }

    func dismissError() {
        error = nil
        isShowingError = false
    }

    func copyToClipboard(_ string: String, shouldShowNotice: Bool) {
        PlatformClipboard.copy(string)
        if shouldShowNotice {
            isShowingClipboardNotice = true
        }
    }

    func dismissClipboardNotice() {
        isShowingClipboardNotice = false
    }

    func present(error: CypherAirError) {
        self.error = error
        isShowingError = true
    }

    private func execute(
        useBackgroundRunner: Bool,
        progress: FileProgressReporter?,
        mapError: @MainActor @Sendable @escaping (Error) -> CypherAirError,
        operation: @MainActor @escaping () async throws -> Void
    ) {
        progress?.reset()
        self.progress?.cancel()
        currentTask?.cancel()
        dismissError()
        isShowingClipboardNotice = false

        nextOperationID &+= 1
        let operationID = nextOperationID
        currentOperationID = operationID
        self.progress = progress
        isRunning = true
        isCancelling = false

        currentTask = Task { @MainActor [weak self] in
            guard let self else { return }

            defer {
                self.finishOperation(operationID: operationID)
            }

            do {
                if useBackgroundRunner {
                    try await self.backgroundRunner(operation)
                } else {
                    try await operation()
                }
            } catch is CancellationError {
                return
            } catch {
                if Self.shouldIgnore(error) {
                    return
                }
                guard self.currentOperationID == operationID else { return }
                self.present(error: mapError(error))
            }
        }
    }

    private func finishOperation(operationID: UInt64) {
        guard currentOperationID == operationID else { return }
        progress = nil
        isRunning = false
        isCancelling = false
        currentTask = nil
    }

    private static func shouldIgnore(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let cypherAirError = error as? CypherAirError,
           case .operationCancelled = cypherAirError {
            return true
        }
        return false
    }
}

@MainActor
private enum PlatformClipboard {
    static func copy(_ string: String) {
        #if canImport(UIKit)
        UIPasteboard.general.string = string
        #elseif canImport(AppKit)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
        #endif
    }
}

@MainActor
private enum PlatformBackgroundActivity {
    static func perform(_ operation: @MainActor @escaping () async throws -> Void) async throws {
        #if canImport(UIKit)
        var backgroundTaskID = UIBackgroundTaskIdentifier.invalid
        backgroundTaskID = UIApplication.shared.beginBackgroundTask {
            UIApplication.shared.endBackgroundTask(backgroundTaskID)
            backgroundTaskID = .invalid
        }
        defer {
            if backgroundTaskID != .invalid {
                UIApplication.shared.endBackgroundTask(backgroundTaskID)
            }
        }
        #endif

        try await operation()
    }
}
