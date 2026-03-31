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
    private(set) var progress: FileProgressReporter?
    private(set) var error: CypherAirError?
    var isShowingError = false
    var isShowingClipboardNotice = false

    private var currentTask: Task<Void, Never>?

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
        progress?.cancel()
        currentTask?.cancel()
        currentTask = nil
        isRunning = false
    }

    func dismissError() {
        error = nil
        isShowingError = false
    }

    func copyToClipboard(_ string: String, config: AppConfiguration) {
        PlatformClipboard.copy(string)
        if config.clipboardNotice {
            isShowingClipboardNotice = true
        }
    }

    func dismissClipboardNotice(disableFutureNoticesIn config: AppConfiguration? = nil) {
        if let config {
            config.clipboardNotice = false
        }
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
        cancel()
        dismissError()
        isShowingClipboardNotice = false
        self.progress = progress
        isRunning = true

        currentTask = Task { @MainActor [weak self] in
            guard let self else { return }

            defer {
                self.progress = nil
                self.isRunning = false
                self.currentTask = nil
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
                self.present(error: mapError(error))
            }
        }
    }

    private static func shouldIgnore(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let cypherAirError = error as? CypherAirError,
           case .operationCancelled = cypherAirError {
            return true
        }
        if let pgpError = error as? PgpError,
           case .OperationCancelled = pgpError {
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
