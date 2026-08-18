import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Shared async operation state for task lifecycle, cancellation, progress, and error mapping.
///
/// Two behaviors here exist because the complete file-protection class seals
/// the app's files shortly after the device locks (SECURITY.md §5): while an
/// operation runs the app holds off idle sleep, and when protected data is
/// about to become unavailable anyway — the device locked past backgrounding —
/// the operation in flight is stopped inside the grace window, its partial
/// output erased by the owning service's cancellation path, and the person
/// told it can be run again. On macOS files do not seal on lock, so the
/// notification wiring and the idle-sleep hold are UIKit-only.
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

    /// Distinguishes a protected-data stop from an ordinary user cancel, which
    /// stays silent: this one must tell the person what happened.
    @ObservationIgnored private var isStoppedForProtectedDataUnavailability = false
    #if canImport(UIKit)
    @ObservationIgnored private nonisolated(unsafe) var protectedDataObserver: (any NSObjectProtocol)?
    #endif

    init(
        backgroundRunner: @escaping BackgroundOperationRunner = PlatformBackgroundActivity.perform,
        progressFactory: @escaping () -> FileProgressReporter = { FileProgressReporter() }
    ) {
        self.backgroundRunner = backgroundRunner
        self.progressFactory = progressFactory
        #if canImport(UIKit)
        protectedDataObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.stopForProtectedDataUnavailability()
            }
        }
        #endif
    }

    deinit {
        #if canImport(UIKit)
        if let protectedDataObserver {
            NotificationCenter.default.removeObserver(protectedDataObserver)
        }
        #endif
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

    /// Stop the operation in flight because protected data is about to become
    /// unavailable. The stop rides the ordinary cancellation path — the owning
    /// service erases its partial output there — but surfaces as an error the
    /// person sees, where a cancel they asked for stays silent.
    func stopForProtectedDataUnavailability() {
        guard isRunning else { return }
        isStoppedForProtectedDataUnavailability = true
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
        isStoppedForProtectedDataUnavailability = false
        currentTask = nil
        dismissError()
        isShowingClipboardNotice = false
    }

    func dismissError() {
        error = nil
        isShowingError = false
    }

    func copyToClipboard(_ string: String, shouldShowNotice: Bool) {
        CypherClipboard.copy(string)
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
        isStoppedForProtectedDataUnavailability = false

        currentTask = Task { @MainActor [weak self] in
            OperationController.beginHoldingOffIdleSleep()
            defer {
                OperationController.endHoldingOffIdleSleep()
            }

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
            } catch {
                guard self.currentOperationID == operationID else { return }
                if self.isStoppedForProtectedDataUnavailability {
                    self.present(error: .operationInterruptedByDeviceLock)
                    return
                }
                if error is CancellationError || Self.shouldIgnore(error) {
                    return
                }
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

    // MARK: - Idle-Sleep Hold

    /// One hold per running operation task, counted across every controller
    /// instance — a briefly overlapping pair must not drop the hold when the
    /// first finishes.
    #if canImport(UIKit)
    private static var idleSleepHoldCount = 0
    #endif

    private static func beginHoldingOffIdleSleep() {
        #if canImport(UIKit)
        idleSleepHoldCount += 1
        UIApplication.shared.isIdleTimerDisabled = true
        #endif
    }

    private static func endHoldingOffIdleSleep() {
        #if canImport(UIKit)
        idleSleepHoldCount -= 1
        if idleSleepHoldCount == 0 {
            UIApplication.shared.isIdleTimerDisabled = false
        }
        #endif
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
