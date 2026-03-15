import Foundation
import os

/// Bridges Rust streaming progress callbacks to SwiftUI-observable state.
/// Implements the UniFFI-generated `ProgressReporter` protocol.
///
/// Thread safety: `onProgress()` is called from a Rust worker thread.
/// Uses `OSAllocatedUnfairLock` for the cancel flag and dispatches UI
/// updates to `@MainActor`.
@Observable
final class FileProgressReporter: ProgressReporter, @unchecked Sendable {

    // MARK: - Observable State

    /// Total bytes processed so far.
    private(set) var bytesProcessed: UInt64 = 0

    /// Total expected bytes (from file metadata). May be 0 if unknown.
    private(set) var totalBytes: UInt64 = 0

    /// Fraction completed (0.0–1.0). Returns 0 if totalBytes is unknown.
    var fractionCompleted: Double {
        guard totalBytes > 0 else { return 0 }
        return Double(bytesProcessed) / Double(totalBytes)
    }

    // MARK: - Cancellation

    private let cancelLock = OSAllocatedUnfairLock(initialState: false)

    /// Whether the operation has been cancelled.
    var isCancelled: Bool {
        cancelLock.withLock { $0 }
    }

    /// Request cancellation. The Rust engine will stop at the next progress callback.
    func cancel() {
        cancelLock.withLock { $0 = true }
    }

    // MARK: - ProgressReporter Protocol

    /// Called from the Rust worker thread on each progress update.
    /// Returns `false` to signal cancellation.
    func onProgress(bytesProcessed: UInt64, totalBytes: UInt64) -> Bool {
        Task { @MainActor [weak self] in
            self?.bytesProcessed = bytesProcessed
            self?.totalBytes = totalBytes
        }
        return !isCancelled
    }

    // MARK: - Reset

    /// Reset state for reuse.
    func reset() {
        bytesProcessed = 0
        totalBytes = 0
        cancelLock.withLock { $0 = false }
    }
}
