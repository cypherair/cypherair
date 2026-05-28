import Foundation

final class KeyProvisioningCommitCoordinator: @unchecked Sendable {
    typealias WaiterRegisteredCheckpoint = @Sendable () async -> Void

    private let lock = NSLock()
    private var activeCommitCount = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func performCommit<Result>(
        _ operation: () async throws -> Result
    ) async rethrows -> Result {
        enterCommit()
        defer {
            leaveCommit()
        }

        return try await operation()
    }

    func waitForActiveCommitsToFinish(
        waiterRegisteredCheckpoint: WaiterRegisteredCheckpoint? = nil
    ) async {
        await withCheckedContinuation { continuation in
            var shouldResumeImmediately = false
            var didRegisterWaiter = false

            lock.lock()
            if activeCommitCount == 0 {
                shouldResumeImmediately = true
            } else {
                waiters.append(continuation)
                didRegisterWaiter = true
            }
            lock.unlock()

            if shouldResumeImmediately {
                continuation.resume()
            } else if didRegisterWaiter, let waiterRegisteredCheckpoint {
                Task {
                    await waiterRegisteredCheckpoint()
                }
            }
        }
    }

    private func enterCommit() {
        lock.lock()
        activeCommitCount += 1
        lock.unlock()
    }

    private func leaveCommit() {
        var continuationsToResume: [CheckedContinuation<Void, Never>] = []

        lock.lock()
        activeCommitCount = max(activeCommitCount - 1, 0)
        if activeCommitCount == 0 {
            continuationsToResume = waiters
            waiters.removeAll()
        }
        lock.unlock()

        for continuation in continuationsToResume {
            continuation.resume()
        }
    }
}
