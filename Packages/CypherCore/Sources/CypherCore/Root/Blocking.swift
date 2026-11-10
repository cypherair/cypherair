import Foundation

/// The one way the core runs a call that can block: on a thread of its own,
/// off the main actor and off Swift's shared pool, which a derivation or a
/// large file would hold for seconds.
enum Blocking {
    static func run<T: Sendable, E: Error>(_ work: @escaping @Sendable () throws(E) -> T) async throws(E) -> T {
        let result = await withCheckedContinuation { (continuation: CheckedContinuation<Result<T, E>, Never>) in
            let thread = Thread {
                continuation.resume(returning: Result(catching: work))
            }
            thread.stackSize = 8 << 20
            thread.qualityOfService = .userInitiated
            thread.start()
        }
        return try result.get()
    }
}
