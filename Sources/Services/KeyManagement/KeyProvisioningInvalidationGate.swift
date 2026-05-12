import Foundation

final class KeyProvisioningInvalidationGate: @unchecked Sendable {
    struct Token: Equatable, Sendable {
        fileprivate let generation: UInt64
    }

    private let lock = NSLock()
    private var generation: UInt64 = 0

    func makeToken() -> Token {
        lock.lock()
        defer { lock.unlock() }
        return Token(generation: generation)
    }

    func invalidate() {
        lock.lock()
        generation &+= 1
        lock.unlock()
    }

    func checkValid(_ token: Token) throws {
        lock.lock()
        let isValid = generation == token.generation
        lock.unlock()

        guard isValid else {
            throw CancellationError()
        }
    }
}
