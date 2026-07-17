import Foundation

/// Invalidates stale system file picker completions after content clear or view teardown.
struct FileImportRequestGate {
    struct Token: Equatable {
        fileprivate let generation: UInt64
    }

    private var generation: UInt64 = 0
    private var activeToken: Token?

    var currentToken: Token? {
        activeToken
    }

    @discardableResult
    mutating func begin() -> Token {
        generation &+= 1
        let token = Token(generation: generation)
        activeToken = token
        return token
    }

    mutating func invalidate() {
        generation &+= 1
        activeToken = nil
    }

    @discardableResult
    mutating func consumeIfCurrent(_ token: Token?) -> Bool {
        guard let token, token == activeToken else {
            return false
        }

        activeToken = nil
        return true
    }
}
