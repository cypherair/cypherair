import Foundation

struct SecureEnclaveCustodyHandleInventorySummary: Equatable, Sendable {
    let totalHandleCount: Int
    let completeSetCount: Int
    let partialSetCount: Int
    let ambiguousSetCount: Int
    let malformedHandleCount: Int

    static let empty = SecureEnclaveCustodyHandleInventorySummary(
        totalHandleCount: 0,
        completeSetCount: 0,
        partialSetCount: 0,
        ambiguousSetCount: 0,
        malformedHandleCount: 0
    )
}
