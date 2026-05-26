import Foundation

/// Operation support result annotated with an optional stable failure category.
struct PGPKeyOperationResolution: Codable, Equatable, Hashable, Sendable {
    let support: PGPKeyOperationSupport
    let failureCategory: PGPKeyOperationFailureCategory?

    static let supported = PGPKeyOperationResolution(
        support: .supported,
        failureCategory: nil
    )

    static func unsupported(_ category: PGPKeyOperationFailureCategory) -> PGPKeyOperationResolution {
        PGPKeyOperationResolution(support: .unsupported, failureCategory: category)
    }

    static func notImplemented(_ category: PGPKeyOperationFailureCategory) -> PGPKeyOperationResolution {
        PGPKeyOperationResolution(support: .notImplemented, failureCategory: category)
    }

    static func unavailable(_ category: PGPKeyOperationFailureCategory) -> PGPKeyOperationResolution {
        PGPKeyOperationResolution(support: .unavailable, failureCategory: category)
    }
}
