import Foundation

struct SecureEnclaveCustodyHandleCleanupResult: Equatable, Sendable {
    let inspectedHandleCount: Int
    let deletedHandleCount: Int
    let failureCategory: PGPKeyOperationFailureCategory?

    var succeeded: Bool {
        failureCategory == nil
    }
}
