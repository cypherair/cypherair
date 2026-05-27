import Foundation

enum SecureEnclaveCustodyHandleState: Equatable, Sendable {
    case missing
    case partial(presentRoles: Set<PGPPrivateOperationRole>)
    case complete(SecureEnclaveCustodyHandlePair)
    case invalid(SecureEnclaveCustodyHandleError)
}
