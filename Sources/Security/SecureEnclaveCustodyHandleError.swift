import Foundation

enum SecureEnclaveCustodyHandleError: Error, Equatable {
    case invalidHandleSetIdentifier
    case invalidApplicationTag
    case invalidPublicKey(PGPPrivateOperationRole)
    case accessPolicyUnavailable
    case hardwareUnavailable
    case localAuthenticationCancelled(PGPPrivateOperationRole)
    case localAuthenticationFailed(PGPPrivateOperationRole)
    case privateHandleMissing(PGPPrivateOperationRole)
    case privateHandleInaccessible(PGPPrivateOperationRole)
    case privateHandleUnauthorized(PGPPrivateOperationRole)
    case ambiguousPrivateHandle(PGPPrivateOperationRole)
    case privateOperationRoleMismatch(expected: PGPPrivateOperationRole, actual: PGPPrivateOperationRole)
    case handlePublicKeyBindingMismatch(PGPPrivateOperationRole)
    case partialHandlePair
    case cleanupOrRollbackFailed

    var failureCategory: PGPKeyOperationFailureCategory {
        switch self {
        case .invalidHandleSetIdentifier,
             .invalidApplicationTag,
             .invalidPublicKey:
            return .privateHandleInaccessible
        case .accessPolicyUnavailable:
            return .localAuthenticationUnavailable
        case .hardwareUnavailable:
            return .hardwareUnavailable
        case .localAuthenticationCancelled:
            return .localAuthenticationCancelled
        case .localAuthenticationFailed:
            return .localAuthenticationFailed
        case .privateHandleMissing:
            return .privateHandleMissing
        case .privateHandleInaccessible,
             .ambiguousPrivateHandle:
            return .privateHandleInaccessible
        case .privateHandleUnauthorized:
            return .privateHandleUnauthorized
        case .privateOperationRoleMismatch:
            return .privateOperationRoleMismatch
        case .handlePublicKeyBindingMismatch:
            return .handlePublicKeyBindingMismatch
        case .partialHandlePair:
            return .migrationOrRecoveryRequired
        case .cleanupOrRollbackFailed:
            return .cleanupOrRollbackFailure
        }
    }

    var isMissing: Bool {
        if case .privateHandleMissing = self {
            return true
        }
        return false
    }
}
