import Foundation
import Security

enum SecureEnclaveCustodyHandleError: Error, Equatable {
    case invalidHandleSetIdentifier
    case invalidApplicationTag
    case invalidPublicKey(PGPPrivateOperationRole)
    case invalidPeerPublicKey(PGPPrivateOperationRole)
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
        case .invalidPeerPublicKey:
            // Untrusted peer input (e.g. the PKESK ephemeral point), not a
            // fault of the local custody handle.
            return .externalOperationInvalidRequest
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

/// Maps Security-framework `OSStatus` / `CFError` results to role-tagged
/// `SecureEnclaveCustodyHandleError` values. Shared by the digest signer,
/// key-agreement, and key-store paths so status classification stays consistent
/// across operations rather than being re-implemented per call site.
enum SecureEnclaveCustodyOSStatusMapper {
    static func handleError(
        for status: OSStatus,
        role: PGPPrivateOperationRole
    ) -> SecureEnclaveCustodyHandleError {
        switch status {
        case errSecNotAvailable:
            return .hardwareUnavailable
        case errSecItemNotFound:
            return .privateHandleMissing(role)
        case errSecDuplicateItem:
            return .privateHandleInaccessible(role)
        case errSecUserCanceled:
            return .localAuthenticationCancelled(role)
        case errSecAuthFailed:
            return .localAuthenticationFailed(role)
        case errSecInteractionNotAllowed:
            return .privateHandleUnauthorized(role)
        default:
            return .privateHandleInaccessible(role)
        }
    }

    static func handleError(
        for error: Unmanaged<CFError>?,
        role: PGPPrivateOperationRole
    ) -> SecureEnclaveCustodyHandleError {
        guard let error else {
            return .privateHandleInaccessible(role)
        }
        let code = OSStatus(CFErrorGetCode(error.takeRetainedValue()))
        return handleError(for: code, role: role)
    }
}
