import Foundation

/// Stable, sanitized failure categories for key operation availability.
enum PGPKeyOperationFailureCategory: String, CaseIterable, Codable, Hashable, Sendable {
    case invalidFamilyCustody
    case operationUnsupportedForCustody
    case operationNotImplementedForCustody
    case operationUnavailableByPolicy
    case hardwareUnavailable
    case localAuthenticationRequired
    case localAuthenticationCancelled
    case localAuthenticationFailed
    case localAuthenticationUnavailable
    case localAuthenticationLockedOut
    case privateHandleMissing
    case privateHandleInaccessible
    case privateHandleUnauthorized
    case privateOperationRoleMismatch
    case handlePublicKeyBindingMismatch
    case classicalComponentFailed
    case metadataAssociationMismatch
    case publicCertificateAssociationMismatch
    case publicMaterialUnavailable
    case revocationArtifactUnavailable
    case externalOperationInvalidRequest
    case externalOperationInvalidResponse
    case externalOperationFailed
    case openPGPSemanticFailure
    case recoveryRequired
    case cleanupOrRollbackFailure
}
