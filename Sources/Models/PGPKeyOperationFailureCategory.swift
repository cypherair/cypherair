import Foundation

/// Stable, sanitized failure categories for key operation availability.
enum PGPKeyOperationFailureCategory: String, CaseIterable, Codable, Hashable, Sendable {
    case invalidConfigurationCustody
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
    case metadataAssociationMismatch
    case publicCertificateAssociationMismatch
    case publicMaterialUnavailable
    case revocationArtifactUnavailable
    case externalOperationInvalidRequest
    case externalOperationInvalidResponse
    case externalOperationFailed
    case openPGPSemanticFailure
    case payloadAuthenticationFailure
    case migrationOrRecoveryRequired
    case prohibitedFallbackAttempted
    case cleanupOrRollbackFailure
}
