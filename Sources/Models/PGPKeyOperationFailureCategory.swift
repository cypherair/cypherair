import Foundation

/// Stable, sanitized failure categories for key operation availability.
enum PGPKeyOperationFailureCategory: String, CaseIterable, Codable, Hashable, Sendable {
    case invalidConfigurationCustody
    case operationUnsupportedForCustody
    case operationNotImplementedForCustody
    case operationUnavailableByPolicy
    case hardwareUnavailable
    case authenticationRequired
    case authenticationCancelled
    case authenticationFailed
    case authenticationUnavailable
    case authenticationLockedOut
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
