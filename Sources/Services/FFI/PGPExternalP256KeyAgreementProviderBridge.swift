import Foundation

final class PGPExternalP256KeyAgreementProviderBridge: ExternalP256KeyAgreementProvider, @unchecked Sendable {
    private let handle: SecureEnclaveCustodyLoadedHandle
    private let keyAgreement: any SecureEnclaveCustodyKeyAgreement

    init(
        handle: SecureEnclaveCustodyLoadedHandle,
        keyAgreement: any SecureEnclaveCustodyKeyAgreement
    ) {
        self.handle = handle
        self.keyAgreement = keyAgreement
    }

    func deriveSharedSecret(
        request: ExternalP256KeyAgreementRequest
    ) throws -> P256RawSharedSecret {
        do {
            let sharedSecret = try keyAgreement.deriveSharedSecret(
                request: request,
                using: handle
            )
            return P256RawSharedSecret(raw: sharedSecret.raw)
        } catch is CancellationError {
            throw ExternalP256KeyAgreementError.OperationCancelled
        } catch let error as SecureEnclaveCustodyHandleError {
            throw ExternalP256KeyAgreementError.Failed(
                category: Self.callbackCategory(for: error.failureCategory)
            )
        } catch {
            throw ExternalP256KeyAgreementError.Failed(category: .externalOperationFailed)
        }
    }

    private static func callbackCategory(
        for category: PGPKeyOperationFailureCategory
    ) -> ExternalP256KeyAgreementFailureCategory {
        switch category {
        case .hardwareUnavailable:
            return .hardwareUnavailable
        case .localAuthenticationRequired:
            return .localAuthenticationRequired
        case .localAuthenticationCancelled:
            return .localAuthenticationCancelled
        case .localAuthenticationFailed:
            return .localAuthenticationFailed
        case .localAuthenticationUnavailable:
            return .localAuthenticationUnavailable
        case .localAuthenticationLockedOut:
            return .localAuthenticationLockedOut
        case .privateHandleMissing:
            return .privateHandleMissing
        case .privateHandleInaccessible:
            return .privateHandleInaccessible
        case .privateHandleUnauthorized:
            return .privateHandleUnauthorized
        case .privateOperationRoleMismatch:
            return .privateOperationRoleMismatch
        case .handlePublicKeyBindingMismatch:
            return .handlePublicKeyBindingMismatch
        case .externalOperationFailed:
            return .externalOperationFailed
        case .invalidConfigurationCustody,
             .operationUnsupportedForCustody,
             .operationNotImplementedForCustody,
             .operationUnavailableByPolicy,
             .metadataAssociationMismatch,
             .publicCertificateAssociationMismatch,
             .publicMaterialUnavailable,
             .revocationArtifactUnavailable,
             .externalOperationInvalidRequest,
             .externalOperationInvalidResponse,
             .openPGPSemanticFailure,
             .payloadAuthenticationFailure,
             .migrationOrRecoveryRequired,
             .prohibitedFallbackAttempted,
             .cleanupOrRollbackFailure:
            return .externalOperationFailed
        }
    }
}
