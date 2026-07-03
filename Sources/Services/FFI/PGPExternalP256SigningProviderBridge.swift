import Foundation

final class PGPExternalP256SigningProviderBridge: ExternalP256SigningProvider, @unchecked Sendable {
    private let handle: SecureEnclaveCustodyLoadedHandle
    private let digestSigner: any SecureEnclaveCustodyDigestSigning

    init(
        handle: SecureEnclaveCustodyLoadedHandle,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) {
        self.handle = handle
        self.digestSigner = digestSigner
    }

    func signSha256Digest(digest: Data) throws -> P256EcdsaSignature {
        do {
            let signature = try digestSigner.signSHA256Digest(digest, using: handle)
            return P256EcdsaSignature(r: signature.r, s: signature.s)
        } catch is CancellationError {
            throw ExternalP256SigningError.OperationCancelled
        } catch let error as SecureEnclaveCustodyHandleError {
            throw ExternalP256SigningError.Failed(
                category: Self.callbackCategory(for: error.failureCategory)
            )
        } catch {
            throw ExternalP256SigningError.Failed(category: .externalOperationFailed)
        }
    }

    private static func callbackCategory(
        for category: PGPKeyOperationFailureCategory
    ) -> ExternalP256SigningFailureCategory {
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
             .classicalComponentFailed,
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
