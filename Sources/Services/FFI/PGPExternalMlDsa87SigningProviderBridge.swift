import Foundation

/// Bridges a loaded Secure Enclave composite signing handle into the Rust
/// engine's `ExternalMlDsa87SigningProvider` callback. The callback performs
/// exactly the enclave primitive — a pure ML-DSA-87 signature over the OpenPGP
/// signature digest; the Ed448 half and all composite assembly stay in Rust
/// (Device-Bound Post-Quantum · High).
final class PGPExternalMlDsa87SigningProviderBridge: ExternalMlDsa87SigningProvider, @unchecked Sendable {
    private let handle: SecureEnclaveCustodyLoadedHandle
    private let compositeSigner: any SecureEnclaveCompositeSigning

    init(
        handle: SecureEnclaveCustodyLoadedHandle,
        compositeSigner: any SecureEnclaveCompositeSigning
    ) {
        self.handle = handle
        self.compositeSigner = compositeSigner
    }

    func signMldsa87Digest(digest: Data) throws -> MlDsa87Signature {
        do {
            let signature = try compositeSigner.signMlDsa87Digest(digest, using: handle)
            return MlDsa87Signature(raw: signature)
        } catch is CancellationError {
            throw ExternalCompositeSigningError.OperationCancelled
        } catch let error as SecureEnclaveCustodyHandleError {
            throw ExternalCompositeSigningError.Failed(
                category: Self.callbackCategory(for: error.failureCategory)
            )
        } catch {
            throw ExternalCompositeSigningError.Failed(category: .externalOperationFailed)
        }
    }

    private static func callbackCategory(
        for category: PGPKeyOperationFailureCategory
    ) -> ExternalCompositeSigningFailureCategory {
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
        case .classicalComponentFailed:
            return .classicalComponentFailed
        case .externalOperationFailed:
            return .externalOperationFailed
        case .invalidFamilyCustody,
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
             .recoveryRequired,
             .cleanupOrRollbackFailure:
            return .externalOperationFailed
        }
    }
}
