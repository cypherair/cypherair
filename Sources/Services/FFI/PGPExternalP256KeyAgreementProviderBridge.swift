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
            // The one copy the FFI record costs: UniFFI must copy it across the
            // callback boundary, and Rust immediately validates and stores the
            // received Vec in Zeroizing. The derived secret itself is erased
            // when this scope ends.
            return sharedSecret.raw.withUnsafeBytes { P256RawSharedSecret(raw: Data($0)) }
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
        case .operationUnsupportedForCustody,
             .operationNotImplementedForCustody,
             .operationUnavailableByPolicy,
             .classicalComponentFailed,
             .metadataAssociationMismatch,
             .publicCertificateAssociationMismatch,
             .publicMaterialUnavailable,
             .revocationArtifactUnavailable,
             .openPGPSemanticFailure,
             .recoveryRequired,
             .cleanupOrRollbackFailure:
            return .externalOperationFailed
        // `externalOperationInvalidRequest` is reachable for key agreement:
        // invalidPeerPublicKey (e.g. an off-curve ephemeral point) maps here.
        // `externalOperationInvalidResponse` has no handle-error source today but
        // is mapped for parity. Unlike the signing bridge (which has no peer key
        // and folds both into externalOperationFailed), these are kept distinct so
        // the peer-input category survives to the caller.
        case .externalOperationInvalidRequest:
            return .externalOperationInvalidRequest
        case .externalOperationInvalidResponse:
            return .externalOperationInvalidResponse
        }
    }
}
