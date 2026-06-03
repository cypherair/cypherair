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
            var sharedSecret = try keyAgreement.deriveSharedSecret(
                request: request,
                using: handle
            )
            defer { sharedSecret.zeroize() }
            var raw = sharedSecret.rawCopy()
            defer { raw.resetBytes(in: 0..<raw.count) }
            let ffiRaw = raw.withUnsafeBytes { buffer in
                Data(buffer)
            }
            // UniFFI must copy this record across the callback boundary; Rust
            // immediately validates and stores the received Vec in Zeroizing.
            return P256RawSharedSecret(raw: ffiRaw)
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
             .openPGPSemanticFailure,
             .payloadAuthenticationFailure,
             .migrationOrRecoveryRequired,
             .prohibitedFallbackAttempted,
             .cleanupOrRollbackFailure:
            return .externalOperationFailed
        case .externalOperationInvalidRequest:
            return .externalOperationInvalidRequest
        case .externalOperationInvalidResponse:
            return .externalOperationInvalidResponse
        }
    }
}
