import Foundation

/// Bridges a loaded Secure Enclave composite key-agreement handle into the
/// Rust engine's `ExternalMlKem768DecapsulationProvider` callback. The
/// callback performs exactly the enclave primitive — ML-KEM-768 decapsulation
/// into the 32-byte key share; the X25519 half, the RFC 9980 KEM combiner, and
/// AES key unwrap stay in Rust.
final class PGPExternalMlKem768DecapsulationProviderBridge: ExternalMlKem768DecapsulationProvider,
    @unchecked Sendable {
    private let handle: SecureEnclaveCustodyLoadedHandle
    private let decapsulator: any SecureEnclaveCompositeDecapsulating

    init(
        handle: SecureEnclaveCustodyLoadedHandle,
        decapsulator: any SecureEnclaveCompositeDecapsulating
    ) {
        self.handle = handle
        self.decapsulator = decapsulator
    }

    func decapsulateMlkem768(
        request: ExternalMlKem768DecapsulationRequest
    ) throws -> MlKem768KeyShare {
        do {
            var keyShare = try decapsulator.decapsulateMlKem768(request: request, using: handle)
            defer { keyShare.resetBytes(in: 0..<keyShare.count) }
            let ffiShare = keyShare.withUnsafeBytes { buffer in Data(buffer) }
            return MlKem768KeyShare(raw: ffiShare)
        } catch is CancellationError {
            throw ExternalCompositeKeyAgreementError.OperationCancelled
        } catch let error as SecureEnclaveCustodyHandleError {
            throw ExternalCompositeKeyAgreementError.Failed(
                category: Self.callbackCategory(for: error.failureCategory)
            )
        } catch {
            throw ExternalCompositeKeyAgreementError.Failed(category: .externalOperationFailed)
        }
    }

    private static func callbackCategory(
        for category: PGPKeyOperationFailureCategory
    ) -> ExternalCompositeKeyAgreementFailureCategory {
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
        case .externalOperationInvalidRequest:
            return .externalOperationInvalidRequest
        case .externalOperationInvalidResponse:
            return .externalOperationInvalidResponse
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
             .recoveryRequired,
             .prohibitedFallbackAttempted,
             .cleanupOrRollbackFailure:
            return .externalOperationFailed
        }
    }
}
