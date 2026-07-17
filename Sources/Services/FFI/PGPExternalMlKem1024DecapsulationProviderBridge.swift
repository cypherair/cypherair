import Foundation

/// Bridges a loaded Secure Enclave composite key-agreement handle into the
/// Rust engine's `ExternalMlKem1024DecapsulationProvider` callback. The
/// callback performs exactly the enclave primitive — ML-KEM-1024 decapsulation
/// into the 32-byte key share; the X448 half, the RFC 9980 KEM combiner, and
/// AES key unwrap stay in Rust (Device-Bound Post-Quantum · High).
final class PGPExternalMlKem1024DecapsulationProviderBridge: ExternalMlKem1024DecapsulationProvider,
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

    func decapsulateMlkem1024(
        request: ExternalMlKem1024DecapsulationRequest
    ) throws -> MlKem1024KeyShare {
        do {
            var keyShare = try decapsulator.decapsulateMlKem1024(request: request, using: handle)
            defer { keyShare.resetBytes(in: 0..<keyShare.count) }
            let ffiShare = keyShare.withUnsafeBytes { buffer in Data(buffer) }
            return MlKem1024KeyShare(raw: ffiShare)
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
