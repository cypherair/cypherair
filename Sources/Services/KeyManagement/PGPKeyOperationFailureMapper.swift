import Foundation
import Stores

/// Normalizes lower-layer errors into stable, non-identifying operation categories.
enum PGPKeyOperationFailureMapper {
    static func category(
        for error: Error,
        fallback: PGPKeyOperationFailureCategory = .externalOperationFailed
    ) -> PGPKeyOperationFailureCategory {
        if let custodyError = error as? CustodyError {
            return custodyError.failureCategory
        }
        if let storeError = error as? StoreError {
            return category(for: CypherAirError.fromStore(storeError), fallback: fallback)
        }

        if let cypherAirError = error as? CypherAirError {
            return category(for: cypherAirError, fallback: fallback)
        }

        return fallback
    }

    static func publicCertificateAssociationCategory(
        for error: Error
    ) -> PGPKeyOperationFailureCategory {
        if let cypherAirError = error as? CypherAirError {
            switch cypherAirError {
            case .invalidKeyData,
                 .corruptData,
                 .unsupportedAlgorithm:
                return .publicCertificateAssociationMismatch
            case .operationCancelled:
                return .operationUnavailableByPolicy
            default:
                return category(for: cypherAirError, fallback: .openPGPSemanticFailure)
            }
        }

        return category(for: error, fallback: .publicCertificateAssociationMismatch)
    }

    private static func category(
        for error: CypherAirError,
        fallback: PGPKeyOperationFailureCategory
    ) -> PGPKeyOperationFailureCategory {
        switch error {
        case .keyOperationUnavailable(let category):
            return category
        case .operationCancelled:
            return .localAuthenticationCancelled
        case .authenticationFailed:
            return .localAuthenticationFailed
        case .biometricsUnavailable:
            return .localAuthenticationUnavailable
        case .noMatchingKey:
            return .metadataAssociationMismatch
        case .invalidKeyData,
             .corruptData:
            return .publicCertificateAssociationMismatch
        default:
            return fallback
        }
    }
}
