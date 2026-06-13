import Foundation
import LocalAuthentication

enum SecureEnclaveCustodyAuthenticationErrorNormalizer {
    static func normalize(_ error: Error) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }

        if let laError = error as? LAError {
            switch laError.code {
            case .userCancel, .appCancel, .systemCancel:
                return .operationCancelled
            case .biometryNotAvailable, .biometryNotEnrolled:
                return .biometricsUnavailable
            case .biometryLockout:
                return .keyOperationUnavailable(category: .localAuthenticationLockedOut)
            default:
                return .authenticationFailed
            }
        }

        return .authenticationFailed
    }
}
