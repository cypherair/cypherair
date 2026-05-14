import Foundation

enum PGPErrorMapper {
    static func map(
        _ error: Error,
        fallback: (String) -> CypherAirError
    ) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }
        if let pgpError = error as? PgpError {
            return map(pgpError)
        }
        return fallback(error.localizedDescription)
    }

    static func mapRecipientMatching(_ error: Error) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }
        guard let pgpError = error as? PgpError else {
            return .noMatchingKey
        }

        switch pgpError {
        case .CorruptData(let reason):
            return .corruptData(reason: reason)
        case .UnsupportedAlgorithm(let algo):
            return .unsupportedAlgorithm(algo: algo)
        default:
            return .noMatchingKey
        }
    }

    static func map(_ pgpError: PgpError) -> CypherAirError {
        switch pgpError {
        case .AeadAuthenticationFailed:
            return .aeadAuthenticationFailed
        case .NoMatchingKey:
            return .noMatchingKey
        case .UnsupportedAlgorithm(let algo):
            return .unsupportedAlgorithm(algo: algo)
        case .KeyExpired:
            return .keyExpired
        case .BadSignature:
            return .badSignature
        case .UnknownSigner:
            return .unknownSigner
        case .CorruptData(let reason):
            return .corruptData(reason: reason)
        case .WrongPassphrase:
            return .wrongPassphrase
        case .InvalidKeyData(let reason):
            return .invalidKeyData(reason: reason)
        case .EncryptionFailed(let reason):
            return .encryptionFailed(reason: reason)
        case .SigningFailed(let reason):
            return .signingFailed(reason: reason)
        case .ArmorError(let reason):
            return .armorError(reason: reason)
        case .IntegrityCheckFailed:
            return .integrityCheckFailed
        case .Argon2idMemoryExceeded(let requiredMb):
            return .argon2idMemoryExceeded(requiredMb: requiredMb)
        case .RevocationError(let reason):
            return .revocationError(reason: reason)
        case .KeyGenerationFailed(let reason):
            return .keyGenerationFailed(reason: reason)
        case .S2kError(let reason):
            return .s2kError(reason: reason)
        case .InternalError(let reason):
            return .internalError(reason: reason)
        case .OperationCancelled:
            return .operationCancelled
        case .FileIoError(let reason):
            return .fileIoError(reason: reason)
        case .KeyTooLargeForQr:
            return .keyTooLargeForQr
        }
    }
}
