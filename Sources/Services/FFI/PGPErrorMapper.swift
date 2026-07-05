import Foundation

enum PGPErrorMapper {
    /// Normalizes generated UniFFI `PgpError` values at the FFI adapter boundary.
    /// Non-FFI layers should receive app-owned `CypherAirError` values instead.
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
            return .internalError(reason: error.localizedDescription)
        }

        if case .NoMatchingKey = pgpError {
            return .noMatchingKey
        }
        return map(pgpError)
    }

    static func mapExternalP256Signing(_ error: Error) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }
        guard let pgpError = error as? PgpError else {
            return .signingFailed(reason: error.localizedDescription)
        }

        switch pgpError {
        case .OperationCancelled:
            return .operationCancelled
        case .ExternalP256SigningFailed(let category):
            return .keyOperationUnavailable(category: externalP256SigningCategory(for: category))
        default:
            return map(pgpError)
        }
    }

    static func mapExternalP256KeyAgreement(_ error: Error) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }
        guard let pgpError = error as? PgpError else {
            return .corruptData(reason: error.localizedDescription)
        }
        // `map` already handles .OperationCancelled and .ExternalP256KeyAgreementFailed
        // identically; this wrapper only differs by its non-PgpError fallback above.
        return map(pgpError)
    }

    static func mapExternalCompositeSigning(_ error: Error) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }
        guard let pgpError = error as? PgpError else {
            return .signingFailed(reason: error.localizedDescription)
        }

        switch pgpError {
        case .OperationCancelled:
            return .operationCancelled
        case .ExternalCompositeSigningFailed(let category):
            return .keyOperationUnavailable(
                category: externalCompositeSigningCategory(for: category)
            )
        default:
            return map(pgpError)
        }
    }

    static func mapExternalCompositeKeyAgreement(_ error: Error) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }
        guard let pgpError = error as? PgpError else {
            return .corruptData(reason: error.localizedDescription)
        }
        // `map` already handles .OperationCancelled and
        // .ExternalCompositeKeyAgreementFailed identically; this wrapper only
        // differs by its non-PgpError fallback above.
        return map(pgpError)
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
        case .ExternalP256SigningFailed(let category):
            return .keyOperationUnavailable(category: externalP256SigningCategory(for: category))
        case .ExternalP256KeyAgreementFailed(let category):
            return .keyOperationUnavailable(category: externalP256KeyAgreementCategory(for: category))
        case .ExternalCompositeSigningFailed(let category):
            return .keyOperationUnavailable(category: externalCompositeSigningCategory(for: category))
        case .ExternalCompositeKeyAgreementFailed(let category):
            return .keyOperationUnavailable(
                category: externalCompositeKeyAgreementCategory(for: category)
            )
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

    private static func externalP256SigningCategory(
        for category: ExternalP256SigningFailureCategory
    ) -> PGPKeyOperationFailureCategory {
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
        }
    }

    private static func externalP256KeyAgreementCategory(
        for category: ExternalP256KeyAgreementFailureCategory
    ) -> PGPKeyOperationFailureCategory {
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
        case .externalOperationInvalidRequest:
            return .externalOperationInvalidRequest
        case .externalOperationInvalidResponse:
            return .externalOperationInvalidResponse
        case .externalOperationFailed:
            return .externalOperationFailed
        }
    }

    private static func externalCompositeSigningCategory(
        for category: ExternalCompositeSigningFailureCategory
    ) -> PGPKeyOperationFailureCategory {
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
        }
    }

    private static func externalCompositeKeyAgreementCategory(
        for category: ExternalCompositeKeyAgreementFailureCategory
    ) -> PGPKeyOperationFailureCategory {
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
        }
    }
}
