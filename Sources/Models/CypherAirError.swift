import Foundation

/// App-level error type for PGP, Security, and UI errors.
enum CypherAirError: Error {
    // PGP-layer errors
    case aeadAuthenticationFailed
    case noMatchingKey
    case unsupportedAlgorithm(algo: String)
    case keyExpired
    case badSignature
    case unknownSigner
    case corruptData(reason: String)
    case wrongPassphrase
    case invalidKeyData(reason: String)
    case encryptionFailed(reason: String)
    case signingFailed(reason: String)
    case armorError(reason: String)
    case integrityCheckFailed
    case argon2idMemoryExceeded(requiredMb: UInt64)
    case revocationError(reason: String)
    case keyGenerationFailed(reason: String)
    case s2kError(reason: String)
    case internalError(reason: String)
    case operationCancelled
    case fileIoError(reason: String)
    case keyOperationUnavailable(category: PGPKeyOperationFailureCategory)

    // Security-layer errors
    case secureEnclaveUnavailable
    case authenticationFailed
    case authenticationCancelled
    case keychainError(String)

    // App-layer errors
    case invalidQRCode
    case unsupportedQRVersion
    case contactImportRequiresPublicCertificate
    case insufficientDiskSpace(fileSizeMB: Int, requiredMB: Int, availableMB: Int)
    case noKeySelected
    case noRecipientsSelected
    case biometricsUnavailable
    case duplicateKey
    case keyTooLargeForQr
    case contactsUnavailable(ContactsAvailability)
    case contactImportConfirmationStale
    case contactImportConfirmationAlreadyPending

    /// Wrap any already-normalized app error into CypherAirError.
    /// - If it's already a CypherAirError, return as-is.
    /// - Otherwise, use the fallback case with the error's description.
    /// Generated UniFFI `PgpError` values are intentionally normalized by
    /// `PGPErrorMapper` in `Sources/Services/FFI`, not here.
    static func from(_ error: Error, fallback: (String) -> CypherAirError) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        } else {
            return fallback(error.localizedDescription)
        }
    }
}
