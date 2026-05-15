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

    // Security-layer errors
    case secureEnclaveUnavailable
    case authenticationFailed
    case authenticationCancelled
    case keychainError(String)

    // App-layer errors
    case invalidQRCode
    case unsupportedQRVersion
    case contactImportRequiresPublicCertificate
    case fileTooLarge(sizeMB: Int)
    case insufficientDiskSpace(fileSizeMB: Int, requiredMB: Int, availableMB: Int)
    case noKeySelected
    case noRecipientsSelected
    case biometricsUnavailable
    case duplicateKey
    case keyTooLargeForQr
    case contactsUnavailable(ContactsAvailability)
    case contactKeyReplacementUnsupported

    /// Wrap any error into CypherAirError.
    /// - If it's already a CypherAirError, return as-is.
    /// - Otherwise, use the fallback case with the error's description.
    static func from(_ error: Error, fallback: (String) -> CypherAirError) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        } else {
            return fallback(error.localizedDescription)
        }
    }
}
