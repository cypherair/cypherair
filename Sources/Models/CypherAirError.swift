import Foundation

/// App-level error type for PGP, Security, and UI errors.
enum CypherAirError: Error {
    // PGP-layer errors
    case aeadAuthenticationFailed
    case noMatchingKey
    case unsupportedAlgorithm(algo: String)
    case keyExpired
    case badSignature
    /// The engine could not start verifying, so nothing was checked. Kept apart
    /// from `badSignature`: only a completed check may state a verdict.
    case verificationUnavailable(reason: String)
    case unknownSigner
    case corruptData(reason: String)
    /// A message exceeded a processing limit — how much of it the engine will
    /// walk, how deeply it nests, or how far it expands — and was refused
    /// before the resource was spent. Kept apart from `corruptData`: nothing
    /// here says the message is damaged, and resending it would not help.
    case messageLimitsExceeded(reason: String)
    case wrongPassphrase
    /// The password given for a password-protected message did not open it.
    /// Distinct from `wrongPassphrase`, which is about a key artifact: the two
    /// reach the user in different places and cannot share one sentence.
    case wrongMessagePassword
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
    /// A write ran out of space on the destination volume. The pre-flight
    /// counterpart is `insufficientDiskSpace`, which knows the figures.
    case storageFull
    case keyOperationUnavailable(category: PGPKeyOperationFailureCategory)

    // Security-layer errors
    case authenticationFailed
    case keychainError(String)
    case keyMetadataUnavailable

    // App-layer errors
    case invalidQRCode
    case unsupportedQRVersion
    case contactImportRequiresPublicCertificate
    case insufficientDiskSpace(requiredMB: Int, availableMB: Int)
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
