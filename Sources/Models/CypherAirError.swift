import Foundation

/// App-level error type that wraps PgpError, Security errors, and UI errors
/// with user-facing localized messages per PRD Section 4.7.
enum CypherAirError: Error, LocalizedError {
    // PGP-layer errors (mapped from PgpError)
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

    // Security-layer errors
    case secureEnclaveUnavailable
    case authenticationFailed
    case authenticationCancelled
    case keychainError(String)

    // App-layer errors
    case invalidQRCode
    case unsupportedQRVersion
    case fileTooLarge(sizeMB: Int)
    case noKeySelected
    case noRecipientsSelected
    case biometricsUnavailable

    /// User-facing error description per PRD Section 4.7.
    var errorDescription: String? {
        switch self {
        case .aeadAuthenticationFailed:
            String(localized: "error.aead", defaultValue: "Message authentication failed. The content may have been tampered with.")
        case .noMatchingKey:
            String(localized: "error.noMatchingKey", defaultValue: "This message is not addressed to any of your identities.")
        case .unsupportedAlgorithm(let algo):
            String(localized: "error.unsupportedAlgo", defaultValue: "Encryption method \(algo) is not supported.")
        case .keyExpired:
            String(localized: "error.keyExpired", defaultValue: "This key has expired. Ask the sender to update their key.")
        case .badSignature:
            String(localized: "error.badSignature", defaultValue: "Signature verification failed. The content may have been modified.")
        case .unknownSigner:
            String(localized: "error.unknownSigner", defaultValue: "The signer is not in your contacts.")
        case .corruptData:
            String(localized: "error.corruptData", defaultValue: "The data appears damaged. Ask the sender to resend.")
        case .wrongPassphrase:
            String(localized: "error.wrongPassphrase", defaultValue: "Incorrect passphrase. Please re-enter your backup passphrase.")
        case .invalidKeyData:
            String(localized: "error.invalidKeyData", defaultValue: "The key data is invalid or corrupt.")
        case .encryptionFailed(let reason):
            String(localized: "error.encryptionFailed", defaultValue: "Encryption failed: \(reason)")
        case .signingFailed(let reason):
            String(localized: "error.signingFailed", defaultValue: "Signing failed: \(reason)")
        case .armorError:
            String(localized: "error.armorError", defaultValue: "Failed to process the message format.")
        case .integrityCheckFailed:
            String(localized: "error.integrityCheck", defaultValue: "Message integrity check failed. The content may have been tampered with.")
        case .argon2idMemoryExceeded(let requiredMb):
            String(localized: "error.argon2idMemory", defaultValue: "This key uses memory-intensive protection (\(requiredMb) MB) that exceeds this device's capacity.")
        case .revocationError:
            String(localized: "error.revocation", defaultValue: "Invalid revocation certificate.")
        case .keyGenerationFailed:
            String(localized: "error.keyGeneration", defaultValue: "Key generation failed. Please try again.")
        case .s2kError(let reason):
            String(localized: "error.s2kError", defaultValue: "Key protection format error: \(reason)")
        case .internalError(let reason):
            String(localized: "error.internalError", defaultValue: "An internal error occurred: \(reason)")
        case .secureEnclaveUnavailable:
            String(localized: "error.seUnavailable", defaultValue: "Secure Enclave is not available on this device.")
        case .authenticationFailed:
            String(localized: "error.authFailed", defaultValue: "Authentication failed.")
        case .authenticationCancelled:
            String(localized: "error.authCancelled", defaultValue: "Authentication was cancelled.")
        case .keychainError:
            String(localized: "error.keychain", defaultValue: "Failed to access secure storage.")
        case .invalidQRCode:
            String(localized: "error.invalidQR", defaultValue: "Not a valid Cypher Air public key.")
        case .unsupportedQRVersion:
            String(localized: "error.unsupportedQRVersion", defaultValue: "This QR code requires a newer version of the app. Please update.")
        case .fileTooLarge(let sizeMB):
            String(localized: "error.fileTooLarge", defaultValue: "File is too large (\(sizeMB) MB). Maximum size is 100 MB.")
        case .noKeySelected:
            String(localized: "error.noKeySelected", defaultValue: "No signing key selected.")
        case .noRecipientsSelected:
            String(localized: "error.noRecipients", defaultValue: "Please select at least one recipient.")
        case .biometricsUnavailable:
            String(localized: "error.biometricsUnavailable", defaultValue: "Biometric authentication is currently unavailable. In High Security mode, all private key operations are blocked until biometric authentication is restored.")
        }
    }

    /// Initialize from a UniFFI PgpError.
    init(pgpError: PgpError) {
        switch pgpError {
        case .AeadAuthenticationFailed:
            self = .aeadAuthenticationFailed
        case .NoMatchingKey:
            self = .noMatchingKey
        case .UnsupportedAlgorithm(let algo):
            self = .unsupportedAlgorithm(algo: algo)
        case .KeyExpired:
            self = .keyExpired
        case .BadSignature:
            self = .badSignature
        case .UnknownSigner:
            self = .unknownSigner
        case .CorruptData(let reason):
            self = .corruptData(reason: reason)
        case .WrongPassphrase:
            self = .wrongPassphrase
        case .InvalidKeyData(let reason):
            self = .invalidKeyData(reason: reason)
        case .EncryptionFailed(let reason):
            self = .encryptionFailed(reason: reason)
        case .SigningFailed(let reason):
            self = .signingFailed(reason: reason)
        case .ArmorError(let reason):
            self = .armorError(reason: reason)
        case .IntegrityCheckFailed:
            self = .integrityCheckFailed
        case .Argon2idMemoryExceeded(let requiredMb):
            self = .argon2idMemoryExceeded(requiredMb: requiredMb)
        case .RevocationError(let reason):
            self = .revocationError(reason: reason)
        case .KeyGenerationFailed(let reason):
            self = .keyGenerationFailed(reason: reason)
        case .S2kError(let reason):
            self = .s2kError(reason: reason)
        case .InternalError(let reason):
            self = .internalError(reason: reason)
        }
    }
}
