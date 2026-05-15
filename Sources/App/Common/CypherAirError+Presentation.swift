import Foundation

extension CypherAirError: LocalizedError {
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
        case .operationCancelled:
            String(localized: "error.operationCancelled", defaultValue: "Operation was cancelled.")
        case .fileIoError(let reason):
            String(localized: "error.fileIoError", defaultValue: "File operation failed: \(reason)")
        case .secureEnclaveUnavailable:
            String(localized: "error.seUnavailable", defaultValue: "Secure Enclave is not available on this device.")
        case .authenticationFailed:
            String(localized: "error.authFailed", defaultValue: "Authentication failed.")
        case .authenticationCancelled:
            String(localized: "error.authCancelled", defaultValue: "Authentication was cancelled.")
        case .keychainError:
            String(localized: "error.keychain", defaultValue: "Failed to access secure storage.")
        case .invalidQRCode:
            String(localized: "error.invalidQR", defaultValue: "Not a valid CypherAir public key.")
        case .unsupportedQRVersion:
            String(localized: "error.unsupportedQRVersion", defaultValue: "This QR code requires a newer version of the app. Please update.")
        case .contactImportRequiresPublicCertificate:
            String(localized: "error.contactImportRequiresPublicCertificate", defaultValue: "Contacts only accept public certificates. Remove any private key material and try again.")
        case .fileTooLarge(let sizeMB):
            String(localized: "error.fileTooLarge", defaultValue: "File is too large (\(sizeMB) MB). Maximum size is 100 MB.")
        case .insufficientDiskSpace(let fileSizeMB, _, let availableMB):
            String(localized: "error.insufficientDiskSpace", defaultValue: "Not enough disk space. File requires approximately \(fileSizeMB) MB but only \(availableMB) MB is available.")
        case .noKeySelected:
            String(localized: "error.noKeySelected", defaultValue: "No signing key selected.")
        case .noRecipientsSelected:
            String(localized: "error.noRecipients", defaultValue: "Please select at least one recipient.")
        case .biometricsUnavailable:
            String(localized: "error.biometricsUnavailable", defaultValue: "Biometric authentication is currently unavailable. In High Security mode, all private key operations are blocked until biometric authentication is restored.")
        case .duplicateKey:
            String(localized: "error.duplicateKey", defaultValue: "A key with this fingerprint already exists on this device.")
        case .keyTooLargeForQr:
            String(localized: "error.keyTooLargeForQr", defaultValue: "This key contains too much data to display as a QR code. Please share your public key via file or text instead.")
        case .contactsUnavailable(let availability):
            availability.unavailableDescription
        case .contactKeyReplacementUnsupported:
            String(
                localized: "error.contactKeyReplacementUnsupported",
                defaultValue: "Key replacement is only available for legacy contacts. Import the new key as a separate contact, then merge contacts if needed."
            )
        }
    }
}
