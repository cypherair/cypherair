import Foundation

extension CypherAirError: LocalizedError {
    /// User-facing error description. The copy is owned by the String Catalog
    /// (docs/PRODUCT.md §5); this file only routes each case to its key.
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
        case .verificationUnavailable:
            String(localized: "error.verificationUnavailable", defaultValue: "This signature could not be checked. The signature data is damaged or uses a format this app does not support.")
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
            String(localized: "error.argon2idMemory", defaultValue: "Passphrase protection for this key needs \(Self.memorySize(megabytes: requiredMb)) of memory, which isn't available right now. Try again after freeing some up.")
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
        case .storageFull:
            String(localized: "error.storageFull", defaultValue: "Not enough disk space. The device ran out of space while writing the file.")
        case .keyOperationUnavailable(let category):
            Self.keyOperationUnavailableDescription(for: category)
        case .authenticationFailed:
            String(localized: "error.authFailed", defaultValue: "Authentication failed.")
        case .keychainError:
            String(localized: "error.keychain", defaultValue: "Failed to access secure storage.")
        case .keyMetadataUnavailable:
            String(localized: "error.keyMetadataUnavailable", defaultValue: "Key information is locked or unavailable. Unlock the app and try again.")
        case .invalidQRCode:
            String(localized: "error.invalidQR", defaultValue: "Not a valid CypherAir X public key.")
        case .unsupportedQRVersion:
            String(localized: "error.unsupportedQRVersion", defaultValue: "This QR code requires a newer version of the app. Please update.")
        case .contactImportRequiresPublicCertificate:
            String(localized: "error.contactImportRequiresPublicCertificate", defaultValue: "Contacts only accept public certificates. Remove any private key material and try again.")
        case .insufficientDiskSpace(let requiredMB, let availableMB):
            String(localized: "error.insufficientDiskSpace", defaultValue: "Not enough disk space. File requires approximately \(requiredMB) MB but only \(availableMB) MB is available.")
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
        case .contactImportConfirmationStale:
            String(localized: "error.contactImportConfirmationStale", defaultValue: "Contacts changed while this import was open. Review the key again before adding it.")
        case .contactImportConfirmationAlreadyPending:
            String(localized: "error.contactImportConfirmationAlreadyPending", defaultValue: "Finish or cancel the current contact import before opening another one.")
        }
    }

    /// What the user can do about it, for the failures where that is a real
    /// question rather than a restatement. `nil` everywhere else — an empty
    /// suggestion is worse than none.
    var recoverySuggestion: String? {
        switch self {
        case .argon2idMemoryExceeded:
            // The memory figure is the limit minus the app's current footprint,
            // so this refusal is a snapshot: freeing memory really can change
            // the answer, and saying so is the only useful thing to offer.
            String(localized: "error.argon2idMemory.recovery", defaultValue: "Close other apps, then try again. If it keeps happening, restart the device.")
        default:
            nil
        }
    }

    /// Renders an Argon2id memory requirement the way people read memory —
    /// "2 GB", not "2048 MB" — and degrades sensibly for the arbitrary figures
    /// a foreign key may declare (1536 MB reads as "1.5 GB").
    private static func memorySize(megabytes: UInt64) -> String {
        // A malformed key can declare a requirement that overflows on the way
        // back to bytes; clamp rather than trap, since this is error copy.
        let (bytes, overflowed) = megabytes.multipliedReportingOverflow(by: 1024 * 1024)
        return Int64(clamping: overflowed ? UInt64.max : bytes)
            .formatted(.byteCount(style: .memory))
    }

    /// Per-category copy for key-operation availability failures. Exhaustive on
    /// purpose — no `default` — so a new sanitized category cannot ship without
    /// its own user-facing copy.
    private static func keyOperationUnavailableDescription(
        for category: PGPKeyOperationFailureCategory
    ) -> String {
        switch category {
        case .invalidFamilyCustody:
            String(localized: "error.keyOperationUnavailable.invalidFamilyCustody", defaultValue: "This key's family and custody settings don't match, so the operation is unavailable.")
        case .operationUnsupportedForCustody:
            String(localized: "error.keyOperationUnavailable.operationUnsupportedForCustody", defaultValue: "This operation is not supported for this key's custody model.")
        case .operationNotImplementedForCustody:
            String(localized: "error.keyOperationUnavailable.operationNotImplementedForCustody", defaultValue: "This operation is not yet available for device-bound keys.")
        case .operationUnavailableByPolicy:
            String(localized: "error.keyOperationUnavailable.operationUnavailableByPolicy", defaultValue: "This operation is currently unavailable.")
        case .hardwareUnavailable:
            String(localized: "error.keyOperationUnavailable.hardwareUnavailable", defaultValue: "The Secure Enclave is not available on this device.")
        case .localAuthenticationRequired:
            String(localized: "error.keyOperationUnavailable.localAuthenticationRequired", defaultValue: "Authentication is required to use this key.")
        case .localAuthenticationCancelled:
            String(localized: "error.keyOperationUnavailable.localAuthenticationCancelled", defaultValue: "Authentication was cancelled. Nothing was changed.")
        case .localAuthenticationFailed:
            String(localized: "error.keyOperationUnavailable.localAuthenticationFailed", defaultValue: "Authentication failed. Please try again.")
        case .localAuthenticationUnavailable:
            String(localized: "error.keyOperationUnavailable.localAuthenticationUnavailable", defaultValue: "Biometric authentication is currently unavailable, so this key cannot be used right now.")
        case .localAuthenticationLockedOut:
            String(localized: "error.keyOperationUnavailable.localAuthenticationLockedOut", defaultValue: "Biometric authentication is locked. Unlock it on this device, then try again.")
        case .privateHandleMissing:
            String(localized: "error.keyOperationUnavailable.privateHandleMissing", defaultValue: "This key's private key material is missing from this device.")
        case .privateHandleInaccessible:
            String(localized: "error.keyOperationUnavailable.privateHandleInaccessible", defaultValue: "This key's private key material could not be accessed.")
        case .privateHandleUnauthorized:
            String(localized: "error.keyOperationUnavailable.privateHandleUnauthorized", defaultValue: "Access to this key's private key material was not authorized.")
        case .privateOperationRoleMismatch:
            String(localized: "error.keyOperationUnavailable.privateOperationRoleMismatch", defaultValue: "This key cannot perform the requested operation.")
        case .handlePublicKeyBindingMismatch:
            String(localized: "error.keyOperationUnavailable.handlePublicKeyBindingMismatch", defaultValue: "This key's device-bound private key does not match its certificate.")
        case .classicalComponentFailed:
            String(localized: "error.keyOperationUnavailable.classicalComponentFailed", defaultValue: "This key's software key component is damaged or does not match its certificate.")
        case .metadataAssociationMismatch:
            String(localized: "error.keyOperationUnavailable.metadataAssociationMismatch", defaultValue: "Stored key information does not match this key.")
        case .publicCertificateAssociationMismatch:
            String(localized: "error.keyOperationUnavailable.publicCertificateAssociationMismatch", defaultValue: "This key's stored certificate does not match its key information.")
        case .publicMaterialUnavailable:
            String(localized: "error.keyOperationUnavailable.publicMaterialUnavailable", defaultValue: "This key's public certificate is unavailable.")
        case .revocationArtifactUnavailable:
            String(localized: "error.keyOperationUnavailable.revocationArtifactUnavailable", defaultValue: "No revocation certificate is stored for this key.")
        case .externalOperationInvalidRequest:
            String(localized: "error.keyOperationUnavailable.externalOperationInvalidRequest", defaultValue: "The Secure Enclave operation request was invalid.")
        case .externalOperationInvalidResponse:
            String(localized: "error.keyOperationUnavailable.externalOperationInvalidResponse", defaultValue: "The Secure Enclave returned an invalid response.")
        case .externalOperationFailed:
            String(localized: "error.keyOperationUnavailable.externalOperationFailed", defaultValue: "The Secure Enclave operation failed.")
        case .openPGPSemanticFailure:
            String(localized: "error.keyOperationUnavailable.openPGPSemanticFailure", defaultValue: "The OpenPGP operation failed.")
        case .recoveryRequired:
            String(localized: "error.keyOperationUnavailable.recoveryRequired", defaultValue: "This key needs recovery before it can be used.")
        case .cleanupOrRollbackFailure:
            String(localized: "error.keyOperationUnavailable.cleanupOrRollbackFailure", defaultValue: "The operation failed and cleanup could not complete.")
        }
    }
}
