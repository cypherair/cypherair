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
        case .keyOperationUnavailable(let category):
            Self.keyOperationUnavailableDescription(for: category)
        case .secureEnclaveUnavailable:
            String(localized: "error.seUnavailable", defaultValue: "Secure Enclave is not available on this device.")
        case .authenticationFailed:
            String(localized: "error.authFailed", defaultValue: "Authentication failed.")
        case .authenticationCancelled:
            String(localized: "error.authCancelled", defaultValue: "Authentication was cancelled.")
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
        case .contactImportConfirmationStale:
            String(localized: "error.contactImportConfirmationStale", defaultValue: "Contacts changed while this import was open. Review the key again before adding it.")
        case .contactImportConfirmationAlreadyPending:
            String(localized: "error.contactImportConfirmationAlreadyPending", defaultValue: "Finish or cancel the current contact import before opening another one.")
        }
    }

    /// Per-category copy for key-operation availability failures. Exhaustive on
    /// purpose — no `default` — so a new sanitized category cannot ship without
    /// its own user-facing copy.
    private static func keyOperationUnavailableDescription(
        for category: PGPKeyOperationFailureCategory
    ) -> String {
        switch category {
        case .invalidConfigurationCustody:
            String(localized: "error.keyOperationUnavailable.invalidConfigurationCustody", defaultValue: "This key's configuration and custody settings don't match, so the operation is unavailable.")
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
        case .payloadAuthenticationFailure:
            String(localized: "error.keyOperationUnavailable.payloadAuthenticationFailure", defaultValue: "Message authentication failed. The content may have been tampered with.")
        case .migrationOrRecoveryRequired:
            String(localized: "error.keyOperationUnavailable.migrationOrRecoveryRequired", defaultValue: "This key needs recovery before it can be used.")
        case .prohibitedFallbackAttempted:
            String(localized: "error.keyOperationUnavailable.prohibitedFallbackAttempted", defaultValue: "A prohibited fallback was blocked. Nothing was changed.")
        case .cleanupOrRollbackFailure:
            String(localized: "error.keyOperationUnavailable.cleanupOrRollbackFailure", defaultValue: "The operation failed and cleanup could not complete.")
        }
    }
}
