use crate::keys::{
    ExternalCompositeKeyAgreementFailureCategory, ExternalCompositeSigningFailureCategory,
    ExternalP256KeyAgreementFailureCategory, ExternalP256SigningFailureCategory,
};

/// PGP error types exposed across the FFI boundary.
///
/// Each variant is normalized into a Swift `CypherAirError` case at the
/// `Services/FFI` adapter boundary; the user-facing copy for that case is owned
/// by the String Catalog, not by these messages.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PgpError {
    /// Key generation failed.
    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    /// The provided key data is invalid or corrupt.
    #[error("Invalid key data: {reason}")]
    InvalidKeyData { reason: String },

    /// No matching secret key found for decryption.
    #[error("No matching key found for decryption")]
    NoMatchingKey,

    /// AEAD authentication failed — message may have been tampered with.
    /// HARD-FAIL: never show partial plaintext.
    #[error("AEAD authentication failed — message may have been tampered with")]
    AeadAuthenticationFailed,

    /// MDC (Modification Detection Code) verification failed.
    /// Similar to AEAD failure but for SEIPDv1 messages.
    #[error("Message integrity check failed — message may have been tampered with")]
    IntegrityCheckFailed,

    /// Signature verification failed — a cryptographic verdict.
    #[error("Signature verification failed")]
    BadSignature,

    /// The verification machinery could not be started, so no signature was
    /// ever checked. Distinct from `BadSignature` on purpose: a failure to
    /// *perform* a check must never be presented as a statement about the
    /// signature.
    #[error("Signature verification could not be performed: {reason}")]
    VerificationSetupFailed { reason: String },

    /// Signer's key is not in contacts.
    #[error("Unknown signer")]
    UnknownSigner,

    /// The key has expired.
    #[error("Key has expired")]
    KeyExpired,

    /// Unsupported algorithm or message format.
    #[error("Unsupported algorithm: {algo}")]
    UnsupportedAlgorithm { algo: String },

    /// Corrupt or unparseable data.
    #[error("Corrupt data: {reason}")]
    CorruptData { reason: String },

    /// Wrong passphrase for key import/unlock.
    #[error("Wrong passphrase")]
    WrongPassphrase,

    /// Encryption failed.
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    /// Signing failed.
    #[error("Signing failed: {reason}")]
    SigningFailed { reason: String },

    /// External P-256 signing failed with a sanitized callback category.
    #[error("External P-256 signing failed: {}", category.stable_reason())]
    ExternalP256SigningFailed {
        category: ExternalP256SigningFailureCategory,
    },

    /// External P-256 key agreement failed with a sanitized callback category.
    #[error("External P-256 key agreement failed: {}", category.stable_reason())]
    ExternalP256KeyAgreementFailed {
        category: ExternalP256KeyAgreementFailureCategory,
    },

    /// External composite (ML-DSA-65 + Ed25519) signing failed with a sanitized callback category.
    #[error("External composite signing failed: {}", category.stable_reason())]
    ExternalCompositeSigningFailed {
        category: ExternalCompositeSigningFailureCategory,
    },

    /// External composite (ML-KEM-768 + X25519) key agreement failed with a sanitized callback category.
    #[error("External composite key agreement failed: {}", category.stable_reason())]
    ExternalCompositeKeyAgreementFailed {
        category: ExternalCompositeKeyAgreementFailureCategory,
    },

    /// Armor encoding/decoding error.
    #[error("Armor error: {reason}")]
    ArmorError { reason: String },

    /// S2K (passphrase derivation) error.
    #[error("S2K error: {reason}")]
    S2kError { reason: String },

    /// Argon2id memory requirement exceeds device capacity.
    #[error("Argon2id memory requirement ({required_mb} MB) exceeds device capacity")]
    Argon2idMemoryExceeded { required_mb: u64 },

    /// Revocation certificate error.
    #[error("Revocation error: {reason}")]
    RevocationError { reason: String },

    /// Internal error — should not happen in normal operation.
    #[error("Internal error: {reason}")]
    InternalError { reason: String },

    /// Operation was cancelled by the user (via progress callback returning false).
    #[error("Operation cancelled")]
    OperationCancelled,

    /// File I/O error (path not found, permission denied, etc.).
    #[error("File I/O error: {reason}")]
    FileIoError { reason: String },

    /// A write ran out of space on the destination volume. Its own variant so
    /// the app can present the out-of-space message it already shows when the
    /// pre-flight check refuses, instead of a raw OS error string.
    #[error("Not enough free space to write the output file")]
    StorageFull,

    /// Public key data is too large to encode as a QR code.
    /// The QR code standard has a maximum capacity; keys with many accumulated
    /// signatures (e.g., from repeated expiry modifications) may exceed this limit.
    #[error("Key too large for QR code: {size_bytes} bytes exceeds maximum {max_bytes} bytes")]
    KeyTooLargeForQr { size_bytes: u64, max_bytes: u64 },
}

// NOTE: There is intentionally NO blanket `From<anyhow::Error> for PgpError` impl.
// All Sequoia anyhow::Error results must be mapped to specific PgpError variants via
// explicit .map_err() calls. This prevents the ? operator from silently converting
// errors to InternalError, which would bypass classify_decrypt_error() and potentially
// misclassify AEAD/MDC/wrong-key errors.
