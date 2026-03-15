/// PGP error types exposed across the FFI boundary.
/// Each variant maps 1:1 to a Swift `CypherAirError` enum case (via UniFFI-generated `PgpError`).
/// See PRD Section 4.7 for user-facing error messages.

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PgpError {
    /// Key generation failed.
    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    /// The provided key data is invalid or corrupt.
    #[error("Invalid key data: {reason}")]
    InvalidKeyData { reason: String },

    /// No matching secret key found for decryption.
    /// PRD: "Not addressed to your identities."
    #[error("No matching key found for decryption")]
    NoMatchingKey,

    /// AEAD authentication failed — message may have been tampered with.
    /// PRD: "May have been tampered with." HARD-FAIL: never show partial plaintext.
    #[error("AEAD authentication failed — message may have been tampered with")]
    AeadAuthenticationFailed,

    /// MDC (Modification Detection Code) verification failed.
    /// Similar to AEAD failure but for SEIPDv1 messages.
    #[error("Message integrity check failed — message may have been tampered with")]
    IntegrityCheckFailed,

    /// Signature verification failed.
    /// PRD: "Content may have been modified."
    #[error("Signature verification failed")]
    BadSignature,

    /// Signer's key is not in contacts.
    /// PRD: "Signer not in Contacts."
    #[error("Unknown signer")]
    UnknownSigner,

    /// The key has expired.
    /// PRD: "Ask sender to update."
    #[error("Key has expired")]
    KeyExpired,

    /// Unsupported algorithm or message format.
    /// PRD: "Method not supported."
    #[error("Unsupported algorithm: {algo}")]
    UnsupportedAlgorithm { algo: String },

    /// Corrupt or unparseable data.
    /// PRD: "Damaged. Ask sender to resend."
    #[error("Corrupt data: {reason}")]
    CorruptData { reason: String },

    /// Wrong passphrase for key import/unlock.
    /// PRD: "Re-enter backup passphrase."
    #[error("Wrong passphrase")]
    WrongPassphrase,

    /// Encryption failed.
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    /// Signing failed.
    #[error("Signing failed: {reason}")]
    SigningFailed { reason: String },

    /// Armor encoding/decoding error.
    #[error("Armor error: {reason}")]
    ArmorError { reason: String },

    /// S2K (passphrase derivation) error.
    #[error("S2K error: {reason}")]
    S2kError { reason: String },

    /// Argon2id memory requirement exceeds device capacity.
    /// PRD: "This key uses memory-intensive protection that exceeds this device's capacity."
    #[error("Argon2id memory requirement ({required_mb} MB) exceeds device capacity")]
    Argon2idMemoryExceeded { required_mb: u64 },

    /// Revocation certificate error.
    #[error("Revocation error: {reason}")]
    RevocationError { reason: String },

    /// Internal error — should not happen in normal operation.
    #[error("Internal error: {reason}")]
    InternalError { reason: String },
}

// NOTE: There is intentionally NO blanket `From<anyhow::Error> for PgpError` impl.
// All Sequoia anyhow::Error results must be mapped to specific PgpError variants via
// explicit .map_err() calls. This prevents the ? operator from silently converting
// errors to InternalError, which would bypass classify_decrypt_error() and potentially
// misclassify AEAD/MDC/wrong-key errors. See security audit finding H1.
