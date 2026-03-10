//! pgp-mobile: OpenPGP wrapper for Cypher Air iOS app.
//!
//! Wraps Sequoia PGP 2.2.0 behind a UniFFI-annotated API.
//! Exposes profile-aware operations for dual-profile (A/B) encryption.
//! All Sequoia internal types are hidden behind this boundary.

pub mod armor;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod keys;
pub mod sign;
pub mod verify;

use crate::armor::ArmorKind;
use crate::decrypt::DecryptResult;
use crate::error::PgpError;
use crate::keys::{GeneratedKey, KeyInfo, KeyProfile};
use crate::verify::VerifyResult;

uniffi::setup_scaffolding!();

/// The main PGP engine object exposed across the FFI boundary.
/// Stateless — all operations are pure functions on the input data.
/// Thread-safe (Send + Sync).
#[derive(uniffi::Object)]
pub struct PgpEngine;

#[uniffi::export]
impl PgpEngine {
    /// Create a new PGP engine instance.
    #[uniffi::constructor]
    pub fn new() -> Self {
        PgpEngine
    }

    // ── Key Generation ──────────────────────────────────────────────

    /// Generate a new key pair with the specified profile.
    ///
    /// - Profile A (Universal): v4 key, Ed25519+X25519, GnuPG compatible.
    /// - Profile B (Advanced): v6 key, Ed448+X448, RFC 9580.
    pub fn generate_key(
        &self,
        name: String,
        email: Option<String>,
        expiry_seconds: Option<u64>,
        profile: KeyProfile,
    ) -> Result<GeneratedKey, PgpError> {
        keys::generate_key_with_profile(name, email, expiry_seconds, profile)
    }

    // ── Key Information ─────────────────────────────────────────────

    /// Parse a key and extract information (fingerprint, version, User ID, etc.).
    pub fn parse_key_info(&self, key_data: Vec<u8>) -> Result<KeyInfo, PgpError> {
        keys::parse_key_info(&key_data)
    }

    /// Get the key version from binary certificate data.
    pub fn get_key_version(&self, cert_data: Vec<u8>) -> Result<u8, PgpError> {
        keys::get_key_version(&cert_data)
    }

    /// Detect the profile of a key (Universal or Advanced).
    pub fn detect_profile(&self, cert_data: Vec<u8>) -> Result<KeyProfile, PgpError> {
        keys::detect_profile(&cert_data)
    }

    // ── Encryption ──────────────────────────────────────────────────

    /// Encrypt plaintext for recipients. Returns ASCII-armored ciphertext.
    ///
    /// Message format is auto-selected by recipient key versions:
    /// - All v4 → SEIPDv1 (MDC)
    /// - All v6 → SEIPDv2 (AEAD OCB)
    /// - Mixed → SEIPDv1
    pub fn encrypt(
        &self,
        plaintext: Vec<u8>,
        recipients: Vec<Vec<u8>>,
        signing_key: Option<Vec<u8>>,
        encrypt_to_self: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, PgpError> {
        encrypt::encrypt(
            &plaintext,
            &recipients,
            signing_key.as_deref(),
            encrypt_to_self.as_deref(),
        )
    }

    /// Encrypt plaintext and return binary ciphertext (.gpg format).
    pub fn encrypt_binary(
        &self,
        plaintext: Vec<u8>,
        recipients: Vec<Vec<u8>>,
        signing_key: Option<Vec<u8>>,
        encrypt_to_self: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, PgpError> {
        encrypt::encrypt_binary(
            &plaintext,
            &recipients,
            signing_key.as_deref(),
            encrypt_to_self.as_deref(),
        )
    }

    // ── Decryption ──────────────────────────────────────────────────

    /// Parse recipients of an encrypted message (Phase 1 — no auth needed).
    /// Returns recipient key IDs as hex strings.
    pub fn parse_recipients(&self, ciphertext: Vec<u8>) -> Result<Vec<String>, PgpError> {
        decrypt::parse_recipients(&ciphertext)
    }

    /// Decrypt a message (Phase 2 — requires authenticated key access).
    /// Handles both SEIPDv1 and SEIPDv2. AEAD/MDC failure → hard-fail.
    pub fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        secret_keys: Vec<Vec<u8>>,
        verification_keys: Vec<Vec<u8>>,
    ) -> Result<DecryptResult, PgpError> {
        decrypt::decrypt(&ciphertext, &secret_keys, &verification_keys)
    }

    // ── Signing ─────────────────────────────────────────────────────

    /// Create a cleartext signature for text.
    pub fn sign_cleartext(
        &self,
        text: Vec<u8>,
        signer_cert: Vec<u8>,
    ) -> Result<Vec<u8>, PgpError> {
        sign::sign_cleartext(&text, &signer_cert)
    }

    /// Create a detached signature for data (files).
    pub fn sign_detached(
        &self,
        data: Vec<u8>,
        signer_cert: Vec<u8>,
    ) -> Result<Vec<u8>, PgpError> {
        sign::sign_detached(&data, &signer_cert)
    }

    // ── Verification ────────────────────────────────────────────────

    /// Verify a cleartext-signed message.
    pub fn verify_cleartext(
        &self,
        signed_message: Vec<u8>,
        verification_keys: Vec<Vec<u8>>,
    ) -> Result<VerifyResult, PgpError> {
        verify::verify_cleartext(&signed_message, &verification_keys)
    }

    /// Verify a detached signature.
    pub fn verify_detached(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
        verification_keys: Vec<Vec<u8>>,
    ) -> Result<VerifyResult, PgpError> {
        verify::verify_detached(&data, &signature, &verification_keys)
    }

    // ── Key Export/Import ────────────────────────────────────────────

    /// Export a secret key protected with a passphrase (ASCII-armored).
    /// Profile A → Iterated+Salted S2K. Profile B → Argon2id.
    pub fn export_secret_key(
        &self,
        cert_data: Vec<u8>,
        passphrase: String,
        profile: KeyProfile,
    ) -> Result<Vec<u8>, PgpError> {
        keys::export_secret_key(&cert_data, &passphrase, profile)
    }

    /// Import a passphrase-protected secret key.
    /// Auto-detects S2K mode (Iterated+Salted or Argon2id).
    pub fn import_secret_key(
        &self,
        armored_data: Vec<u8>,
        passphrase: String,
    ) -> Result<Vec<u8>, PgpError> {
        keys::import_secret_key(&armored_data, &passphrase)
    }

    // ── Revocation ──────────────────────────────────────────────────

    /// Parse and validate a revocation certificate.
    pub fn parse_revocation_cert(
        &self,
        rev_data: Vec<u8>,
    ) -> Result<String, PgpError> {
        keys::parse_revocation_cert(&rev_data)
    }

    // ── Armor ───────────────────────────────────────────────────────

    /// Armor binary data into ASCII format.
    pub fn armor(&self, data: Vec<u8>, kind: ArmorKind) -> Result<Vec<u8>, PgpError> {
        armor::encode_armor(&data, kind)
    }

    /// Dearmor ASCII-armored data into binary format.
    pub fn dearmor(&self, armored: Vec<u8>) -> Result<Vec<u8>, PgpError> {
        let (data, _kind) = armor::decode_armor(&armored)?;
        Ok(data)
    }

    /// Armor a public key certificate.
    pub fn armor_public_key(&self, cert_data: Vec<u8>) -> Result<Vec<u8>, PgpError> {
        armor::armor_public_key(&cert_data)
    }

    // ── QR / URL Scheme ─────────────────────────────────────────────

    /// Encode a public key for QR code URL scheme.
    /// Format: cypherair://import/v1/<base64url, no padding>
    pub fn encode_qr_url(&self, public_key_data: Vec<u8>) -> Result<String, PgpError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let encoded = URL_SAFE_NO_PAD.encode(&public_key_data);
        Ok(format!("cypherair://import/v1/{encoded}"))
    }

    /// Decode a QR code URL and extract the public key.
    /// Validates the URL format and parses the key.
    pub fn decode_qr_url(&self, url: String) -> Result<Vec<u8>, PgpError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let prefix = "cypherair://import/v1/";
        if !url.starts_with(prefix) {
            return Err(PgpError::CorruptData {
                reason: "Not a valid Cypher Air URL. Expected cypherair://import/v1/...".to_string(),
            });
        }

        let b64_data = &url[prefix.len()..];
        let key_bytes = URL_SAFE_NO_PAD.decode(b64_data).map_err(|e| {
            PgpError::CorruptData {
                reason: format!("Invalid base64url data: {e}"),
            }
        })?;

        // Validate that it's a valid OpenPGP public key
        let _key_info = keys::parse_key_info(&key_bytes)?;

        Ok(key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = PgpEngine::new();
        // Engine is stateless, just verify it can be created
        assert!(true);
    }
}
