//! pgp-mobile: OpenPGP wrapper for CypherAir iOS app.
//!
//! Wraps Sequoia PGP 2.2.0 behind a UniFFI-annotated API.
//! Exposes profile-aware operations for dual-profile (A/B) encryption.
//! All Sequoia internal types are hidden behind this boundary.

pub mod armor;
pub mod cert_signature;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod keys;
pub mod password;
mod qr_url;
pub mod sign;
pub mod signature_details;
pub mod streaming;
pub mod verify;

use std::sync::Arc;

use openpgp::crypto::Password;
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use crate::armor::ArmorKind;
use crate::cert_signature::{CertificateSignatureResult, CertificationKind};
use crate::error::PgpError;
use crate::keys::{
    CertificateMergeResult, DiscoveredCertificateSelectors, GeneratedKey, KeyInfo, KeyProfile,
    ModifyExpiryResult, PublicCertificateValidationResult, S2kInfo, UserIdSelectorInput,
};
use crate::password::{PasswordDecryptResult, PasswordMessageFormat};
use crate::signature_details::{
    DecryptDetailedResult, FileDecryptDetailedResult, FileVerifyDetailedResult,
    VerifyDetailedResult,
};

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

    /// Discover selector-bearing subkey and User ID metadata from binary certificate bytes.
    ///
    /// This API is binary-only by contract. ASCII-armored certificate input is rejected.
    pub fn discover_certificate_selectors(
        &self,
        cert_data: Vec<u8>,
    ) -> Result<DiscoveredCertificateSelectors, PgpError> {
        keys::discover_certificate_selectors(&cert_data)
    }

    /// Get the key version from binary certificate data.
    pub fn get_key_version(&self, cert_data: Vec<u8>) -> Result<u8, PgpError> {
        keys::get_key_version(&cert_data)
    }

    /// Detect the profile of a key (Universal or Advanced).
    pub fn detect_profile(&self, cert_data: Vec<u8>) -> Result<KeyProfile, PgpError> {
        keys::detect_profile(&cert_data)
    }

    /// Validate contact-import data as a public certificate and return normalized metadata.
    ///
    /// Secret-bearing input is rejected with `InvalidKeyData` using a stable reason token.
    pub fn validate_public_certificate(
        &self,
        cert_data: Vec<u8>,
    ) -> Result<PublicCertificateValidationResult, PgpError> {
        keys::validate_public_certificate(&cert_data)
    }

    // ── Certificate Merge / Update ──────────────────────────────────

    /// Merge same-fingerprint public certificate update material into an existing public certificate.
    ///
    /// Both inputs must be binary OpenPGP public certificate bytes. Secret-bearing
    /// input and fingerprint mismatches are rejected with `InvalidKeyData`.
    pub fn merge_public_certificate_update(
        &self,
        existing_cert: Vec<u8>,
        incoming_cert_or_update: Vec<u8>,
    ) -> Result<CertificateMergeResult, PgpError> {
        keys::merge_public_certificate_update(&existing_cert, &incoming_cert_or_update)
    }

    // ── Key Modification ──────────────────────────────────────────────

    /// Modify the expiration time of an existing certificate.
    /// Requires the full certificate (with secret key material) to re-sign binding signatures.
    ///
    /// SECURITY: Output `cert_data` contains unencrypted secret key material.
    /// The Swift caller must SE-wrap it immediately and zeroize after wrapping.
    pub fn modify_expiry(
        &self,
        cert_data: Vec<u8>,
        new_expiry_seconds: Option<u64>,
    ) -> Result<ModifyExpiryResult, PgpError> {
        let cert_data = Zeroizing::new(cert_data);
        keys::modify_expiry(&cert_data, new_expiry_seconds)
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
        let signing_key = signing_key.map(Zeroizing::new);
        encrypt::encrypt(
            &plaintext,
            &recipients,
            signing_key.as_ref().map(|z| z.as_slice()),
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
        let signing_key = signing_key.map(Zeroizing::new);
        encrypt::encrypt_binary(
            &plaintext,
            &recipients,
            signing_key.as_ref().map(|z| z.as_slice()),
            encrypt_to_self.as_deref(),
        )
    }

    /// Encrypt plaintext with a password and return ASCII-armored ciphertext.
    pub fn encrypt_with_password(
        &self,
        plaintext: Vec<u8>,
        password: String,
        format: PasswordMessageFormat,
        signing_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, PgpError> {
        let password = Password::from(password);
        let signing_key = signing_key.map(Zeroizing::new);
        password::encrypt(
            &plaintext,
            &password,
            format,
            signing_key.as_ref().map(|z| z.as_slice()),
        )
    }

    /// Encrypt plaintext with a password and return binary ciphertext.
    pub fn encrypt_binary_with_password(
        &self,
        plaintext: Vec<u8>,
        password: String,
        format: PasswordMessageFormat,
        signing_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, PgpError> {
        let password = Password::from(password);
        let signing_key = signing_key.map(Zeroizing::new);
        password::encrypt_binary(
            &plaintext,
            &password,
            format,
            signing_key.as_ref().map(|z| z.as_slice()),
        )
    }

    // ── Decryption ──────────────────────────────────────────────────

    /// Parse recipients of an encrypted message (Phase 1 — no auth needed).
    /// Returns recipient key IDs as hex strings.
    ///
    /// NOTE: These are encryption *subkey* identifiers from PKESK packets, not primary
    /// key fingerprints. For matching against local keys, use `match_recipients` instead.
    pub fn parse_recipients(&self, ciphertext: Vec<u8>) -> Result<Vec<String>, PgpError> {
        decrypt::parse_recipients(&ciphertext)
    }

    /// Match PKESK recipients against local certificates (Phase 1 — no auth needed).
    /// Returns primary fingerprints of matching certificates (lowercase hex).
    ///
    /// PKESK packets contain encryption subkey identifiers, not primary key fingerprints.
    /// This function uses Sequoia's key_handles() to correctly match subkey IDs against
    /// certificates, then returns the primary fingerprint of each matched certificate.
    /// Only public key data is needed — no secret keys, no authentication.
    pub fn match_recipients(
        &self,
        ciphertext: Vec<u8>,
        local_certs: Vec<Vec<u8>>,
    ) -> Result<Vec<String>, PgpError> {
        decrypt::match_recipients(&ciphertext, &local_certs)
    }

    /// Decrypt a message and preserve per-signature detailed results.
    pub fn decrypt_detailed(
        &self,
        ciphertext: Vec<u8>,
        secret_keys: Vec<Vec<u8>>,
        verification_keys: Vec<Vec<u8>>,
    ) -> Result<DecryptDetailedResult, PgpError> {
        let secret_keys: Vec<Zeroizing<Vec<u8>>> =
            secret_keys.into_iter().map(Zeroizing::new).collect();
        decrypt::decrypt_detailed(&ciphertext, &secret_keys, &verification_keys)
    }

    /// Decrypt a password-encrypted message without falling back to recipient-key decryption.
    pub fn decrypt_with_password(
        &self,
        ciphertext: Vec<u8>,
        password: String,
        verification_keys: Vec<Vec<u8>>,
    ) -> Result<PasswordDecryptResult, PgpError> {
        let password = Password::from(password);
        password::decrypt(&ciphertext, &password, &verification_keys)
    }

    // ── Signing ─────────────────────────────────────────────────────

    /// Create a cleartext signature for text.
    pub fn sign_cleartext(&self, text: Vec<u8>, signer_cert: Vec<u8>) -> Result<Vec<u8>, PgpError> {
        let signer_cert = Zeroizing::new(signer_cert);
        sign::sign_cleartext(&text, &signer_cert)
    }

    /// Create a detached signature for data (files).
    pub fn sign_detached(&self, data: Vec<u8>, signer_cert: Vec<u8>) -> Result<Vec<u8>, PgpError> {
        let signer_cert = Zeroizing::new(signer_cert);
        sign::sign_detached(&data, &signer_cert)
    }

    // ── Verification ────────────────────────────────────────────────

    /// Verify a cleartext-signed message and preserve per-signature detailed results.
    pub fn verify_cleartext_detailed(
        &self,
        signed_message: Vec<u8>,
        verification_keys: Vec<Vec<u8>>,
    ) -> Result<VerifyDetailedResult, PgpError> {
        verify::verify_cleartext_detailed(&signed_message, &verification_keys)
    }

    /// Verify a detached signature and preserve per-signature detailed results.
    pub fn verify_detached_detailed(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
        verification_keys: Vec<Vec<u8>>,
    ) -> Result<VerifyDetailedResult, PgpError> {
        verify::verify_detached_detailed(&data, &signature, &verification_keys)
    }

    // ── Certificate Signature Verification ────────────────────────

    /// Verify a direct-key signature against a target certificate using crypto-only semantics.
    pub fn verify_direct_key_signature(
        &self,
        signature: Vec<u8>,
        target_cert: Vec<u8>,
        candidate_signers: Vec<Vec<u8>>,
    ) -> Result<CertificateSignatureResult, PgpError> {
        cert_signature::verify_direct_key_signature(&signature, &target_cert, &candidate_signers)
    }

    /// Verify a User ID binding signature against an explicitly selected User ID occurrence.
    pub fn verify_user_id_binding_signature_by_selector(
        &self,
        signature: Vec<u8>,
        target_cert: Vec<u8>,
        user_id_selector: UserIdSelectorInput,
        candidate_signers: Vec<Vec<u8>>,
    ) -> Result<CertificateSignatureResult, PgpError> {
        cert_signature::verify_user_id_binding_signature_by_selector(
            &signature,
            &target_cert,
            &user_id_selector,
            &candidate_signers,
        )
    }

    /// Generate raw certification-signature bytes for an explicitly selected User ID occurrence.
    pub fn generate_user_id_certification_by_selector(
        &self,
        signer_secret_cert: Vec<u8>,
        target_cert: Vec<u8>,
        user_id_selector: UserIdSelectorInput,
        certification_kind: CertificationKind,
    ) -> Result<Vec<u8>, PgpError> {
        let signer_secret_cert = Zeroizing::new(signer_secret_cert);
        cert_signature::generate_user_id_certification_by_selector(
            &signer_secret_cert,
            &target_cert,
            &user_id_selector,
            certification_kind,
        )
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
        let cert_data = Zeroizing::new(cert_data);
        keys::export_secret_key(&cert_data, &passphrase, profile)
    }

    /// Parse S2K parameters from a passphrase-protected key without importing it.
    /// Use this to check Argon2id memory requirements before calling import_secret_key.
    /// Returns S2K type, memory requirement (KiB), parallelism, and time passes.
    pub fn parse_s2k_params(&self, armored_data: Vec<u8>) -> Result<S2kInfo, PgpError> {
        keys::parse_s2k_params(&armored_data)
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

    /// Parse and cryptographically verify a revocation certificate against the target key.
    pub fn parse_revocation_cert(
        &self,
        rev_data: Vec<u8>,
        cert_data: Vec<u8>,
    ) -> Result<String, PgpError> {
        let cert_data = Zeroizing::new(cert_data);
        keys::parse_revocation_cert(&rev_data, &cert_data)
    }

    /// Generate a key-level revocation signature from an existing secret certificate.
    pub fn generate_key_revocation(&self, secret_cert: Vec<u8>) -> Result<Vec<u8>, PgpError> {
        let secret_cert = Zeroizing::new(secret_cert);
        keys::generate_key_revocation(&secret_cert)
    }

    /// Generate a subkey-specific revocation signature from an existing secret certificate.
    pub fn generate_subkey_revocation(
        &self,
        secret_cert: Vec<u8>,
        subkey_fingerprint: String,
    ) -> Result<Vec<u8>, PgpError> {
        let secret_cert = Zeroizing::new(secret_cert);
        keys::generate_subkey_revocation(&secret_cert, &subkey_fingerprint)
    }

    /// Generate a User ID-specific revocation signature using an explicit selector.
    pub fn generate_user_id_revocation_by_selector(
        &self,
        secret_cert: Vec<u8>,
        user_id_selector: UserIdSelectorInput,
    ) -> Result<Vec<u8>, PgpError> {
        let secret_cert = Zeroizing::new(secret_cert);
        keys::generate_user_id_revocation_by_selector(&secret_cert, &user_id_selector)
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

    // ── Streaming File Operations ──────────────────────────────────────

    /// Encrypt a file using streaming I/O. Constant memory usage.
    /// Output is binary (.gpg format). Message format auto-selected by recipient key versions.
    pub fn encrypt_file(
        &self,
        input_path: String,
        output_path: String,
        recipients: Vec<Vec<u8>>,
        signing_key: Option<Vec<u8>>,
        encrypt_to_self: Option<Vec<u8>>,
        progress: Option<Arc<dyn streaming::ProgressReporter>>,
    ) -> Result<(), PgpError> {
        let signing_key = signing_key.map(Zeroizing::new);
        streaming::encrypt_file(
            &input_path,
            &output_path,
            &recipients,
            signing_key.as_ref().map(|z| z.as_slice()),
            encrypt_to_self.as_deref(),
            progress,
        )
    }

    /// Decrypt a file using streaming I/O and preserve per-signature detailed results.
    pub fn decrypt_file_detailed(
        &self,
        input_path: String,
        output_path: String,
        secret_keys: Vec<Vec<u8>>,
        verification_keys: Vec<Vec<u8>>,
        progress: Option<Arc<dyn streaming::ProgressReporter>>,
    ) -> Result<FileDecryptDetailedResult, PgpError> {
        let secret_keys: Vec<Zeroizing<Vec<u8>>> =
            secret_keys.into_iter().map(Zeroizing::new).collect();
        streaming::decrypt_file_detailed(
            &input_path,
            &output_path,
            &secret_keys,
            &verification_keys,
            progress,
        )
    }

    /// Create a detached signature for a file using streaming I/O.
    /// Returns the ASCII-armored signature.
    pub fn sign_detached_file(
        &self,
        input_path: String,
        signer_cert: Vec<u8>,
        progress: Option<Arc<dyn streaming::ProgressReporter>>,
    ) -> Result<Vec<u8>, PgpError> {
        let signer_cert = Zeroizing::new(signer_cert);
        streaming::sign_detached_file(&input_path, &signer_cert, progress)
    }

    /// Verify a detached file signature using streaming I/O and preserve per-signature details.
    pub fn verify_detached_file_detailed(
        &self,
        data_path: String,
        signature: Vec<u8>,
        verification_keys: Vec<Vec<u8>>,
        progress: Option<Arc<dyn streaming::ProgressReporter>>,
    ) -> Result<FileVerifyDetailedResult, PgpError> {
        streaming::verify_detached_file_detailed(
            &data_path,
            &signature,
            &verification_keys,
            progress,
        )
    }

    /// Match PKESK recipients from an encrypted file against local certificates (Phase 1).
    /// Reads only PKESK headers — does not load the full file into memory.
    /// Handles both binary and ASCII-armored input.
    pub fn match_recipients_from_file(
        &self,
        input_path: String,
        local_certs: Vec<Vec<u8>>,
    ) -> Result<Vec<String>, PgpError> {
        streaming::match_recipients_from_file(&input_path, &local_certs)
    }

    // ── QR / URL Scheme ─────────────────────────────────────────────

    /// Encode a public key for QR code URL scheme.
    /// Format: cypherair://import/v1/<base64url, no padding>
    ///
    /// SECURITY: Validates that the input is a valid OpenPGP public key and rejects
    /// secret key material to prevent accidental private key leakage via QR codes.
    pub fn encode_qr_url(&self, public_key_data: Vec<u8>) -> Result<String, PgpError> {
        qr_url::encode_qr_url(public_key_data)
    }

    /// Decode a QR code URL and extract the public key.
    /// Validates the URL format, parses the key, and rejects secret key material.
    /// Only public keys should be exchanged via QR codes.
    pub fn decode_qr_url(&self, url: String) -> Result<Vec<u8>, PgpError> {
        qr_url::decode_qr_url(&url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_smoke() {
        let engine = PgpEngine::new();
        // Verify engine can perform a basic operation (not just construction)
        let result = engine.decode_qr_url("cypherair://import/v1/invalid".to_string());
        assert!(result.is_err(), "Invalid QR data should produce an error");
    }
}
