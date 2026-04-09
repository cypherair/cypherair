use std::io::Read;

use openpgp::crypto::SessionKey;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use zeroize::Zeroize;

use crate::error::PgpError;

/// Result of a decryption operation.
///
/// SECURITY: `plaintext` contains sensitive decrypted content. The Swift caller must
/// zeroize this data (via `resetBytes(in:)`) when it is no longer needed.
///
/// NOTE: A custom `Drop` impl cannot be added because `uniffi::Record` derives move
/// fields out of the struct, which is incompatible with `Drop`. Zeroization on the
/// error path is handled explicitly in `decrypt()` (line 143). On the success path,
/// the Swift caller is responsible for zeroization after use.
#[derive(uniffi::Record)]
pub struct DecryptResult {
    /// The decrypted plaintext. MUST be zeroized by the caller after use.
    pub plaintext: Vec<u8>,
    /// Signature verification result, if the message was signed.
    pub signature_status: Option<SignatureStatus>,
    /// Fingerprint of the signing key, if signed and key is known.
    pub signer_fingerprint: Option<String>,
}

/// Signature verification status for decrypted messages.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SignatureStatus {
    /// Signature is valid and the signer key is known.
    Valid,
    /// Signature is valid but the signer key is not in the provided set.
    UnknownSigner,
    /// Signature verification failed — content may have been modified.
    Bad,
    /// Message was not signed.
    NotSigned,
    /// Signer key has expired. Signature may have been valid when created.
    /// PRD: "Ask sender to update."
    Expired,
}

pub(crate) fn parse_verification_certs(
    verification_keys: &[Vec<u8>],
) -> Result<Vec<openpgp::Cert>, PgpError> {
    let mut verifier_certs = Vec::new();
    for key_data in verification_keys {
        let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Invalid verification key: {e}"),
        })?;
        verifier_certs.push(cert);
    }
    Ok(verifier_certs)
}

/// Parse the recipients of an encrypted message without decrypting.
/// This is Phase 1 of the two-phase decryption protocol — no authentication needed.
///
/// Returns a list of recipient key IDs (as hex strings).
pub fn parse_recipients(ciphertext: &[u8]) -> Result<Vec<String>, PgpError> {
    let ppr = openpgp::parse::PacketParser::from_bytes(ciphertext).map_err(|e| {
        PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        }
    })?;

    let mut recipients = Vec::new();

    // Walk through packets looking for PKESK (Public-Key Encrypted Session Key)
    let mut ppr = ppr;
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        match pp.packet {
            openpgp::Packet::PKESK(ref pkesk) => {
                if let Some(rid) = pkesk.recipient() {
                    recipients.push(rid.to_hex());
                }
            }
            // Stop after we've seen all PKESKs (they come before the encrypted data).
            // In Sequoia 2.x, both SEIPDv1 and SEIPDv2 are under Packet::SEIP.
            openpgp::Packet::SEIP(_) => {
                break;
            }
            _ => {}
        }
        let (_, next) = pp.recurse().map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?;
        ppr = next;
    }

    if recipients.is_empty() {
        return Err(PgpError::CorruptData {
            reason: "No recipients found in message".to_string(),
        });
    }

    Ok(recipients)
}

/// Match PKESK recipients in ciphertext against provided local certificates.
/// Returns the primary fingerprints of certificates that have a matching encryption subkey.
/// This is Phase 1 of the two-phase decryption protocol — no secret keys needed.
///
/// PKESK packets contain encryption *subkey* identifiers (Key IDs for v4, fingerprints for v6),
/// not primary key fingerprints. This function uses Sequoia's `key_handles()` to correctly
/// match subkey identifiers against certificates, then returns the primary fingerprint of
/// each matched certificate.
///
/// Parameters:
/// - `ciphertext`: The encrypted message (binary, not armored).
/// - `local_certs_data`: Public key certificates (binary) to match against.
///
/// Returns: Deduplicated list of matched primary key fingerprints (lowercase hex).
/// Returns `PgpError::NoMatchingKey` if no certificates match.
pub fn match_recipients(
    ciphertext: &[u8],
    local_certs_data: &[Vec<u8>],
) -> Result<Vec<String>, PgpError> {
    let policy = StandardPolicy::new();

    // Parse PKESK recipients as KeyHandle values (not strings).
    let mut pkesk_recipients: Vec<openpgp::KeyHandle> = Vec::new();
    let ppr = openpgp::parse::PacketParser::from_bytes(ciphertext).map_err(|e| {
        PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        }
    })?;
    let mut ppr = ppr;
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        match pp.packet {
            openpgp::Packet::PKESK(ref pkesk) => {
                if let Some(rid) = pkesk.recipient() {
                    pkesk_recipients.push(rid.clone());
                }
            }
            openpgp::Packet::SEIP(_) => {
                break;
            }
            _ => {}
        }
        let (_, next) = pp.recurse().map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?;
        ppr = next;
    }

    if pkesk_recipients.is_empty() {
        return Err(PgpError::CorruptData {
            reason: "No recipients found in message".to_string(),
        });
    }

    // Parse local certificates (silently skip unparseable ones).
    let mut local_certs = Vec::new();
    for cert_data in local_certs_data {
        if let Ok(cert) = openpgp::Cert::from_bytes(cert_data) {
            local_certs.push(cert);
        }
    }

    // Match: for each local cert, check if any of its encryption subkeys match a PKESK recipient.
    // cert.keys() iterates ALL keys in a certificate (primary + subkeys).
    // .key_handles() filters to those whose KeyHandle matches the PKESK recipient.
    // .for_transport_encryption() ensures we only match encryption-capable subkeys.
    let mut matched_fingerprints: Vec<String> = Vec::new();
    for cert in &local_certs {
        let primary_fp = cert.fingerprint().to_hex().to_lowercase();
        if matched_fingerprints.contains(&primary_fp) {
            continue; // Already matched
        }
        for rid in &pkesk_recipients {
            let has_match = cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .key_handles(std::iter::once(rid))
                .for_transport_encryption()
                .next()
                .is_some();
            if has_match {
                matched_fingerprints.push(primary_fp);
                break; // This cert matched, move to next cert
            }
        }
    }

    if matched_fingerprints.is_empty() {
        return Err(PgpError::NoMatchingKey);
    }

    Ok(matched_fingerprints)
}

/// Decrypt a message using the provided secret keys.
/// This is Phase 2 of the two-phase decryption protocol — requires authenticated key access.
///
/// Handles both SEIPDv1 (MDC) and SEIPDv2 (AEAD OCB/GCM).
/// AEAD authentication failure → hard-fail (PgpError::AeadAuthenticationFailed).
/// MDC verification failure → hard-fail (PgpError::IntegrityCheckFailed).
///
/// Parameters:
/// - `ciphertext`: The encrypted message (binary or ASCII-armored).
/// - `secret_keys`: One or more full certificates (with secret keys) in binary format.
/// - `verification_keys`: Optional public keys for signature verification.
pub fn decrypt<K: AsRef<[u8]>>(
    ciphertext: &[u8],
    secret_keys: &[K],
    verification_keys: &[Vec<u8>],
) -> Result<DecryptResult, PgpError> {
    let policy = StandardPolicy::new();

    // Parse secret key certificates
    let mut certs = Vec::new();
    for key_data in secret_keys {
        let cert =
            openpgp::Cert::from_bytes(key_data.as_ref()).map_err(|e| PgpError::InvalidKeyData {
                reason: format!("Invalid secret key: {e}"),
            })?;
        certs.push(cert);
    }

    // Parse verification key certificates
    let verifier_certs = parse_verification_certs(verification_keys)?;

    let helper = DecryptHelper {
        policy: &policy,
        secret_certs: &certs,
        verifier_certs: &verifier_certs,
        signature_status: None,
        signer_fingerprint: None,
    };

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?
        .with_policy(&policy, None, helper)
        .map_err(|e| classify_decrypt_error(e))?;

    let mut plaintext = Vec::new();
    if let Err(e) = decryptor.read_to_end(&mut plaintext) {
        // SECURITY: Zeroize partial plaintext on error to prevent leaking fragments.
        // This enforces the AEAD hard-fail requirement: no partial plaintext on auth failure.
        plaintext.zeroize();
        return Err(classify_decrypt_error(e.into()));
    }

    let helper = decryptor.into_helper();

    Ok(DecryptResult {
        plaintext,
        signature_status: helper.signature_status,
        signer_fingerprint: helper.signer_fingerprint,
    })
}

pub(crate) fn decrypt_with_fixed_session_key(
    ciphertext: &[u8],
    session_key_algo: Option<SymmetricAlgorithm>,
    session_key: SessionKey,
    verifier_certs: &[openpgp::Cert],
) -> Result<DecryptResult, PgpError> {
    let policy = StandardPolicy::new();
    let helper = FixedSessionKeyDecryptHelper {
        verifier_certs,
        signature_status: None,
        signer_fingerprint: None,
        session_key,
        session_key_algo,
    };

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?
        .with_policy(&policy, None, helper)
        .map_err(classify_decrypt_error)?;

    let mut plaintext = Vec::new();
    if let Err(e) = decryptor.read_to_end(&mut plaintext) {
        plaintext.zeroize();
        return Err(classify_decrypt_error(e.into()));
    }

    let helper = decryptor.into_helper();
    Ok(DecryptResult {
        plaintext,
        signature_status: helper.signature_status,
        signer_fingerprint: helper.signer_fingerprint,
    })
}

/// Helper struct for Sequoia's streaming decryption API.
/// `pub(crate)` so that `streaming.rs` can construct this for file-based decryption.
pub(crate) struct DecryptHelper<'a> {
    pub(crate) policy: &'a StandardPolicy<'a>,
    pub(crate) secret_certs: &'a [openpgp::Cert],
    pub(crate) verifier_certs: &'a [openpgp::Cert],
    pub(crate) signature_status: Option<SignatureStatus>,
    pub(crate) signer_fingerprint: Option<String>,
}

struct FixedSessionKeyDecryptHelper<'a> {
    verifier_certs: &'a [openpgp::Cert],
    signature_status: Option<SignatureStatus>,
    signer_fingerprint: Option<String>,
    session_key: SessionKey,
    session_key_algo: Option<SymmetricAlgorithm>,
}

impl<'a> VerificationHelper for DecryptHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        // Return all verification certs + secret certs (which also contain public keys)
        let mut all_certs: Vec<openpgp::Cert> = self.verifier_certs.to_vec();
        all_certs.extend(self.secret_certs.iter().cloned());
        Ok(all_certs)
    }

    /// Check signature verification results during decryption.
    ///
    /// DESIGN NOTE: Unlike `VerifyHelper::check()` (in verify.rs) which returns `Err(...)` for
    /// bad signatures, this implementation returns `Ok(())` even for bad signatures. This is
    /// intentional — during decryption, a bad signature should not prevent the user from seeing
    /// the plaintext. Instead, the signature status is reported as a "graded result" (per PRD
    /// Section 4.5) alongside the decrypted content. The UI shows a warning but still displays
    /// the message. In contrast, standalone signature verification (`verify_cleartext`,
    /// `verify_detached`) hard-fails on bad signatures because the content is already visible
    /// and the sole purpose is to validate the signature.
    // NOTE: All non-GoodChecksum arms intentionally fall through (no early return).
    // Only GoodChecksum triggers early return. For MissingKey, BadKey, and catch-all,
    // the last-set status wins based on iteration order. This is acceptable because
    // during decryption, signature verification is "graded" — decryption succeeds
    // regardless of signature status.
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        apply_signature_results(
            structure,
            &mut self.signature_status,
            &mut self.signer_fingerprint,
        )
    }
}

impl<'a> VerificationHelper for FixedSessionKeyDecryptHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.verifier_certs.to_vec())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        apply_signature_results(
            structure,
            &mut self.signature_status,
            &mut self.signer_fingerprint,
        )
    }
}

fn apply_signature_results(
    structure: MessageStructure,
    signature_status: &mut Option<SignatureStatus>,
    signer_fingerprint: &mut Option<String>,
) -> openpgp::Result<()> {
    for layer in structure {
        match layer {
            MessageLayer::Encryption { .. } => {}
            MessageLayer::Compression { .. } => {}
            MessageLayer::SignatureGroup { results } => {
                for result in results {
                    match result {
                        Ok(GoodChecksum { ka, .. }) => {
                            *signature_status = Some(SignatureStatus::Valid);
                            *signer_fingerprint =
                                Some(ka.cert().fingerprint().to_hex().to_lowercase());
                            return Ok(());
                        }
                        Err(VerificationError::MissingKey { .. }) => {
                            *signature_status = Some(SignatureStatus::UnknownSigner);
                        }
                        Err(VerificationError::BadKey { ka, error, .. }) => {
                            if is_expired_error(&error) {
                                *signature_status = Some(SignatureStatus::Expired);
                                *signer_fingerprint =
                                    Some(ka.cert().fingerprint().to_hex().to_lowercase());
                            } else {
                                *signature_status = Some(SignatureStatus::Bad);
                            }
                        }
                        Err(_) => {
                            *signature_status = Some(SignatureStatus::Bad);
                        }
                    }
                }
            }
        }
    }

    if signature_status.is_none() {
        *signature_status = Some(SignatureStatus::NotSigned);
    }

    Ok(())
}

/// Classify a Sequoia decryption error into the appropriate PgpError variant.
///
/// SECURITY NOTE: The fallback is always `CorruptData`, which is safe — the decryption
/// hard-fails regardless of classification, so no plaintext is ever leaked. The classification
/// only affects which user-facing error message is shown ("tampered" vs "damaged").
///
/// STRATEGY: Uses a hybrid approach — structured downcast first, string matching fallback.
///
/// 1. **Structured downcast** (`openpgp::Error` variants): Covers most Sequoia errors and is
///    resilient to error message rewording across Sequoia versions. Handles two wrapping layers:
///    - Direct `anyhow::Error` (from `DecryptorBuilder::with_policy()`)
///    - `io::Error`-wrapped errors (from `Decryptor::read_to_end()` via the `Read` trait)
///
/// 2. **String matching fallback**: Required because the `crypto-openssl` backend returns
///    `openssl::error::ErrorStack` (not `openpgp::Error::ManipulatedMessage`) when an AEAD
///    tag verification fails. OpenSSL's `cipher_final` produces its own error type that cannot
///    be downcast to `openpgp::Error`. String matching catches these and any other unstructured
///    errors in the chain.
///
/// MAINTENANCE: After Sequoia version bumps, verify that `openpgp::Error` variants still cover
/// the expected cases. The string fallback provides defense-in-depth if new error paths appear.
pub(crate) fn classify_decrypt_error(e: openpgp::anyhow::Error) -> PgpError {
    // Strategy 1: Structured downcast — try direct anyhow → openpgp::Error
    // This path handles errors from DecryptorBuilder::with_policy().
    if let Some(openpgp_err) = e.downcast_ref::<openpgp::Error>() {
        return map_openpgp_error(openpgp_err, &e);
    }

    // Strategy 1b: Unwrap io::Error layer — errors from Decryptor::read_to_end().
    // Sequoia's Decryptor implements io::Read; its read() wraps non-IO errors in
    // io::Error::new(ErrorKind::Other, anyhow_error). We unwrap this layer.
    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
        if let Some(inner) = io_err.get_ref() {
            if let Some(openpgp_err) = inner.downcast_ref::<openpgp::Error>() {
                return map_openpgp_error(openpgp_err, &e);
            }
        }
    }

    // Strategy 2: String matching fallback — walk the entire error chain.
    // Required for OpenSSL AEAD tag mismatch errors (openssl::error::ErrorStack)
    // and any other errors that don't downcast to openpgp::Error.
    // All comparisons are case-insensitive to guard against rewording across versions.
    for cause in e.chain() {
        let cause_str = cause.to_string().to_lowercase();
        if cause_str.contains("authentication")
            || cause_str.contains("aead")
            || cause_str.contains("tag mismatch")
            || cause_str.contains("manipulated")
        {
            return PgpError::AeadAuthenticationFailed;
        }
        if cause_str.contains("mdc")
            || cause_str.contains("modification detection")
            || cause_str.contains("integrity")
        {
            return PgpError::IntegrityCheckFailed;
        }
    }

    // Final fallback: check top-level message for "no key" patterns
    let err_str = e.to_string().to_lowercase();
    if err_str.contains("no matching key")
        || err_str.contains("no key to decrypt")
        || err_str.contains("no session key")
    {
        PgpError::NoMatchingKey
    } else {
        PgpError::CorruptData {
            reason: format!("Decryption failed: {e}"),
        }
    }
}

/// Map a structured `openpgp::Error` variant to the appropriate `PgpError`.
/// Called from `classify_decrypt_error` after successful downcast.
fn map_openpgp_error(err: &openpgp::Error, original: &openpgp::anyhow::Error) -> PgpError {
    match err {
        // ManipulatedMessage covers both MDC failure (SEIPDv1) and AEAD structural
        // failures (missing/short chunks). Map to IntegrityCheckFailed as a general
        // "tampered" indicator — both AEAD and MDC are integrity mechanisms.
        openpgp::Error::ManipulatedMessage => PgpError::IntegrityCheckFailed,

        openpgp::Error::MissingSessionKey(_) => PgpError::NoMatchingKey,

        openpgp::Error::InvalidPassword => PgpError::WrongPassphrase,

        openpgp::Error::UnsupportedAEADAlgorithm(a) => PgpError::UnsupportedAlgorithm {
            algo: a.to_string(),
        },

        openpgp::Error::UnsupportedSymmetricAlgorithm(a) => PgpError::UnsupportedAlgorithm {
            algo: a.to_string(),
        },

        // Non-exhaustive enum — safe fallback for any future Sequoia variants.
        _ => PgpError::CorruptData {
            reason: format!("Decryption failed: {original}"),
        },
    }
}

/// Check if an error chain contains an `openpgp::Error::Expired` variant.
/// Used to distinguish expired signer keys from other verification failures,
/// so that the UI can show "Ask sender to update" instead of "Content may have
/// been modified." See security audit finding M2+M3.
///
/// Uses the same hybrid strategy as `classify_decrypt_error()`:
/// 1. Structured downcast (preferred, resilient to message rewording)
/// 2. Error chain walk (catches nested Expired errors)
/// 3. String fallback (defense-in-depth)
pub(crate) fn is_expired_error(error: &openpgp::anyhow::Error) -> bool {
    // Strategy 1: Direct downcast
    if matches!(
        error.downcast_ref::<openpgp::Error>(),
        Some(openpgp::Error::Expired(_))
    ) {
        return true;
    }
    // Strategy 2: Walk the error chain for nested Expired variants
    for cause in error.chain() {
        if let Some(openpgp::Error::Expired(_)) = cause.downcast_ref::<openpgp::Error>() {
            return true;
        }
    }
    // Strategy 3: String fallback (defense-in-depth against error wrapping changes).
    // Tightened to specific phrases to avoid false positives from unrelated error
    // messages that happen to contain the word "expired".
    let err_str = error.to_string().to_lowercase();
    err_str.contains("key expired")
        || err_str.contains("certificate expired")
        || err_str.contains("signature expired")
        || err_str.contains("validity period expired")
}

impl<'a> DecryptionHelper for DecryptHelper<'a> {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        // Try each PKESK against each of our secret keys.
        // SECURITY: `into_keypair()` extracts secret material from the key; the KeyPair
        // is consumed by `pkesk.decrypt()`. `session_key` (SessionKey type) is zeroized
        // by Sequoia's Drop impl when it goes out of scope. See sign.rs for similar rationale.
        for pkesk in pkesks {
            for cert in self.secret_certs {
                for ka in cert
                    .keys()
                    .with_policy(self.policy, None)
                    .supported()
                    .unencrypted_secret()
                    .key_handles(pkesk.recipient())
                    .for_transport_encryption()
                {
                    if let Some((algo, session_key)) = ka
                        .key()
                        .clone()
                        .into_keypair()
                        .ok()
                        .and_then(|mut kp| pkesk.decrypt(&mut kp, sym_algo))
                    {
                        if decrypt(algo, &session_key) {
                            return Ok(None);
                        }
                    }
                }
            }
        }

        Err(openpgp::anyhow::anyhow!("No key to decrypt message"))
    }
}

impl<'a> DecryptionHelper for FixedSessionKeyDecryptHelper<'a> {
    fn decrypt(
        &mut self,
        _pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        if decrypt(self.session_key_algo, &self.session_key) {
            Ok(None)
        } else if self.session_key_algo.is_none() {
            Err(openpgp::anyhow::anyhow!(
                "Fixed session key failed payload authentication"
            ))
        } else {
            Err(openpgp::anyhow::anyhow!("No key to decrypt message"))
        }
    }
}
