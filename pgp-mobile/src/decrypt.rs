use std::io::Read;

use openpgp::crypto::SessionKey;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use zeroize::{Zeroize, Zeroizing};

use crate::error::PgpError;
use crate::external_composite_decryptor::ExternalCompositeDecryptorError;
use crate::external_decryptor::ExternalP256DecryptorError;
use crate::signature_details::{DecryptDetailedResult, SignatureCollector, SummaryFoldMode};

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

/// Quantum-safety of a produced message, judged by the artifact itself:
/// the public-key algorithms of its PKESK packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MessageQuantumSafety {
    /// Every session-key packet targets an RFC 9980 composite KEM.
    FullyPostQuantum,
    /// Some, but not all, session-key packets target a composite KEM.
    Mixed,
    /// No session-key packet targets a composite KEM.
    NonePostQuantum,
}

/// Classify a message's quantum-safety from its PKESK algorithms.
///
/// The caller may pass a truncated prefix of a large message (streamed
/// file output): parsing stops at the first encrypted-container packet,
/// which follows all PKESKs. That container is therefore the proof that
/// every session-key packet has been seen — so this function fails closed
/// (returns `CorruptData`) if it reaches the end of the input without
/// observing the container. Otherwise a prefix truncated *before* some
/// PKESKs could silently downgrade the verdict (e.g. report `NonePostQuantum`
/// or `Mixed` for a message that is actually fully post-quantum). Callers
/// map the error to "no badge" rather than a misleading one.
pub fn message_quantum_safety(ciphertext: &[u8]) -> Result<MessageQuantumSafety, PgpError> {
    use openpgp::types::PublicKeyAlgorithm;

    let mut ppr = openpgp::parse::PacketParser::from_bytes(ciphertext).map_err(|e| {
        PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        }
    })?;

    let mut total = 0usize;
    let mut post_quantum = 0usize;
    let mut saw_container = false;

    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        match pp.packet {
            openpgp::Packet::PKESK(ref pkesk) => {
                total += 1;
                let algo = match pkesk {
                    openpgp::packet::PKESK::V3(p) => p.pk_algo(),
                    openpgp::packet::PKESK::V6(p) => p.pk_algo(),
                    _ => PublicKeyAlgorithm::Unknown(0),
                };
                if matches!(
                    algo,
                    PublicKeyAlgorithm::MLKEM768_X25519 | PublicKeyAlgorithm::MLKEM1024_X448
                ) {
                    post_quantum += 1;
                }
            }
            openpgp::Packet::SEIP(_) => {
                // The encrypted container follows all session-key packets;
                // reaching it means every PKESK has been counted. Padding and
                // Marker packets deliberately fall through to `_` so they never
                // stand in for the container.
                saw_container = true;
                break;
            }
            _ => {}
        }
        let (_, next) = pp.recurse().map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?;
        ppr = next;
    }

    if !saw_container {
        return Err(PgpError::CorruptData {
            reason: "Encrypted container not found before end of input; cannot classify \
                     quantum-safety from a truncated prefix"
                .to_string(),
        });
    }

    Ok(if total == 0 || post_quantum == 0 {
        MessageQuantumSafety::NonePostQuantum
    } else if post_quantum == total {
        MessageQuantumSafety::FullyPostQuantum
    } else {
        MessageQuantumSafety::Mixed
    })
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

/// Decrypt a message and preserve detailed per-signature results.
pub fn decrypt_detailed<K: AsRef<[u8]>>(
    ciphertext: &[u8],
    secret_keys: &[K],
    verification_keys: &[Vec<u8>],
) -> Result<DecryptDetailedResult, PgpError> {
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
        collector: SignatureCollector::new(SummaryFoldMode::DecryptLike),
    };

    let (plaintext, helper) = decrypt_with_helper(ciphertext, &policy, helper)?;
    let (summary_state, summary_entry_index, signatures) = helper.collector.into_parts();

    Ok(DecryptDetailedResult {
        summary_state,
        summary_entry_index,
        signatures,
        plaintext,
    })
}

/// Maximum plaintext size accepted by the in-memory decrypt path.
///
/// In-memory decryption (message text, not files) buffers the entire plaintext
/// in RAM. A small, highly-compressed OpenPGP message can otherwise expand
/// without bound and OOM / Jetsam-kill the app — a decompression bomb. Files are
/// decrypted through the streaming path (`streaming::decrypt_file_with_helper`),
/// which is disk-backed and not subject to this cap. 256 MiB is far above any
/// legitimate pasted/typed message while bounding peak allocation well under the
/// 8 GB minimum-device budget.
pub(crate) const MAX_IN_MEMORY_PLAINTEXT_BYTES: usize = 256 * 1024 * 1024;

/// Chunk size for the capped in-memory read loop.
const DECRYPT_READ_CHUNK: usize = 64 * 1024;

pub(crate) fn decrypt_with_helper<'a, H>(
    ciphertext: &'a [u8],
    policy: &'a StandardPolicy<'a>,
    helper: H,
) -> Result<(Vec<u8>, H), PgpError>
where
    H: VerificationHelper + DecryptionHelper,
{
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?
        .with_policy(policy, None, helper)
        .map_err(|e| classify_decrypt_error(e))?;

    let mut plaintext = Vec::new();
    if let Err(e) =
        read_capped_zeroizing(&mut decryptor, &mut plaintext, MAX_IN_MEMORY_PLAINTEXT_BYTES)
    {
        // SECURITY: Zeroize partial plaintext on error to prevent leaking fragments.
        // This enforces the AEAD hard-fail requirement: no partial plaintext on auth failure.
        plaintext.zeroize();
        return Err(e);
    }

    let helper = decryptor.into_helper();
    Ok((plaintext, helper))
}

/// Read `reader` fully into `sink`, enforcing an output-size ceiling and zeroizing
/// the transient chunk buffer on every path.
///
/// Bounds the decompression-bomb OOM on the in-memory decrypt path: a read that
/// would push the accumulated plaintext past `max_bytes` fails closed with
/// `CorruptData` instead of allocating without bound. Any reader error (including
/// the terminal AEAD/MDC authentication failure surfaced on the final read) is
/// classified and returned, so the caller still enforces the AEAD hard-fail
/// contract before the plaintext is used. The chunk buffer is `Zeroizing`, so no
/// plaintext fragment survives in the scratch allocation.
fn read_capped_zeroizing<R: Read>(
    reader: &mut R,
    sink: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<(), PgpError> {
    let mut buffer = Zeroizing::new(vec![0u8; DECRYPT_READ_CHUNK]);
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|e| classify_decrypt_error(e.into()))?;
        if read == 0 {
            return Ok(());
        }
        // `sink.len() <= max_bytes` holds by construction, so the subtraction
        // never underflows; a read that would exceed the ceiling fails closed.
        if read > max_bytes - sink.len() {
            return Err(PgpError::CorruptData {
                reason: "Decrypted message exceeds the maximum in-memory size".to_string(),
            });
        }
        sink.extend_from_slice(&buffer[..read]);
    }
}

pub(crate) fn decrypt_with_fixed_session_key_detailed(
    ciphertext: &[u8],
    session_key_algo: Option<SymmetricAlgorithm>,
    session_key: SessionKey,
    verifier_certs: &[openpgp::Cert],
) -> Result<DecryptDetailedResult, PgpError> {
    let policy = StandardPolicy::new();
    let helper = FixedSessionKeyDecryptHelper {
        verifier_certs,
        collector: SignatureCollector::new(SummaryFoldMode::DecryptLike),
        session_key,
        session_key_algo,
    };

    let (plaintext, helper) = decrypt_with_helper(ciphertext, &policy, helper)?;
    let (summary_state, summary_entry_index, signatures) = helper.collector.into_parts();

    Ok(DecryptDetailedResult {
        summary_state,
        summary_entry_index,
        signatures,
        plaintext,
    })
}

/// Helper struct for Sequoia's streaming decryption API.
/// `pub(crate)` so that `streaming.rs` can construct this for file-based decryption.
pub(crate) struct DecryptHelper<'a> {
    pub(crate) policy: &'a StandardPolicy<'a>,
    pub(crate) secret_certs: &'a [openpgp::Cert],
    pub(crate) verifier_certs: &'a [openpgp::Cert],
    pub(crate) collector: SignatureCollector,
}

struct FixedSessionKeyDecryptHelper<'a> {
    verifier_certs: &'a [openpgp::Cert],
    collector: SignatureCollector,
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
        self.collector.observe_structure(structure);
        Ok(())
    }
}

impl<'a> VerificationHelper for FixedSessionKeyDecryptHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.verifier_certs.to_vec())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        self.collector.observe_structure(structure);
        Ok(())
    }
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
    if let Some(external_error) = e
        .chain()
        .find_map(|cause| cause.downcast_ref::<ExternalP256DecryptorError>().copied())
    {
        return match external_error {
            ExternalP256DecryptorError::OperationCancelled => PgpError::OperationCancelled,
            ExternalP256DecryptorError::ExternalFailure(category) => {
                PgpError::ExternalP256KeyAgreementFailed { category }
            }
            ExternalP256DecryptorError::InvalidRequest(_) => {
                PgpError::ExternalP256KeyAgreementFailed {
                    category:
                        crate::keys::ExternalP256KeyAgreementFailureCategory::ExternalOperationInvalidRequest,
                }
            }
            ExternalP256DecryptorError::InvalidResponse(_) => {
                PgpError::ExternalP256KeyAgreementFailed {
                    category:
                        crate::keys::ExternalP256KeyAgreementFailureCategory::ExternalOperationInvalidResponse,
                }
            }
        };
    }

    if let Some(external_error) = e.chain().find_map(|cause| {
        cause
            .downcast_ref::<ExternalCompositeDecryptorError>()
            .copied()
    }) {
        return match external_error {
            ExternalCompositeDecryptorError::OperationCancelled => PgpError::OperationCancelled,
            ExternalCompositeDecryptorError::ExternalFailure(category) => {
                PgpError::ExternalCompositeKeyAgreementFailed { category }
            }
            ExternalCompositeDecryptorError::ClassicalComponentFailure(_) => {
                PgpError::ExternalCompositeKeyAgreementFailed {
                    category:
                        crate::keys::ExternalCompositeKeyAgreementFailureCategory::ClassicalComponentFailed,
                }
            }
            ExternalCompositeDecryptorError::InvalidRequest(_) => {
                PgpError::ExternalCompositeKeyAgreementFailed {
                    category:
                        crate::keys::ExternalCompositeKeyAgreementFailureCategory::ExternalOperationInvalidRequest,
                }
            }
            ExternalCompositeDecryptorError::InvalidResponse(_) => {
                PgpError::ExternalCompositeKeyAgreementFailed {
                    category:
                        crate::keys::ExternalCompositeKeyAgreementFailureCategory::ExternalOperationInvalidResponse,
                }
            }
        };
    }

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
        if cause_str.contains("operation cancelled by user") {
            return PgpError::OperationCancelled;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_capped_zeroizing_rejects_output_over_ceiling() {
        // A reader that yields more than the ceiling must fail closed rather
        // than accumulate without bound (decompression-bomb guard, #611).
        let data = vec![0xABu8; 20];
        let mut sink = Vec::new();
        let result = read_capped_zeroizing(&mut data.as_slice(), &mut sink, 10);
        assert!(matches!(result, Err(PgpError::CorruptData { .. })));
    }

    #[test]
    fn read_capped_zeroizing_accepts_output_within_ceiling() {
        let data = vec![0xABu8; 8];
        let mut sink = Vec::new();
        read_capped_zeroizing(&mut data.as_slice(), &mut sink, 10).expect("within ceiling");
        assert_eq!(sink, data);
    }

    #[test]
    fn read_capped_zeroizing_accepts_output_exactly_at_ceiling() {
        let data = vec![0xABu8; 10];
        let mut sink = Vec::new();
        read_capped_zeroizing(&mut data.as_slice(), &mut sink, 10).expect("exactly at ceiling");
        assert_eq!(sink.len(), 10);
    }
}
