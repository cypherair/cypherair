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
pub fn decrypt(
    ciphertext: &[u8],
    secret_keys: &[Vec<u8>],
    verification_keys: &[Vec<u8>],
) -> Result<DecryptResult, PgpError> {
    let policy = StandardPolicy::new();

    // Parse secret key certificates
    let mut certs = Vec::new();
    for key_data in secret_keys {
        let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid secret key: {e}"),
            }
        })?;
        certs.push(cert);
    }

    // Parse verification key certificates
    let mut verifier_certs = Vec::new();
    for key_data in verification_keys {
        let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid verification key: {e}"),
            }
        })?;
        verifier_certs.push(cert);
    }

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

/// Helper struct for Sequoia's streaming decryption API.
struct DecryptHelper<'a> {
    policy: &'a StandardPolicy<'a>,
    secret_certs: &'a [openpgp::Cert],
    verifier_certs: &'a [openpgp::Cert],
    signature_status: Option<SignatureStatus>,
    signer_fingerprint: Option<String>,
}

impl<'a> VerificationHelper for DecryptHelper<'a> {
    fn get_certs(
        &mut self,
        _ids: &[openpgp::KeyHandle],
    ) -> openpgp::Result<Vec<openpgp::Cert>> {
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
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            match layer {
                MessageLayer::Encryption { .. } => {}
                MessageLayer::Compression { .. } => {}
                MessageLayer::SignatureGroup { results } => {
                    for result in results {
                        match result {
                            Ok(GoodChecksum { ka, .. }) => {
                                self.signature_status = Some(SignatureStatus::Valid);
                                self.signer_fingerprint = Some(
                                    ka.cert().fingerprint().to_hex().to_lowercase(),
                                );
                                return Ok(());
                            }
                            Err(VerificationError::MissingKey { .. }) => {
                                self.signature_status = Some(SignatureStatus::UnknownSigner);
                            }
                            Err(_) => {
                                self.signature_status = Some(SignatureStatus::Bad);
                            }
                        }
                    }
                }
            }
        }

        if self.signature_status.is_none() {
            self.signature_status = Some(SignatureStatus::NotSigned);
        }

        Ok(())
    }
}

/// Classify a Sequoia decryption error into the appropriate PgpError variant.
///
/// SECURITY NOTE: This function uses string matching on Sequoia error messages because
/// Sequoia returns `anyhow::Error` without structured error types for decryption failures.
/// The fallback is always `CorruptData`, which is safe — the decryption hard-fails regardless
/// of classification, so no plaintext is ever leaked. The classification only affects which
/// user-facing error message is shown ("tampered" vs "damaged").
///
/// MAINTENANCE: If Sequoia upgrades change error message text, this classification may
/// degrade (more errors classified as CorruptData). Review this function after any Sequoia
/// version bump. Check if Sequoia exposes structured error types (e.g., `openpgp::Error`)
/// that could replace string matching.
fn classify_decrypt_error(e: openpgp::anyhow::Error) -> PgpError {
    let err_str = e.to_string().to_lowercase();

    // Check the entire error chain for more specific error types.
    // Sequoia wraps errors in anyhow, so we walk the chain.
    // All comparisons are case-insensitive to guard against Sequoia rewording
    // error messages across versions.
    for cause in e.chain() {
        let cause_str = cause.to_string().to_lowercase();
        if cause_str.contains("authentication")
            || cause_str.contains("aead")
            || cause_str.contains("tag mismatch")
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

    // Fall back to top-level error string
    if err_str.contains("no matching key") || err_str.contains("no key to decrypt") {
        PgpError::NoMatchingKey
    } else {
        PgpError::CorruptData {
            reason: format!("Decryption failed: {e}"),
        }
    }
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
                    if let Some((algo, session_key)) =
                        ka.key().clone().into_keypair().ok()
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
