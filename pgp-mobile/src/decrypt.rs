use std::io::Read;

use openpgp::crypto::SessionKey;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;

/// Result of a decryption operation.
#[derive(uniffi::Record)]
pub struct DecryptResult {
    /// The decrypted plaintext.
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
            // Stop after we've seen all PKESKs (they come before the encrypted data)
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
        .map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("authentication")
                || err_str.contains("AEAD")
                || err_str.contains("tag")
            {
                PgpError::AeadAuthenticationFailed
            } else if err_str.contains("MDC")
                || err_str.contains("modification detection")
                || err_str.contains("integrity")
            {
                PgpError::IntegrityCheckFailed
            } else if err_str.contains("no matching key")
                || err_str.contains("No key to decrypt")
            {
                PgpError::NoMatchingKey
            } else {
                PgpError::CorruptData {
                    reason: format!("Decryption failed: {e}"),
                }
            }
        })?;

    let mut plaintext = Vec::new();
    decryptor
        .read_to_end(&mut plaintext)
        .map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("authentication")
                || err_str.contains("AEAD")
                || err_str.contains("tag")
            {
                PgpError::AeadAuthenticationFailed
            } else if err_str.contains("MDC") || err_str.contains("integrity") {
                PgpError::IntegrityCheckFailed
            } else {
                PgpError::CorruptData {
                    reason: format!("Read failed: {e}"),
                }
            }
        })?;

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

impl<'a> DecryptionHelper for DecryptHelper<'a> {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        // Try each PKESK against each of our secret keys
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
