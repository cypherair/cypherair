use std::sync::Arc;

use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::{SEIP, SKESK};
use openpgp::serialize::stream::{Armorer, Encryptor, Message};
use openpgp::types::{AEADAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp as openpgp;

use crate::armor;
use crate::bounded_walk;
use crate::decrypt;
use crate::encrypt;
use crate::error::PgpError;
use crate::keys::{
    ExternalMlDsa65SigningProvider, ExternalMlDsa87SigningProvider, ExternalP256SigningProvider,
};
use crate::signature_details::{DetailedSignatureEntry, SignatureVerificationState};

/// Message format for password-encrypted messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PasswordMessageFormat {
    Seipdv1,
    Seipdv2,
}

/// Result status for password-based decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PasswordDecryptStatus {
    Decrypted,
    NoSkesk,
    PasswordRejected,
}

/// Result of password-based decryption.
///
/// SECURITY: If `plaintext` is present, the Swift caller must zeroize the returned
/// data (via `resetBytes(in:)`) once it is no longer needed.
#[derive(Debug, uniffi::Record)]
pub struct PasswordDecryptResult {
    pub status: PasswordDecryptStatus,
    pub plaintext: Option<Vec<u8>>,
    pub summary_state: SignatureVerificationState,
    pub summary_entry_index: Option<u64>,
    pub signatures: Vec<DetailedSignatureEntry>,
}

/// Encrypt plaintext with a password and return ASCII-armored ciphertext.
pub fn encrypt(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_key: Option<&[u8]>,
) -> Result<Vec<u8>, PgpError> {
    encrypt_impl(plaintext, password, format, signing_key, false)
}

/// Encrypt plaintext with a password and return binary ciphertext.
pub fn encrypt_binary(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_key: Option<&[u8]>,
) -> Result<Vec<u8>, PgpError> {
    encrypt_impl(plaintext, password, format, signing_key, true)
}

/// Encrypt plaintext with a password and sign it using a public certificate plus external P-256 signer.
pub fn encrypt_with_external_p256_signer(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
) -> Result<Vec<u8>, PgpError> {
    encrypt_external_impl(
        plaintext,
        password,
        format,
        signing_public_cert,
        signing_key_fingerprint,
        signer,
        false,
    )
}

/// Encrypt plaintext with a password, sign externally, and return binary ciphertext.
pub fn encrypt_binary_with_external_p256_signer(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
) -> Result<Vec<u8>, PgpError> {
    encrypt_external_impl(
        plaintext,
        password,
        format,
        signing_public_cert,
        signing_key_fingerprint,
        signer,
        true,
    )
}

/// Encrypt plaintext with a password and sign it using a public certificate plus
/// external split-custody composite signer.
pub fn encrypt_with_external_composite_signer(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa65SigningProvider>,
) -> Result<Vec<u8>, PgpError> {
    encrypt_external_composite_impl(
        plaintext,
        password,
        format,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        false,
    )
}

/// Encrypt plaintext with a password, sign with the external split-custody
/// composite signer, and return binary ciphertext.
pub fn encrypt_binary_with_external_composite_signer(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa65SigningProvider>,
) -> Result<Vec<u8>, PgpError> {
    encrypt_external_composite_impl(
        plaintext,
        password,
        format,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        true,
    )
}

/// Decrypt a password-encrypted message without falling back to recipient-key decryption.
///
/// `affordable_memory_kib` is what the calling process can afford to dirty right
/// now — a platform figure only the host can read (see the Swift
/// `Argon2idMemoryGuard`). It narrows, and never widens, the format ceiling in
/// `MAX_MESSAGE_ARGON2_MEMORY_KIB`: pass `u64::MAX` to mean "the device is not
/// the constraint" and still get the format bound. The check is applied per
/// candidate, so a message carrying one unaffordable slot alongside an
/// affordable one still opens through the latter.
pub fn decrypt(
    encrypted_message: &[u8],
    password: &Password,
    verification_keys: &[Vec<u8>],
    affordable_memory_kib: u64,
) -> Result<PasswordDecryptResult, PgpError> {
    let normalized = normalize_message_bytes(encrypted_message)?;
    let skesks = collect_message_skesks(&normalized)?;
    if skesks.is_empty() {
        return Ok(PasswordDecryptResult {
            status: PasswordDecryptStatus::NoSkesk,
            plaintext: None,
            summary_state: SignatureVerificationState::NotSigned,
            summary_entry_index: None,
            signatures: Vec::new(),
        });
    }

    let verifier_certs = decrypt::parse_verification_certs(verification_keys)?;
    let mut deferred_candidate_error: Option<PgpError> = None;

    for skesk in &skesks {
        let (session_key_algo, session_key) =
            match derive_candidate(skesk, password, affordable_memory_kib) {
                CandidateOutcome::Candidate {
                    session_key_algo,
                    session_key,
                } => (session_key_algo, session_key),
                CandidateOutcome::Reject => continue,
                CandidateOutcome::DeferredError(error) => {
                    if deferred_candidate_error.is_none() {
                        deferred_candidate_error = Some(error);
                    }
                    continue;
                }
            };

        match decrypt::decrypt_with_fixed_session_key_detailed(
            &normalized,
            session_key_algo,
            session_key,
            &verifier_certs,
        ) {
            Ok(result) => {
                return Ok(PasswordDecryptResult {
                    status: PasswordDecryptStatus::Decrypted,
                    plaintext: Some(result.plaintext),
                    summary_state: result.summary_state,
                    summary_entry_index: result.summary_entry_index,
                    signatures: result.signatures,
                });
            }
            Err(error @ PgpError::AeadAuthenticationFailed)
            | Err(error @ PgpError::IntegrityCheckFailed)
            | Err(error @ PgpError::UnsupportedAlgorithm { .. }) => {
                if deferred_candidate_error.is_none() {
                    deferred_candidate_error = Some(error);
                }
            }
            Err(PgpError::CorruptData { .. }) | Err(PgpError::NoMatchingKey) => {}
            Err(error) => return Err(error),
        }
    }

    if let Some(error) = deferred_candidate_error {
        return Err(error);
    }

    Ok(PasswordDecryptResult {
        status: PasswordDecryptStatus::PasswordRejected,
        plaintext: None,
        summary_state: SignatureVerificationState::NotSigned,
        summary_entry_index: None,
        signatures: Vec::new(),
    })
}

enum CandidateOutcome {
    Candidate {
        session_key_algo: Option<SymmetricAlgorithm>,
        session_key: SessionKey,
    },
    Reject,
    DeferredError(PgpError),
}

fn encrypt_impl(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_key: Option<&[u8]>,
    binary: bool,
) -> Result<Vec<u8>, PgpError> {
    let policy = openpgp::policy::StandardPolicy::new();
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = if binary {
        message
    } else {
        Armorer::new(message)
            .kind(openpgp::armor::Kind::Message)
            .build()
            .map_err(|e| PgpError::EncryptionFailed {
                reason: format!("Armor setup failed: {e}"),
            })?
    };

    let encryptor = Encryptor::with_passwords(message, std::iter::once(password.clone()))
        .symmetric_algo(SymmetricAlgorithm::AES256);
    let encryptor = match format {
        PasswordMessageFormat::Seipdv1 => encryptor,
        PasswordMessageFormat::Seipdv2 => encryptor.aead_algo(AEADAlgorithm::OCB),
    };
    let message = encryptor.build().map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Encryptor setup failed: {e}"),
    })?;

    let message = encrypt::setup_signer(message, signing_key, &policy)?;
    encrypt::write_and_finalize(message, plaintext)?;

    Ok(sink)
}

fn encrypt_external_impl(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
    binary: bool,
) -> Result<Vec<u8>, PgpError> {
    let policy = openpgp::policy::StandardPolicy::new();
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = if binary {
        message
    } else {
        Armorer::new(message)
            .kind(openpgp::armor::Kind::Message)
            .build()
            .map_err(|e| PgpError::EncryptionFailed {
                reason: format!("Armor setup failed: {e}"),
            })?
    };

    let encryptor = Encryptor::with_passwords(message, std::iter::once(password.clone()))
        .symmetric_algo(SymmetricAlgorithm::AES256);
    let encryptor = match format {
        PasswordMessageFormat::Seipdv1 => encryptor,
        PasswordMessageFormat::Seipdv2 => encryptor.aead_algo(AEADAlgorithm::OCB),
    };
    let message = encryptor.build().map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Encryptor setup failed: {e}"),
    })?;

    let message = encrypt::setup_external_p256_signer(
        message,
        signing_public_cert,
        signing_key_fingerprint,
        signer,
        &policy,
    )?;
    encrypt::write_and_finalize_external_signing(message, plaintext)?;

    Ok(sink)
}

fn encrypt_external_composite_impl(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa65SigningProvider>,
    binary: bool,
) -> Result<Vec<u8>, PgpError> {
    let policy = openpgp::policy::StandardPolicy::new();
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = if binary {
        message
    } else {
        Armorer::new(message)
            .kind(openpgp::armor::Kind::Message)
            .build()
            .map_err(|e| PgpError::EncryptionFailed {
                reason: format!("Armor setup failed: {e}"),
            })?
    };

    let encryptor = Encryptor::with_passwords(message, std::iter::once(password.clone()))
        .symmetric_algo(SymmetricAlgorithm::AES256);
    let encryptor = match format {
        PasswordMessageFormat::Seipdv1 => encryptor,
        PasswordMessageFormat::Seipdv2 => encryptor.aead_algo(AEADAlgorithm::OCB),
    };
    let message = encryptor.build().map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Encryptor setup failed: {e}"),
    })?;

    let message = encrypt::setup_external_composite_signer(
        message,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        &policy,
    )?;
    encrypt::write_and_finalize_external_signing(message, plaintext)?;

    Ok(sink)
}

/// Device-Bound Post-Quantum · High analog of
/// `encrypt_with_external_composite_signer`.
pub fn encrypt_with_external_composite_high_signer(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa87SigningProvider>,
) -> Result<Vec<u8>, PgpError> {
    encrypt_external_composite_high_impl(
        plaintext,
        password,
        format,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        false,
    )
}

/// Device-Bound Post-Quantum · High analog of
/// `encrypt_binary_with_external_composite_signer`.
pub fn encrypt_binary_with_external_composite_high_signer(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa87SigningProvider>,
) -> Result<Vec<u8>, PgpError> {
    encrypt_external_composite_high_impl(
        plaintext,
        password,
        format,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        true,
    )
}

fn encrypt_external_composite_high_impl(
    plaintext: &[u8],
    password: &Password,
    format: PasswordMessageFormat,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa87SigningProvider>,
    binary: bool,
) -> Result<Vec<u8>, PgpError> {
    let policy = openpgp::policy::StandardPolicy::new();
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = if binary {
        message
    } else {
        Armorer::new(message)
            .kind(openpgp::armor::Kind::Message)
            .build()
            .map_err(|e| PgpError::EncryptionFailed {
                reason: format!("Armor setup failed: {e}"),
            })?
    };

    let encryptor = Encryptor::with_passwords(message, std::iter::once(password.clone()))
        .symmetric_algo(SymmetricAlgorithm::AES256);
    let encryptor = match format {
        PasswordMessageFormat::Seipdv1 => encryptor,
        PasswordMessageFormat::Seipdv2 => encryptor.aead_algo(AEADAlgorithm::OCB),
    };
    let message = encryptor.build().map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Encryptor setup failed: {e}"),
    })?;

    let message = encrypt::setup_external_composite_high_signer(
        message,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        &policy,
    )?;
    encrypt::write_and_finalize_external_signing(message, plaintext)?;

    Ok(sink)
}

fn normalize_message_bytes(message: &[u8]) -> Result<Vec<u8>, PgpError> {
    if message.first().copied() == Some(b'-') {
        armor::decode_armor(message)
            .map(|(data, _kind)| data)
            .map_err(|error| match error {
                PgpError::ArmorError { reason } => PgpError::CorruptData {
                    reason: format!("Failed to parse message: {reason}"),
                },
                other => other,
            })
    } else {
        Ok(message.to_vec())
    }
}

fn collect_message_skesks(ciphertext: &[u8]) -> Result<Vec<SKESK>, PgpError> {
    let mut skesks: Vec<SKESK> = Vec::new();

    let end = bounded_walk::walk_message_prefix_bytes(ciphertext, |packet| {
        match packet {
            openpgp::Packet::SKESK(skesk) => {
                // Fail closed at the bound rather than after collecting: each
                // SKESK is both an allocation here and a full Argon2 KDF on a
                // wrong-password attempt, so an unbounded count would cost
                // twice over before anything refused it.
                if skesks.len() == MAX_MESSAGE_SKESK_PACKETS {
                    return Err(PgpError::MessageLimitsExceeded {
                        reason: format!(
                            "Message carries more than {MAX_MESSAGE_SKESK_PACKETS} SKESK packets"
                        ),
                    });
                }
                skesks.push(skesk.clone());
            }
            openpgp::Packet::SEIP(SEIP::V2(seip_v2)) => {
                if !seip_v2.symmetric_algo().is_supported() {
                    return Err(PgpError::UnsupportedAlgorithm {
                        algo: seip_v2.symmetric_algo().to_string(),
                    });
                }
                if !seip_v2.aead().is_supported() {
                    return Err(PgpError::UnsupportedAlgorithm {
                        algo: seip_v2.aead().to_string(),
                    });
                }
            }
            _ => {}
        }
        Ok(())
    })?;

    if end != bounded_walk::PrefixEnd::Container {
        return Err(PgpError::CorruptData {
            reason: "No encrypted data found in message".to_string(),
        });
    }

    Ok(skesks)
}

/// Ceiling on the Argon2 memory cost accepted from a password-encrypted message.
///
/// A password message carries attacker-chosen Argon2 parameters. RFC 9580 encodes
/// the memory cost as a `2^m` KiB exponent (up to 2 TiB); an absurd value exhausts
/// memory and Jetsam-kills the app on a decrypt attempt, before any authentication
/// runs. Our own traffic is unaffected: message encryption uses Sequoia's default
/// Iterated+Salted S2K (no Argon2), and the highest Argon2 cost we ever emit is the
/// 2 GiB key export. 2 GiB is RFC 9106's primary recommendation — the ceiling
/// admits it exactly and rejects the OOM-DoS range above it on the 8 GB minimum
/// device.
///
/// This is what the *format* may ask for. What *this device, right now* can
/// afford is a separate and smaller question, which only the host can answer;
/// it arrives as `affordable_memory_kib` and narrows this bound per call.
const MAX_MESSAGE_ARGON2_MEMORY_KIB: u64 = 2 * 1024 * 1024; // 2 GiB

/// Reject an Argon2 S2K whose time cost (passes) is implausibly high. Total KDF
/// work scales with memory × passes; memory is bounded above, so bounding passes
/// closes the remaining knob an attacker could turn to make a single decrypt
/// attempt run arbitrarily long. Our own export uses one pass; 16 leaves ample
/// headroom over RFC 9106's recommendations while rejecting the abuse range.
const MAX_MESSAGE_ARGON2_PASSES: u8 = 16;

/// Reject a password-encrypted message carrying an implausible number of SKESK
/// packets. Each SKESK is collected into memory and drives a full Argon2 KDF on
/// a wrong-password attempt, so an unbounded count multiplies the per-message
/// cost. A legitimate message carries one; 16 tolerates unusual multi-password
/// constructions.
const MAX_MESSAGE_SKESK_PACKETS: usize = 16;

fn validate_skesk(skesk: &SKESK, affordable_memory_kib: u64) -> Result<(), PgpError> {
    let s2k = match skesk {
        SKESK::V4(skesk_v4) => {
            if !skesk_v4.symmetric_algo().is_supported() {
                return Err(PgpError::UnsupportedAlgorithm {
                    algo: skesk_v4.symmetric_algo().to_string(),
                });
            }
            skesk_v4.s2k()
        }
        SKESK::V6(skesk_v6) => {
            if !skesk_v6.symmetric_algo().is_supported() {
                return Err(PgpError::UnsupportedAlgorithm {
                    algo: skesk_v6.symmetric_algo().to_string(),
                });
            }
            if !skesk_v6.aead_algo().is_supported() {
                return Err(PgpError::UnsupportedAlgorithm {
                    algo: skesk_v6.aead_algo().to_string(),
                });
            }
            skesk_v6.s2k()
        }
        _ => {
            return Err(PgpError::CorruptData {
                reason: "Unsupported SKESK packet version".to_string(),
            });
        }
    };

    validate_s2k_memory(s2k, affordable_memory_kib)
}

/// Reject an S2K whose Argon2 memory cost exceeds what either the format or this
/// device permits. Runs before `skesk.decrypt`, so the KDF never executes with a
/// parameter that would exhaust memory part-way through.
fn validate_s2k_memory(
    s2k: &openpgp::crypto::S2K,
    affordable_memory_kib: u64,
) -> Result<(), PgpError> {
    if let openpgp::crypto::S2K::Argon2 { m, t, .. } = s2k {
        let memory_kib = crate::keys::argon2_memory_kib(*m);
        if memory_kib > MAX_MESSAGE_ARGON2_MEMORY_KIB.min(affordable_memory_kib) {
            return Err(PgpError::Argon2idMemoryExceeded {
                required_mb: memory_kib / 1024,
            });
        }
        if *t > MAX_MESSAGE_ARGON2_PASSES {
            return Err(PgpError::CorruptData {
                reason: format!(
                    "Argon2 time cost {t} passes exceeds the maximum of {MAX_MESSAGE_ARGON2_PASSES}"
                ),
            });
        }
    }

    Ok(())
}

fn derive_candidate(
    skesk: &SKESK,
    password: &Password,
    affordable_memory_kib: u64,
) -> CandidateOutcome {
    if let Err(error) = validate_skesk(skesk, affordable_memory_kib) {
        return CandidateOutcome::DeferredError(error);
    }

    match skesk.decrypt(password) {
        Ok((session_key_algo, session_key)) => {
            if let Some(algo) = session_key_algo {
                if !algo.is_supported() {
                    return CandidateOutcome::DeferredError(PgpError::UnsupportedAlgorithm {
                        algo: algo.to_string(),
                    });
                }

                let expected_key_size = match algo.key_size() {
                    Ok(size) => size,
                    Err(_) => {
                        return CandidateOutcome::DeferredError(PgpError::UnsupportedAlgorithm {
                            algo: algo.to_string(),
                        });
                    }
                };
                if session_key.len() != expected_key_size {
                    return CandidateOutcome::Reject;
                }
            }

            CandidateOutcome::Candidate {
                session_key_algo,
                session_key,
            }
        }
        Err(error) => classify_candidate_error(error),
    }
}

fn classify_candidate_error(error: openpgp::anyhow::Error) -> CandidateOutcome {
    if let Some(openpgp_error) = error.downcast_ref::<openpgp::Error>() {
        return match openpgp_error {
            openpgp::Error::UnsupportedSymmetricAlgorithm(algo) => {
                CandidateOutcome::DeferredError(PgpError::UnsupportedAlgorithm {
                    algo: algo.to_string(),
                })
            }
            openpgp::Error::UnsupportedAEADAlgorithm(algo) => {
                CandidateOutcome::DeferredError(PgpError::UnsupportedAlgorithm {
                    algo: algo.to_string(),
                })
            }
            openpgp::Error::MalformedPacket(_)
            | openpgp::Error::MalformedMessage(_)
            | openpgp::Error::MalformedMPI(_)
            | openpgp::Error::PacketTooLarge(_, _, _)
            | openpgp::Error::UnsupportedPacketType(_) => {
                CandidateOutcome::DeferredError(PgpError::CorruptData {
                    reason: format!("Failed to decrypt password packet: {error}"),
                })
            }
            _ => CandidateOutcome::Reject,
        };
    }

    CandidateOutcome::Reject
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::packet::skesk::SKESK4;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp::crypto::{Password, S2K};

    /// Memory exponent the fixture packet is actually built at. Constructing a
    /// SKESK runs the KDF, so a hostile exponent cannot be requested from the
    /// constructor — it would exhaust the machine running the test rather than
    /// the code under test. Build affordably, then rewrite the exponent on the
    /// wire, which is exactly the shape a hostile message arrives in.
    const FIXTURE_BUILD_MEMORY_EXPONENT: u8 = 16; // 64 MiB
    const FIXTURE_SALT: [u8; 16] = [7u8; 16];
    const ARGON2_FIXTURE_PLAINTEXT: &[u8] = b"payload";

    /// A minimal password message whose single SKESK declares Argon2 at `2^m`
    /// KiB. Sequoia only ever emits the default Iterated+Salted S2K for our own
    /// traffic, so an Argon2-protected message has to be built by hand.
    fn password_message_with_argon2_skesk(m: u8, password: &Password) -> Vec<u8> {
        let session_key = openpgp::crypto::SessionKey::new(32).expect("session key");
        let skesk = SKESK4::with_password(
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES256,
            S2K::Argon2 {
                salt: FIXTURE_SALT,
                t: 1,
                p: 1,
                m: FIXTURE_BUILD_MEMORY_EXPONENT,
            },
            &session_key,
            password,
        )
        .expect("build Argon2 SKESK");

        let mut sink = Vec::new();
        openpgp::Packet::from(skesk)
            .serialize(&mut sink)
            .expect("serialize SKESK");
        if m != FIXTURE_BUILD_MEMORY_EXPONENT {
            rewrite_argon2_memory_exponent(&mut sink, m);
        }

        // The container the SKESK's session key opens.
        let mut container = Vec::new();
        {
            let message = Message::new(&mut container);
            let encryptor = Encryptor::with_session_key(
                message,
                SymmetricAlgorithm::AES256,
                session_key.clone(),
            )
            .expect("session-key encryptor");
            let message = encryptor.build().expect("build container");
            let mut literal = openpgp::serialize::stream::LiteralWriter::new(message)
                .build()
                .expect("build literal");
            std::io::Write::write_all(&mut literal, ARGON2_FIXTURE_PLAINTEXT)
                .expect("write payload");
            literal.finalize().expect("finalize container");
        }
        sink.extend_from_slice(&container);
        sink
    }

    /// Rewrite the memory exponent of the serialized Argon2 S2K in place. An
    /// Argon2 S2K spec is `[0x04][salt: 16][t][p][m]`, and the fixture's salt
    /// makes the needle unique within the packet.
    fn rewrite_argon2_memory_exponent(skesk_packet: &mut [u8], m: u8) {
        let mut needle = vec![0x04u8];
        needle.extend_from_slice(&FIXTURE_SALT);
        needle.extend_from_slice(&[1, 1, FIXTURE_BUILD_MEMORY_EXPONENT]);

        let start = skesk_packet
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("serialized Argon2 S2K spec should be present");
        skesk_packet[start + needle.len() - 1] = m;
    }

    #[test]
    fn validate_s2k_memory_rejects_oversized_argon2() {
        // m = 30 -> 2^30 KiB = 1 TiB, far past the ceiling: a decrypt-time OOM
        // DoS that must be refused before the KDF runs.
        let s2k = S2K::Argon2 {
            salt: [0u8; 16],
            t: 1,
            p: 1,
            m: 30,
        };
        assert!(matches!(
            validate_s2k_memory(&s2k, u64::MAX),
            Err(PgpError::Argon2idMemoryExceeded { .. })
        ));
    }

    #[test]
    fn decrypt_refuses_a_message_beyond_the_format_ceiling() {
        // The whole packet path, not just the predicate: a real SKESK at 1 TiB
        // must come back refused rather than derived, however much memory the
        // device claims to have.
        let password = Password::from("irrelevant");
        let message = password_message_with_argon2_skesk(30, &password);

        match decrypt(&message, &password, &[], u64::MAX) {
            Err(PgpError::Argon2idMemoryExceeded { required_mb }) => {
                assert_eq!(required_mb, 1024 * 1024, "1 TiB expressed in MiB");
            }
            other => panic!("expected Argon2idMemoryExceeded, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_refuses_a_cost_this_device_cannot_afford() {
        // 64 MiB is far inside the format ceiling, so only the device budget can
        // refuse it — and it must, before the KDF runs.
        let password = Password::from("irrelevant");
        let message = password_message_with_argon2_skesk(16, &password);

        match decrypt(&message, &password, &[], 32 * 1024) {
            Err(PgpError::Argon2idMemoryExceeded { required_mb }) => {
                assert_eq!(required_mb, 64);
            }
            other => panic!("expected Argon2idMemoryExceeded, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_derives_a_cost_this_device_can_afford() {
        // The same message under a budget that admits it opens normally, which
        // is what makes the refusal above the budget talking rather than the
        // packet being rejected for some other reason.
        let password = Password::from("irrelevant");
        let message = password_message_with_argon2_skesk(16, &password);

        let result =
            decrypt(&message, &password, &[], 128 * 1024).expect("an affordable cost must run");
        assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
        assert_eq!(result.plaintext.as_deref(), Some(ARGON2_FIXTURE_PLAINTEXT));
    }

    #[test]
    fn message_ceiling_admits_our_own_export_cost() {
        // Our key export emits RFC 9106's primary recommendation, which lands
        // exactly on this ceiling. Raising the export cost past it would leave
        // us refusing a memory cost we ourselves consider legitimate.
        let export = crate::keys::export_s2k_params(crate::keys::KeySuite::Ed448X448);
        assert!(
            export.memory_kib <= MAX_MESSAGE_ARGON2_MEMORY_KIB,
            "export costs {} KiB but messages are capped at {MAX_MESSAGE_ARGON2_MEMORY_KIB} KiB",
            export.memory_kib
        );
    }

    #[test]
    fn validate_s2k_memory_rejects_excessive_passes() {
        // Legal memory but an abusive time cost: bounded so a single decrypt
        // attempt cannot be driven arbitrarily long.
        let s2k = S2K::Argon2 {
            salt: [0u8; 16],
            t: MAX_MESSAGE_ARGON2_PASSES + 1,
            p: 1,
            m: 19,
        };
        assert!(matches!(
            validate_s2k_memory(&s2k, u64::MAX),
            Err(PgpError::CorruptData { .. })
        ));
    }

    #[test]
    fn validate_s2k_memory_accepts_passes_at_the_bound() {
        let s2k = S2K::Argon2 {
            salt: [0u8; 16],
            t: MAX_MESSAGE_ARGON2_PASSES,
            p: 1,
            m: 19,
        };
        assert!(validate_s2k_memory(&s2k, u64::MAX).is_ok());
    }

    #[test]
    fn own_password_message_round_trips_through_memory_clamp() {
        // Proves the clamp does not reject our own password-encrypted messages:
        // encrypt then decrypt must succeed through `validate_skesk`.
        let password = Password::from("correct horse battery staple");
        let ciphertext = encrypt(b"hello", &password, PasswordMessageFormat::Seipdv2, None)
            .expect("encrypt password message");
        let result =
            decrypt(&ciphertext, &password, &[], u64::MAX).expect("decrypt password message");
        assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
        assert_eq!(result.plaintext.as_deref(), Some(&b"hello"[..]));
    }
}
