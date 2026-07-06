use std::sync::Arc;

use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::{SEIP, SKESK};
use openpgp::parse::Parse;
use openpgp::serialize::stream::{Armorer, Encryptor, Message};
use openpgp::types::{AEADAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp as openpgp;

use crate::armor;
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
pub fn decrypt(
    encrypted_message: &[u8],
    password: &Password,
    verification_keys: &[Vec<u8>],
) -> Result<PasswordDecryptResult, PgpError> {
    let normalized = normalize_message_bytes(encrypted_message)?;
    let context = collect_message_context(&normalized)?;
    if context.skesks.is_empty() {
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

    for skesk in &context.skesks {
        let (session_key_algo, session_key) = match derive_candidate(skesk, password) {
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

struct PasswordMessageContext {
    skesks: Vec<SKESK>,
    saw_encryption_container: bool,
}

fn collect_message_context(ciphertext: &[u8]) -> Result<PasswordMessageContext, PgpError> {
    let mut context = PasswordMessageContext {
        skesks: Vec::new(),
        saw_encryption_container: false,
    };

    let ppr = openpgp::parse::PacketParser::from_bytes(ciphertext).map_err(|e| {
        PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        }
    })?;
    let mut ppr = ppr;
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        match &pp.packet {
            openpgp::Packet::SKESK(skesk) => context.skesks.push(skesk.clone()),
            openpgp::Packet::SEIP(seip) => {
                context.saw_encryption_container = true;
                if let SEIP::V2(seip_v2) = seip {
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
                break;
            }
            _ => {}
        }

        let (_, next) = pp.recurse().map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?;
        ppr = next;
    }

    if !context.saw_encryption_container {
        return Err(PgpError::CorruptData {
            reason: "No encrypted data found in message".to_string(),
        });
    }

    Ok(context)
}

fn validate_skesk(skesk: &SKESK) -> Result<(), PgpError> {
    match skesk {
        SKESK::V4(skesk_v4) => {
            if !skesk_v4.symmetric_algo().is_supported() {
                return Err(PgpError::UnsupportedAlgorithm {
                    algo: skesk_v4.symmetric_algo().to_string(),
                });
            }
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
        }
        _ => {
            return Err(PgpError::CorruptData {
                reason: "Unsupported SKESK packet version".to_string(),
            });
        }
    }

    Ok(())
}

fn derive_candidate(skesk: &SKESK, password: &Password) -> CandidateOutcome {
    if let Err(error) = validate_skesk(skesk) {
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
