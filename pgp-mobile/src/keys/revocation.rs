use super::*;
use std::sync::Arc;

use crate::external_signer::{map_external_signing_error, signer_for_provider};

fn parse_cert_for_revocation(secret_cert: &[u8]) -> Result<openpgp::Cert, PgpError> {
    openpgp::Cert::from_bytes(secret_cert).map_err(|e| PgpError::InvalidKeyData {
        reason: format!("Secret certificate required: {e}"),
    })
}

fn primary_signer_for_revocation(
    cert: &openpgp::Cert,
) -> Result<openpgp::crypto::KeyPair, PgpError> {
    cert.primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Secret certificate required: {e}"),
        })?
        .into_keypair()
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Secret certificate required: {e}"),
        })
}

fn serialize_revocation_signature(sig: openpgp::packet::Signature) -> Result<Vec<u8>, PgpError> {
    let mut revocation = Vec::new();
    openpgp::Packet::from(sig)
        .serialize(&mut revocation)
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to serialize revocation signature: {e}"),
        })?;
    Ok(revocation)
}

fn parse_public_cert_for_external_revocation(
    public_cert: &[u8],
) -> Result<openpgp::Cert, PgpError> {
    let cert = openpgp::Cert::from_bytes(public_cert).map_err(|e| PgpError::InvalidKeyData {
        reason: format!("Invalid external revocation public certificate: {e}"),
    })?;
    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External revocation requires a public certificate".to_string(),
        });
    }
    Ok(cert)
}

fn ensure_external_revocation_certificate_not_revoked(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    reference_time: SystemTime,
) -> Result<(), PgpError> {
    let valid_cert = cert
        .with_policy(policy, Some(reference_time))
        .map_err(|error| PgpError::RevocationError {
            reason: format!("External revocation certificate is not policy-valid: {error}"),
        })?;
    match valid_cert.revocation_status() {
        RevocationStatus::NotAsFarAsWeKnow => Ok(()),
        RevocationStatus::Revoked(_) => Err(PgpError::RevocationError {
            reason: "Cannot generate selective revocation for a revoked certificate".to_string(),
        }),
        RevocationStatus::CouldBe(_) => Err(PgpError::RevocationError {
            reason: "Cannot generate selective revocation for a certificate with unresolved revocation status".to_string(),
        }),
    }
}

fn select_external_revocation_primary_signing_key(
    cert: &openpgp::Cert,
    signing_key_fingerprint: &str,
    policy: &StandardPolicy,
    reference_time: SystemTime,
) -> Result<
    openpgp::packet::key::Key<
        openpgp::packet::key::PublicParts,
        openpgp::packet::key::UnspecifiedRole,
    >,
    PgpError,
> {
    let expected_fingerprint = signing_key_fingerprint.trim();
    if expected_fingerprint.is_empty() {
        return Err(PgpError::InvalidKeyData {
            reason: "External revocation signer expected fingerprint must not be empty".to_string(),
        });
    }

    let primary_fingerprint = cert.primary_key().key().fingerprint().to_hex();
    if !primary_fingerprint.eq_ignore_ascii_case(expected_fingerprint) {
        return Err(PgpError::RevocationError {
            reason: "External revocation requires the primary signing key".to_string(),
        });
    }

    let primary = cert
        .primary_key()
        .with_policy(policy, Some(reference_time))
        .map_err(|error| PgpError::RevocationError {
            reason: format!("No policy-valid external revocation primary key found: {error}"),
        })?;
    if !primary.key().pk_algo().is_supported() {
        return Err(PgpError::RevocationError {
            reason: "External revocation primary signing key uses an unsupported algorithm"
                .to_string(),
        });
    }
    if !primary.for_signing() {
        return Err(PgpError::RevocationError {
            reason: "External revocation primary key is not signing-capable".to_string(),
        });
    }

    Ok(primary.key().role_as_unspecified().clone())
}

/// Generate a key-level revocation signature from an existing secret certificate.
pub fn generate_key_revocation(secret_cert: &[u8]) -> Result<Vec<u8>, PgpError> {
    let cert = parse_cert_for_revocation(secret_cert)?;
    let mut signer = primary_signer_for_revocation(&cert)?;
    let sig = cert
        .revoke(&mut signer, ReasonForRevocation::KeyRetired, b"")
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to generate key revocation: {e}"),
        })?;
    serialize_revocation_signature(sig)
}

/// Generate a subkey-specific revocation signature from an existing secret certificate.
pub fn generate_subkey_revocation(
    secret_cert: &[u8],
    subkey_fingerprint: &str,
) -> Result<Vec<u8>, PgpError> {
    let cert = parse_cert_for_revocation(secret_cert)?;
    let mut signer = primary_signer_for_revocation(&cert)?;
    let normalized_subkey_fingerprint = subkey_fingerprint.to_lowercase();
    let subkey = cert
        .keys()
        .subkeys()
        .find(|ka| ka.key().fingerprint().to_hex().to_lowercase() == normalized_subkey_fingerprint)
        .ok_or_else(|| PgpError::InvalidKeyData {
            reason: "Subkey fingerprint not found in certificate".to_string(),
        })?;

    let sig = SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"")
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to configure subkey revocation: {e}"),
        })?
        .build(&mut signer, &cert, subkey.key(), None)
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to generate subkey revocation: {e}"),
        })?;

    serialize_revocation_signature(sig)
}

/// Generate a subkey-specific revocation signature from a public-only P-256
/// certificate through an external signing provider.
pub fn generate_subkey_revocation_with_external_p256_signer(
    public_cert: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
    subkey_fingerprint: &str,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let reference_time = SystemTime::now();
    let cert = parse_public_cert_for_external_revocation(public_cert)?;
    ensure_external_revocation_certificate_not_revoked(&cert, &policy, reference_time)?;
    let signing_public_key = select_external_revocation_primary_signing_key(
        &cert,
        signing_key_fingerprint,
        &policy,
        reference_time,
    )?;
    let mut external_signer = signer_for_provider(signing_public_key, signer).map_err(|error| {
        PgpError::RevocationError {
            reason: format!("External signer setup failed: {error}"),
        }
    })?;

    let normalized_subkey_fingerprint = subkey_fingerprint.to_lowercase();
    let subkey = cert
        .keys()
        .subkeys()
        .find(|ka| ka.key().fingerprint().to_hex().to_lowercase() == normalized_subkey_fingerprint)
        .ok_or_else(|| PgpError::InvalidKeyData {
            reason: "Subkey fingerprint not found in certificate".to_string(),
        })?;

    let sig = SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"")
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to configure subkey revocation: {e}"),
        })?
        .build(
            &mut external_signer,
            &cert,
            subkey.key(),
            Some(openpgp::types::HashAlgorithm::SHA256),
        )
        .map_err(|error| {
            map_external_signing_error(error, |reason| PgpError::RevocationError {
                reason: format!("Failed to generate subkey revocation: {reason}"),
            })
        })?;

    serialize_revocation_signature(sig)
}

/// Generate a User ID-specific revocation signature using an explicit selector.
pub fn generate_user_id_revocation_by_selector(
    secret_cert: &[u8],
    user_id_selector: &UserIdSelectorInput,
) -> Result<Vec<u8>, PgpError> {
    let cert = parse_cert_for_revocation(secret_cert)?;
    let mut signer = primary_signer_for_revocation(&cert)?;
    let user_id = find_user_id_by_selector(secret_cert, user_id_selector)?;

    let sig = UserIDRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to configure User ID revocation: {e}"),
        })?
        .build(&mut signer, &cert, &user_id, None)
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to generate User ID revocation: {e}"),
        })?;

    serialize_revocation_signature(sig)
}

/// Generate a User ID-specific revocation signature from a public-only P-256
/// certificate through an external signing provider.
pub fn generate_user_id_revocation_by_selector_with_external_p256_signer(
    public_cert: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
    user_id_selector: &UserIdSelectorInput,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let reference_time = SystemTime::now();
    let cert = parse_public_cert_for_external_revocation(public_cert)?;
    ensure_external_revocation_certificate_not_revoked(&cert, &policy, reference_time)?;
    let signing_public_key = select_external_revocation_primary_signing_key(
        &cert,
        signing_key_fingerprint,
        &policy,
        reference_time,
    )?;
    let mut external_signer = signer_for_provider(signing_public_key, signer).map_err(|error| {
        PgpError::RevocationError {
            reason: format!("External signer setup failed: {error}"),
        }
    })?;
    let user_id = find_user_id_by_selector(public_cert, user_id_selector)?;

    let sig = UserIDRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to configure User ID revocation: {e}"),
        })?
        .build(
            &mut external_signer,
            &cert,
            &user_id,
            Some(openpgp::types::HashAlgorithm::SHA256),
        )
        .map_err(|error| {
            map_external_signing_error(error, |reason| PgpError::RevocationError {
                reason: format!("Failed to generate User ID revocation: {reason}"),
            })
        })?;

    serialize_revocation_signature(sig)
}

/// Parse a revocation certificate and cryptographically verify it against the target key.
pub fn parse_revocation_cert(rev_data: &[u8], cert_data: &[u8]) -> Result<String, PgpError> {
    let pkt = openpgp::Packet::from_bytes(rev_data).map_err(|e| PgpError::RevocationError {
        reason: format!("Failed to parse revocation cert: {e}"),
    })?;

    let sig = match pkt {
        openpgp::Packet::Signature(sig) => {
            if sig.typ() == openpgp::types::SignatureType::KeyRevocation {
                sig
            } else {
                return Err(PgpError::RevocationError {
                    reason: format!("Not a key revocation signature: {:?}", sig.typ()),
                });
            }
        }
        _ => {
            return Err(PgpError::RevocationError {
                reason: "Not a signature packet".to_string(),
            });
        }
    };

    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    // Cryptographically verify the revocation signature against the target key.
    let primary_key = cert.primary_key().key();
    sig.verify_primary_key_revocation(primary_key, primary_key)
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Revocation signature is not valid for this key: {e}"),
        })?;

    let fingerprint = cert.fingerprint().to_hex().to_lowercase();
    Ok(format!("Valid key revocation signature for {fingerprint}"))
}
