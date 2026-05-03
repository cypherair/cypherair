use super::*;

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

/// Generate a User ID-specific revocation signature from an existing secret certificate.
///
/// Legacy compatibility path: if the certificate contains duplicate User ID bytes,
/// this selects the first matching occurrence.
pub fn generate_user_id_revocation(
    secret_cert: &[u8],
    user_id_data: &[u8],
) -> Result<Vec<u8>, PgpError> {
    let cert = parse_cert_for_revocation(secret_cert)?;
    let mut signer = primary_signer_for_revocation(&cert)?;
    let user_id = cert
        .userids()
        .find(|ua| ua.userid().value() == user_id_data)
        .ok_or_else(|| PgpError::InvalidKeyData {
            reason: "User ID bytes not found in certificate".to_string(),
        })?;

    let sig = UserIDRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to configure User ID revocation: {e}"),
        })?
        .build(&mut signer, &cert, user_id.userid(), None)
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to generate User ID revocation: {e}"),
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
