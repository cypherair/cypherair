use std::sync::Arc;

use openpgp::packet::{key, Key};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;
use crate::external_signer::{map_external_signing_error, signer_for_provider};
use crate::keys::ExternalP256SigningProvider;

// Note: `zeroize` is not explicitly used here because Sequoia's `KeyPair` type manages
// its own secret key material lifecycle. The `into_keypair()` call extracts the secret
// from the Cert, and the KeyPair is consumed by the Signer, which handles cleanup.

/// Extract a signing keypair from a certificate.
/// Used by cleartext signing, streaming file signing, and external signer tests.
pub(crate) fn extract_signing_keypair(
    cert_data: &[u8],
    policy: &StandardPolicy,
) -> Result<openpgp::crypto::KeyPair, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: format!("Invalid signing key: {e}"),
    })?;

    cert.keys()
        .with_policy(policy, None)
        .supported()
        .secret()
        .for_signing()
        .next()
        .ok_or(PgpError::SigningFailed {
            reason: "No signing-capable secret key found".to_string(),
        })?
        .key()
        .clone()
        .into_keypair()
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Failed to create signing keypair: {e}"),
        })
}

/// Create a cleartext signature for text content.
/// Produces a cleartext-signed message (text + inline signature).
pub fn sign_cleartext(text: &[u8], signer_cert_data: &[u8]) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let signing_keypair = extract_signing_keypair(signer_cert_data, &policy)?;

    sign_cleartext_with_signer(text, signing_keypair)
}

pub fn sign_cleartext_with_external_p256_signer(
    text: &[u8],
    public_cert_data: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let signing_public_key =
        select_external_p256_signing_key(public_cert_data, signing_key_fingerprint, &policy)?;
    let external_signer = signer_for_provider(signing_public_key, signer).map_err(|error| {
        PgpError::SigningFailed {
            reason: format!("External signer setup failed: {error}"),
        }
    })?;

    sign_cleartext_with_signer(text, external_signer)
}

pub(crate) fn select_external_p256_signing_key(
    public_cert_data: &[u8],
    signing_key_fingerprint: &str,
    policy: &StandardPolicy,
) -> Result<Key<key::PublicParts, key::UnspecifiedRole>, PgpError> {
    let expected_fingerprint = signing_key_fingerprint.trim().to_ascii_lowercase();
    if expected_fingerprint.is_empty() {
        return Err(PgpError::InvalidKeyData {
            reason: "External signer expected fingerprint must not be empty".to_string(),
        });
    }

    let cert =
        openpgp::Cert::from_bytes(public_cert_data).map_err(|error| PgpError::InvalidKeyData {
            reason: format!("Invalid external signer public certificate: {error}"),
        })?;
    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External signer requires a public certificate".to_string(),
        });
    }

    cert.keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .for_signing()
        .find(|key| {
            key.key()
                .fingerprint()
                .to_hex()
                .eq_ignore_ascii_case(&expected_fingerprint)
        })
        .map(|key| key.key().role_as_unspecified().clone())
        .ok_or(PgpError::SigningFailed {
            reason: "No matching external signing key found".to_string(),
        })
}

pub(crate) fn sign_cleartext_with_signer<S>(
    text: &[u8],
    signing_keypair: S,
) -> Result<Vec<u8>, PgpError>
where
    S: openpgp::crypto::Signer + Send + Sync,
{
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    // Cleartext signatures handle their own ASCII formatting — no Armorer needed.
    // The Signer with .cleartext() produces the -----BEGIN PGP SIGNED MESSAGE----- format.
    let mut signer = Signer::with_template(
        message,
        signing_keypair,
        openpgp::packet::signature::SignatureBuilder::new(openpgp::types::SignatureType::Text),
    )
    .map_err(|e| PgpError::SigningFailed {
        reason: format!("Signer setup failed: {e}"),
    })?
    .cleartext()
    .build()
    .map_err(|error| map_signing_error("Signer setup failed", error))?;

    // Write text directly to the signer (no LiteralWriter for cleartext sigs).
    std::io::Write::write_all(&mut signer, text).map_err(|e| PgpError::SigningFailed {
        reason: format!("Write failed: {e}"),
    })?;

    signer
        .finalize()
        .map_err(|error| map_signing_error("Finalize failed", error))?;

    Ok(sink)
}

fn map_signing_error(context: &str, error: openpgp::anyhow::Error) -> PgpError {
    map_external_signing_error(error, |reason| PgpError::SigningFailed {
        reason: format!("{context}: {reason}"),
    })
}

#[cfg(test)]
pub(crate) fn sign_detached_with_signer<S>(
    data: &[u8],
    signing_keypair: S,
) -> Result<Vec<u8>, PgpError>
where
    S: openpgp::crypto::Signer + Send + Sync,
{
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Signature)
        .build()
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Armor setup failed: {e}"),
        })?;

    let mut signer = Signer::new(message, signing_keypair)
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Signer setup failed: {e}"),
        })?
        .detached()
        .build()
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Signer setup failed: {e}"),
        })?;

    std::io::Write::write_all(&mut signer, data).map_err(|e| PgpError::SigningFailed {
        reason: format!("Write failed: {e}"),
    })?;

    signer.finalize().map_err(|e| PgpError::SigningFailed {
        reason: format!("Finalize failed: {e}"),
    })?;

    Ok(sink)
}
