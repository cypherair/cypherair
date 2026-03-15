use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;

// Note: `zeroize` is not explicitly used here because Sequoia's `KeyPair` type manages
// its own secret key material lifecycle. The `into_keypair()` call extracts the secret
// from the Cert, and the KeyPair is consumed by the Signer, which handles cleanup.

/// Extract a signing keypair from a certificate.
/// Used by sign_cleartext, sign_detached, and streaming::sign_detached_file.
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
    .map_err(|e| PgpError::SigningFailed {
        reason: format!("Signer setup failed: {e}"),
    })?;

    // Write text directly to the signer (no LiteralWriter for cleartext sigs).
    std::io::Write::write_all(&mut signer, text).map_err(|e| PgpError::SigningFailed {
        reason: format!("Write failed: {e}"),
    })?;

    signer.finalize().map_err(|e| PgpError::SigningFailed {
        reason: format!("Finalize failed: {e}"),
    })?;

    Ok(sink)
}

/// Create a detached signature for file content.
/// Returns the signature in binary OpenPGP format.
pub fn sign_detached(data: &[u8], signer_cert_data: &[u8]) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let signing_keypair = extract_signing_keypair(signer_cert_data, &policy)?;

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

    std::io::copy(&mut &data[..], &mut signer).map_err(|e| PgpError::SigningFailed {
        reason: format!("Write failed: {e}"),
    })?;

    signer.finalize().map_err(|e| PgpError::SigningFailed {
        reason: format!("Finalize failed: {e}"),
    })?;

    Ok(sink)
}
