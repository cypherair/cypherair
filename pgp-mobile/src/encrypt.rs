use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;

/// Encrypt plaintext for the given recipients.
///
/// Message format is determined automatically by recipient key versions:
/// - All v4 recipients → SEIPDv1 (MDC)
/// - All v6 recipients → SEIPDv2 (AEAD OCB)
/// - Mixed v4+v6 → SEIPDv1 (lowest common denominator)
///
/// Sequoia handles format auto-selection when recipient certs are passed
/// to the encryption API.
///
/// Parameters:
/// - `plaintext`: The data to encrypt.
/// - `recipient_certs`: Binary OpenPGP public key data for each recipient.
/// - `signing_key`: Optional full cert (with secret) for signing the message.
/// - `encrypt_to_self`: Optional own public key to add as recipient.
///
/// Returns ASCII-armored ciphertext.
pub fn encrypt(
    plaintext: &[u8],
    recipient_certs: &[Vec<u8>],
    signing_key: Option<&[u8]>,
    encrypt_to_self: Option<&[u8]>,
) -> Result<Vec<u8>, PgpError> {
    if recipient_certs.is_empty() && encrypt_to_self.is_none() {
        return Err(PgpError::EncryptionFailed {
            reason: "No recipients specified".to_string(),
        });
    }

    let policy = StandardPolicy::new();

    // Parse all recipient certificates
    let mut recipients = Vec::new();
    for cert_data in recipient_certs {
        let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid recipient key: {e}"),
            }
        })?;
        recipients.push(cert);
    }

    // Add encrypt-to-self recipient if provided
    if let Some(self_cert_data) = encrypt_to_self {
        let self_cert = openpgp::Cert::from_bytes(self_cert_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid self key: {e}"),
            }
        })?;
        recipients.push(self_cert);
    }

    // Collect encryption-capable subkeys from all recipients
    let mut recipient_keys: Vec<Recipient> = Vec::new();
    for cert in &recipients {
        let mut found = false;
        for key in cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .for_transport_encryption()
        {
            recipient_keys.push(key.key().into());
            found = true;
        }
        if !found {
            return Err(PgpError::EncryptionFailed {
                reason: format!(
                    "Recipient {} has no valid encryption subkey",
                    cert.fingerprint()
                ),
            });
        }
    }

    // Build the message
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    // Armor the output
    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Message)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Armor setup failed: {e}"),
        })?;

    // Set up encryption — Sequoia automatically selects SEIPDv1 or SEIPDv2
    // based on the recipient key versions
    let message = Encryptor2::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;

    // Optionally sign
    let message = if let Some(signer_data) = signing_key {
        let signer_cert = openpgp::Cert::from_bytes(signer_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid signing key: {e}"),
            }
        })?;

        let signing_keypair = signer_cert
            .keys()
            .with_policy(&policy, None)
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
            })?;

        Signer::new(message, signing_keypair)
            .build()
            .map_err(|e| PgpError::SigningFailed {
                reason: format!("Signer setup failed: {e}"),
            })?
    } else {
        message
    };

    // Write the literal data (no compression — outgoing messages must not compress)
    let mut literal = LiteralWriter::new(message)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Literal writer setup failed: {e}"),
        })?;

    std::io::copy(&mut &plaintext[..], &mut literal).map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Write failed: {e}"),
    })?;

    literal.finalize().map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Finalize failed: {e}"),
    })?;

    Ok(sink)
}

/// Encrypt plaintext and return binary (non-armored) ciphertext.
/// Used for file encryption where .gpg output is preferred.
pub fn encrypt_binary(
    plaintext: &[u8],
    recipient_certs: &[Vec<u8>],
    signing_key: Option<&[u8]>,
    encrypt_to_self: Option<&[u8]>,
) -> Result<Vec<u8>, PgpError> {
    if recipient_certs.is_empty() && encrypt_to_self.is_none() {
        return Err(PgpError::EncryptionFailed {
            reason: "No recipients specified".to_string(),
        });
    }

    let policy = StandardPolicy::new();

    let mut recipients = Vec::new();
    for cert_data in recipient_certs {
        let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid recipient key: {e}"),
            }
        })?;
        recipients.push(cert);
    }

    if let Some(self_cert_data) = encrypt_to_self {
        let self_cert = openpgp::Cert::from_bytes(self_cert_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid self key: {e}"),
            }
        })?;
        recipients.push(self_cert);
    }

    let mut recipient_keys: Vec<Recipient> = Vec::new();
    for cert in &recipients {
        for key in cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .for_transport_encryption()
        {
            recipient_keys.push(key.key().into());
        }
    }

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = Encryptor2::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;

    let message = if let Some(signer_data) = signing_key {
        let signer_cert = openpgp::Cert::from_bytes(signer_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid signing key: {e}"),
            }
        })?;

        let signing_keypair = signer_cert
            .keys()
            .with_policy(&policy, None)
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
            })?;

        Signer::new(message, signing_keypair)
            .build()
            .map_err(|e| PgpError::SigningFailed {
                reason: format!("Signer setup failed: {e}"),
            })?
    } else {
        message
    };

    let mut literal = LiteralWriter::new(message)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Literal writer setup failed: {e}"),
        })?;

    std::io::copy(&mut &plaintext[..], &mut literal).map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Write failed: {e}"),
    })?;

    literal.finalize().map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Finalize failed: {e}"),
    })?;

    Ok(sink)
}
