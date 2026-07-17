use std::io::Write;
use std::sync::Arc;

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::types::RevocationStatus;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;
use crate::external_composite_signer::{
    composite_high_signer_for_provider, composite_signer_for_provider,
};
use crate::external_signer::{map_external_signing_error, signer_for_provider};
use crate::keys::{
    ExternalMlDsa65SigningProvider, ExternalMlDsa87SigningProvider, ExternalP256SigningProvider,
};
use crate::sign::select_external_signing_key;

/// Parse recipient certificates, validate each has at least one encryption-capable
/// subkey, deduplicate by fingerprint, and return the parsed certs.
pub(crate) fn collect_recipients(
    recipient_certs: &[Vec<u8>],
    encrypt_to_self: Option<&[u8]>,
    policy: &StandardPolicy,
) -> Result<Vec<openpgp::Cert>, PgpError> {
    if recipient_certs.is_empty() && encrypt_to_self.is_none() {
        return Err(PgpError::EncryptionFailed {
            reason: "No recipients specified".to_string(),
        });
    }

    let mut certs = Vec::new();
    let mut seen_fingerprints = std::collections::HashSet::new();

    for cert_data in recipient_certs {
        let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Invalid recipient key: {e}"),
        })?;
        let fp = cert.fingerprint().to_hex();
        if seen_fingerprints.insert(fp) {
            certs.push(cert);
        }
    }

    if let Some(self_cert_data) = encrypt_to_self {
        let self_cert =
            openpgp::Cert::from_bytes(self_cert_data).map_err(|e| PgpError::InvalidKeyData {
                reason: format!("Invalid self key: {e}"),
            })?;
        // Deduplicate: skip if already in recipients (e.g., encrypt-to-self with own key as recipient)
        let fp = self_cert.fingerprint().to_hex();
        if seen_fingerprints.insert(fp) {
            certs.push(self_cert);
        }
    }

    // Validate each cert: not revoked, and has at least one live encryption-capable subkey
    for cert in &certs {
        // Reject revoked certificates (key-level revocation)
        if matches!(
            cert.revocation_status(policy, None),
            RevocationStatus::Revoked(_)
        ) {
            return Err(PgpError::EncryptionFailed {
                reason: format!("Recipient {} key is revoked", cert.fingerprint()),
            });
        }

        let found = cert
            .keys()
            .with_policy(policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .next()
            .is_some();
        if !found {
            return Err(PgpError::EncryptionFailed {
                reason: format!(
                    "Recipient {} has no valid encryption subkey",
                    cert.fingerprint()
                ),
            });
        }
    }

    Ok(certs)
}

/// Collect Recipient objects from parsed certs. Must be called where certs are
/// in scope so the borrowed Recipient references remain valid.
pub(crate) fn build_recipients<'a>(
    certs: &'a [openpgp::Cert],
    policy: &'a StandardPolicy<'a>,
) -> Vec<Recipient<'a>> {
    let mut recipient_keys: Vec<Recipient> = Vec::new();
    for cert in certs {
        for ka in cert
            .keys()
            .with_policy(policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            recipient_keys.push(ka.into());
        }
    }
    recipient_keys
}

/// Set up an optional signer for the message pipeline.
pub(crate) fn setup_signer<'a>(
    message: Message<'a>,
    signing_key: Option<&[u8]>,
    policy: &StandardPolicy,
) -> Result<Message<'a>, PgpError> {
    if let Some(signer_data) = signing_key {
        let signer_cert =
            openpgp::Cert::from_bytes(signer_data).map_err(|e| PgpError::InvalidKeyData {
                reason: format!("Invalid signing key: {e}"),
            })?;

        // `.revoked(false)` skips a revoked signing subkey, mirroring recipient
        // selection above: a cert with a live primary but a hard-revoked
        // signing subkey must not sign the message. If another live, unrevoked
        // signing key remains it is used; only when none does the
        // no-valid-signing-key error fire.
        let signing_keypair = signer_cert
            .keys()
            .with_policy(policy, None)
            .supported()
            .revoked(false)
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
            .map_err(|e| PgpError::SigningFailed {
                reason: format!("Signer setup failed: {e}"),
            })?
            .build()
            .map_err(|e| PgpError::SigningFailed {
                reason: format!("Signer setup failed: {e}"),
            })
    } else {
        Ok(message)
    }
}

/// Set up an external P-256 signer for a message pipeline.
pub(crate) fn setup_external_p256_signer<'a>(
    message: Message<'a>,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
    policy: &StandardPolicy,
) -> Result<Message<'a>, PgpError> {
    let signing_public_key =
        select_external_signing_key(signing_public_cert, signing_key_fingerprint, policy)?;
    let external_signer = signer_for_provider(signing_public_key, signer).map_err(|error| {
        PgpError::SigningFailed {
            reason: format!("External signer setup failed: {error}"),
        }
    })?;

    Signer::new(message, external_signer)
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Signer setup failed: {e}"),
        })?
        .build()
        .map_err(|error| map_external_signing_error(error, signer_error("Signer setup failed")))
}

/// Set up an external split-custody composite signer for a message pipeline.
pub(crate) fn setup_external_composite_signer<'a>(
    message: Message<'a>,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa65SigningProvider>,
    policy: &StandardPolicy,
) -> Result<Message<'a>, PgpError> {
    let signing_public_key =
        select_external_signing_key(signing_public_cert, signing_key_fingerprint, policy)?;
    let external_signer =
        composite_signer_for_provider(signing_public_key, classical_eddsa_secret, signer).map_err(
            |error| PgpError::SigningFailed {
                reason: format!("External signer setup failed: {error}"),
            },
        )?;

    Signer::new(message, external_signer)
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Signer setup failed: {e}"),
        })?
        .build()
        .map_err(|error| map_external_signing_error(error, signer_error("Signer setup failed")))
}

/// Device-Bound Post-Quantum · High analog of `setup_external_composite_signer`
/// (ML-DSA-87 + Ed448).
pub(crate) fn setup_external_composite_high_signer<'a>(
    message: Message<'a>,
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa87SigningProvider>,
    policy: &StandardPolicy,
) -> Result<Message<'a>, PgpError> {
    let signing_public_key =
        select_external_signing_key(signing_public_cert, signing_key_fingerprint, policy)?;
    let external_signer =
        composite_high_signer_for_provider(signing_public_key, classical_eddsa_secret, signer)
            .map_err(|error| PgpError::SigningFailed {
                reason: format!("External signer setup failed: {error}"),
            })?;

    Signer::new(message, external_signer)
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Signer setup failed: {e}"),
        })?
        .build()
        .map_err(|error| map_external_signing_error(error, signer_error("Signer setup failed")))
}

/// Write plaintext to the message pipeline and finalize.
pub(crate) fn write_and_finalize(message: Message, plaintext: &[u8]) -> Result<(), PgpError> {
    let mut literal =
        LiteralWriter::new(message)
            .build()
            .map_err(|e| PgpError::EncryptionFailed {
                reason: format!("Literal writer setup failed: {e}"),
            })?;

    literal
        .write_all(plaintext)
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Write failed: {e}"),
        })?;

    literal.finalize().map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Finalize failed: {e}"),
    })?;

    Ok(())
}

/// Write plaintext to an external-signer pipeline and preserve typed callback errors.
pub(crate) fn write_and_finalize_external_signing(
    message: Message,
    plaintext: &[u8],
) -> Result<(), PgpError> {
    let mut literal =
        LiteralWriter::new(message)
            .build()
            .map_err(|e| PgpError::EncryptionFailed {
                reason: format!("Literal writer setup failed: {e}"),
            })?;

    literal
        .write_all(plaintext)
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Write failed: {e}"),
        })?;

    literal
        .finalize()
        .map_err(|error| map_external_signing_error(error, signer_error("Finalize failed")))?;

    Ok(())
}

fn signer_error(context: &'static str) -> impl FnOnce(String) -> PgpError {
    move |reason| PgpError::SigningFailed {
        reason: format!("{context}: {reason}"),
    }
}

/// Encrypt plaintext for the given recipients.
///
/// Message format is determined automatically by recipient key versions:
/// - All v4 recipients → SEIPDv1 (MDC)
/// - All v6 recipients → SEIPDv2 (AEAD OCB)
/// - Mixed v4+v6 → SEIPDv1 (lowest common denominator)
///
/// SECURITY NOTE: Format auto-selection is intentionally
/// delegated to Sequoia's `Encryptor`, which inspects recipient certificates'
/// Features subpackets to determine the correct message format. This invariant
/// is verified by packet-level assertions in `pgp-mobile/tests/cross_suite_tests.rs`
/// (test_format_selection_*), which parse the raw SEIP version field for every
/// recipient key version combination. After any Sequoia version bump, these tests
/// must pass to confirm no regression in format selection behavior.
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
    let policy = StandardPolicy::new();
    let certs = collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = build_recipients(&certs, &policy);

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
    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;

    let message = setup_signer(message, signing_key, &policy)?;

    // Write the literal data (no compression — outgoing messages must not compress)
    write_and_finalize(message, plaintext)?;

    Ok(sink)
}

/// Encrypt plaintext and sign it using a public certificate plus external P-256 signer.
pub fn encrypt_with_external_p256_signer(
    plaintext: &[u8],
    recipient_certs: &[Vec<u8>],
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
    encrypt_to_self: Option<&[u8]>,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let certs = collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = build_recipients(&certs, &policy);

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Message)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Armor setup failed: {e}"),
        })?;

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;

    let message = setup_external_p256_signer(
        message,
        signing_public_cert,
        signing_key_fingerprint,
        signer,
        &policy,
    )?;

    write_and_finalize_external_signing(message, plaintext)?;

    Ok(sink)
}

/// Encrypt plaintext and sign it using a public certificate plus external
/// split-custody composite signer.
pub fn encrypt_with_external_composite_signer(
    plaintext: &[u8],
    recipient_certs: &[Vec<u8>],
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa65SigningProvider>,
    encrypt_to_self: Option<&[u8]>,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let certs = collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = build_recipients(&certs, &policy);

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Message)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Armor setup failed: {e}"),
        })?;

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;

    let message = setup_external_composite_signer(
        message,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        &policy,
    )?;

    write_and_finalize_external_signing(message, plaintext)?;

    Ok(sink)
}

/// Device-Bound Post-Quantum · High analog of
/// `encrypt_with_external_composite_signer` (ML-DSA-87 + Ed448 signer).
pub fn encrypt_with_external_composite_high_signer(
    plaintext: &[u8],
    recipient_certs: &[Vec<u8>],
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa87SigningProvider>,
    encrypt_to_self: Option<&[u8]>,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let certs = collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = build_recipients(&certs, &policy);

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Message)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Armor setup failed: {e}"),
        })?;

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;

    let message = setup_external_composite_high_signer(
        message,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        &policy,
    )?;

    write_and_finalize_external_signing(message, plaintext)?;

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
    let policy = StandardPolicy::new();
    let certs = collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = build_recipients(&certs, &policy);

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;

    let message = setup_signer(message, signing_key, &policy)?;

    write_and_finalize(message, plaintext)?;

    Ok(sink)
}
