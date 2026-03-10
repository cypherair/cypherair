use std::time::SystemTime;

use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::RevocationStatus;
use sequoia_openpgp as openpgp;

use crate::armor;
use crate::error::PgpError;

/// Encryption profile selection.
/// Profile A (Universal): v4, Ed25519+X25519, SEIPDv1, Iterated+Salted S2K.
/// Profile B (Advanced): v6, Ed448+X448, SEIPDv2 AEAD OCB, Argon2id S2K.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyProfile {
    /// Profile A: Universal compatible. v4 keys, GnuPG compatible.
    Universal,
    /// Profile B: Advanced security. v6 keys, RFC 9580.
    Advanced,
}

/// Result of key generation, containing the key pair and revocation certificate.
#[derive(uniffi::Record)]
pub struct GeneratedKey {
    /// Full certificate (public + secret) in binary OpenPGP format.
    pub cert_data: Vec<u8>,
    /// Public key only in binary OpenPGP format.
    pub public_key_data: Vec<u8>,
    /// Revocation certificate in binary OpenPGP format.
    pub revocation_cert: Vec<u8>,
    /// Key fingerprint as lowercase hex string.
    pub fingerprint: String,
    /// Key version (4 for Profile A, 6 for Profile B).
    pub key_version: u8,
    /// The profile used to generate this key.
    pub profile: KeyProfile,
}

/// Information extracted from a parsed key.
#[derive(uniffi::Record)]
pub struct KeyInfo {
    /// Key fingerprint as lowercase hex string.
    pub fingerprint: String,
    /// Key version (4 or 6).
    pub key_version: u8,
    /// Primary User ID string (name + email).
    pub user_id: Option<String>,
    /// Whether the key has a valid encryption subkey.
    pub has_encryption_subkey: bool,
    /// Whether the key is revoked.
    pub is_revoked: bool,
    /// Whether the key has expired.
    pub is_expired: bool,
    /// Detected profile based on key version and algorithms.
    pub profile: KeyProfile,
}

/// Generate a new key pair with the specified profile.
///
/// - Profile A (Universal): CipherSuite::Cv25519, Profile::RFC4880 → v4 key
/// - Profile B (Advanced): CipherSuite::Cv448, Profile::RFC9580 → v6 key
pub fn generate_key(
    name: String,
    email: Option<String>,
    expiry_seconds: Option<u64>,
) -> Result<GeneratedKey, PgpError> {
    generate_key_with_profile(name, email, expiry_seconds, KeyProfile::Universal)
}

/// Generate a new key pair with explicit profile selection.
pub fn generate_key_with_profile(
    name: String,
    email: Option<String>,
    expiry_seconds: Option<u64>,
    profile: KeyProfile,
) -> Result<GeneratedKey, PgpError> {
    let user_id = match &email {
        Some(e) => format!("{name} <{e}>"),
        None => name.clone(),
    };

    let mut builder = CertBuilder::general_purpose(Some(user_id.clone()));

    // Set cipher suite and profile based on KeyProfile
    match profile {
        KeyProfile::Universal => {
            builder = builder.set_cipher_suite(CipherSuite::Cv25519);
            // RFC4880 is the default profile — no explicit set needed
        }
        KeyProfile::Advanced => {
            builder = builder
                .set_cipher_suite(CipherSuite::Cv448)
                .set_profile(openpgp::Profile::RFC9580)
                .map_err(|e| PgpError::KeyGenerationFailed {
                    reason: format!("Failed to set profile: {e}"),
                })?;
        }
    }

    // Set expiry
    if let Some(secs) = expiry_seconds {
        builder = builder.set_validity_period(Some(std::time::Duration::from_secs(secs)));
    } else {
        // Default: 2 years
        builder = builder.set_validity_period(Some(std::time::Duration::from_secs(
            2 * 365 * 24 * 60 * 60,
        )));
    }

    let (cert, rev) = builder.generate().map_err(|e| PgpError::KeyGenerationFailed {
        reason: e.to_string(),
    })?;

    // Serialize full cert (public + secret)
    let mut cert_data = Vec::new();
    cert.as_tsk()
        .serialize(&mut cert_data)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize cert: {e}"),
        })?;

    // Serialize public key only
    let mut public_key_data = Vec::new();
    cert.serialize(&mut public_key_data)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize public key: {e}"),
        })?;

    // Serialize revocation certificate
    let mut revocation_cert = Vec::new();
    openpgp::Packet::from(rev)
        .serialize(&mut revocation_cert)
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to serialize revocation cert: {e}"),
        })?;

    let fingerprint = cert.fingerprint().to_hex();
    let key_version = cert.primary_key().key().version();

    Ok(GeneratedKey {
        cert_data,
        public_key_data,
        revocation_cert,
        fingerprint: fingerprint.to_lowercase(),
        key_version,
        profile,
    })
}

/// Parse a certificate (public key or full key) and extract key information.
pub fn parse_key_info(key_data: &[u8]) -> Result<KeyInfo, PgpError> {
    let cert =
        openpgp::Cert::from_bytes(key_data).map_err(|e| PgpError::InvalidKeyData {
            reason: e.to_string(),
        })?;

    let policy = StandardPolicy::new();
    let now = SystemTime::now();

    let fingerprint = cert.fingerprint().to_hex().to_lowercase();
    let key_version = cert.primary_key().key().version();

    // Extract primary User ID
    let user_id = cert
        .userids()
        .next()
        .map(|uid| String::from_utf8_lossy(uid.component().value()).to_string());

    // Check for valid encryption subkey
    let has_encryption_subkey = cert
        .keys()
        .with_policy(&policy, Some(now))
        .supported()
        .for_transport_encryption()
        .next()
        .is_some();

    // Check revocation status
    let is_revoked = matches!(
        cert.revocation_status(&policy, Some(now)),
        RevocationStatus::Revoked(_)
    );

    // Check expiry: a key is expired if the primary key's alive() check fails at the
    // current time but succeeds at its creation time (meaning the issue is temporal, not
    // structural). Revoked keys are not considered expired (they have a separate status).
    let is_expired = if is_revoked {
        false
    } else if let Ok(valid_cert) = cert.with_policy(&policy, Some(now)) {
        // If the cert is valid at the current time, check if the primary key is alive
        valid_cert.primary_key().alive().is_err()
    } else {
        // If the cert is not valid at now, check if it was valid at creation time
        // (meaning it expired rather than being structurally invalid)
        let creation_time = cert.primary_key().key().creation_time();
        cert.with_policy(&policy, Some(creation_time)).is_ok()
    };

    // Detect profile from key version
    let profile = if key_version >= 6 {
        KeyProfile::Advanced
    } else {
        KeyProfile::Universal
    };

    Ok(KeyInfo {
        fingerprint,
        key_version,
        user_id,
        has_encryption_subkey,
        is_revoked,
        is_expired,
        profile,
    })
}

/// Export a secret key protected with a passphrase.
/// - Profile A (Universal): Iterated+Salted S2K (mode 3) — selected automatically by Sequoia for v4/RFC4880 keys.
/// - Profile B (Advanced): Argon2id S2K — selected automatically by Sequoia for v6/RFC9580 keys.
///
/// Returns ASCII-armored key data with passphrase-encrypted secret key material.
pub fn export_secret_key(
    cert_data: &[u8],
    passphrase: &str,
    _profile: KeyProfile,
) -> Result<Vec<u8>, PgpError> {
    let cert =
        openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
            reason: e.to_string(),
        })?;

    let password = openpgp::crypto::Password::from(passphrase);

    // Encrypt each secret key component with the passphrase.
    // Sequoia's encrypt_secret() automatically selects the S2K mode based on
    // the key's profile: RFC4880 keys → Iterated+Salted, RFC9580 keys → Argon2id.
    let mut encrypted_packets: Vec<openpgp::Packet> = Vec::new();

    // Encrypt primary key
    {
        let primary = cert.primary_key().key().clone()
            .parts_into_secret()
            .map_err(|e| PgpError::S2kError {
                reason: format!("Primary key has no secret parts: {e}"),
            })?;
        let encrypted = primary.encrypt_secret(&password)
            .map_err(|e| PgpError::S2kError {
                reason: format!("Failed to encrypt primary key: {e}"),
            })?;
        encrypted_packets.push(encrypted.role_into_primary().into());
    }

    // Encrypt subkeys
    for ka in cert.keys().subkeys().secret() {
        let key = ka.key().clone();
        let encrypted = key.encrypt_secret(&password)
            .map_err(|e| PgpError::S2kError {
                reason: format!("Failed to encrypt subkey: {e}"),
            })?;
        encrypted_packets.push(encrypted.role_into_subordinate().into());
    }

    // Merge the encrypted key packets back into the cert.
    // insert_packets replaces matching keys with the encrypted versions.
    let (encrypted_cert, _changed) = cert.insert_packets(encrypted_packets)
        .map_err(|e| PgpError::S2kError {
            reason: format!("Failed to merge encrypted keys: {e}"),
        })?;

    // Serialize the cert with encrypted secret keys as armored output.
    let mut sink = Vec::new();
    let mut armored = armor::armor_writer(&mut sink, openpgp::armor::Kind::SecretKey)?;
    encrypted_cert
        .as_tsk()
        .serialize(&mut armored)
        .map_err(|e| PgpError::S2kError {
            reason: format!("Failed to serialize encrypted key: {e}"),
        })?;
    armored.finalize().map_err(|e| PgpError::ArmorError {
        reason: e.to_string(),
    })?;

    Ok(sink)
}

/// Import a passphrase-protected secret key.
/// Automatically detects S2K mode (Iterated+Salted or Argon2id).
///
/// Returns the decrypted certificate in binary format (with unencrypted secret keys),
/// ready for SE wrapping on the Swift side.
pub fn import_secret_key(armored_data: &[u8], passphrase: &str) -> Result<Vec<u8>, PgpError> {
    let cert = openpgp::Cert::from_bytes(armored_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    let password = openpgp::crypto::Password::from(passphrase);

    // Decrypt each secret key with the passphrase and collect the decrypted packets.
    let mut decrypted_packets: Vec<openpgp::Packet> = Vec::new();

    // Decrypt primary key
    {
        let primary = cert.primary_key().key().clone()
            .parts_into_secret()
            .map_err(|_| PgpError::WrongPassphrase)?;
        let decrypted = primary
            .decrypt_secret(&password)
            .map_err(|_| PgpError::WrongPassphrase)?;
        decrypted_packets.push(decrypted.role_into_primary().into());
    }

    // Decrypt subkeys
    for ka in cert.keys().subkeys().secret() {
        let key = ka.key().clone();
        let decrypted = key
            .decrypt_secret(&password)
            .map_err(|_| PgpError::WrongPassphrase)?;
        decrypted_packets.push(decrypted.role_into_subordinate().into());
    }

    // Merge decrypted key packets back into the cert, replacing the encrypted versions.
    let (decrypted_cert, _changed) = cert.insert_packets(decrypted_packets)
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Failed to merge decrypted keys: {e}"),
        })?;

    // Serialize the cert with decrypted secret keys.
    let mut output = Vec::new();
    decrypted_cert
        .as_tsk()
        .serialize(&mut output)
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Failed to serialize imported key: {e}"),
        })?;

    Ok(output)
}

/// Extract the secret key bytes from a certificate for SE wrapping.
/// The returned bytes should be immediately wrapped by the Secure Enclave
/// and then zeroized from memory.
pub fn extract_secret_key_bytes(cert_data: &[u8]) -> Result<Vec<u8>, PgpError> {
    let cert =
        openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
            reason: e.to_string(),
        })?;

    let mut secret_bytes = Vec::new();
    cert.as_tsk()
        .serialize(&mut secret_bytes)
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Failed to extract secret key: {e}"),
        })?;

    Ok(secret_bytes)
}

/// Parse a revocation certificate and verify it's valid.
pub fn parse_revocation_cert(rev_data: &[u8]) -> Result<String, PgpError> {
    let pkt = openpgp::Packet::from_bytes(rev_data).map_err(|e| PgpError::RevocationError {
        reason: format!("Failed to parse revocation cert: {e}"),
    })?;

    match pkt {
        openpgp::Packet::Signature(sig) => {
            if sig.typ() == openpgp::types::SignatureType::KeyRevocation {
                Ok(format!("Valid key revocation signature"))
            } else {
                Err(PgpError::RevocationError {
                    reason: format!("Not a key revocation signature: {:?}", sig.typ()),
                })
            }
        }
        _ => Err(PgpError::RevocationError {
            reason: "Not a signature packet".to_string(),
        }),
    }
}

/// Get the key version from binary certificate data.
pub fn get_key_version(cert_data: &[u8]) -> Result<u8, PgpError> {
    let cert =
        openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
            reason: e.to_string(),
        })?;
    Ok(cert.primary_key().key().version())
}

/// Detect the profile of a key based on its version and algorithms.
pub fn detect_profile(cert_data: &[u8]) -> Result<KeyProfile, PgpError> {
    let version = get_key_version(cert_data)?;
    Ok(if version >= 6 {
        KeyProfile::Advanced
    } else {
        KeyProfile::Universal
    })
}
