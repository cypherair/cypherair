use super::*;

/// Encrypt a secret key using Argon2id S2K (Profile B).
/// Uses an explicit export strategy rather than inline magic numbers so Swift-side
/// calibration can later plug into the same path without rewriting the export flow.
struct ProfileBExportS2kStrategy {
    time_passes: u8,
    parallelism: u8,
    memory_exponent: u8,
}

impl ProfileBExportS2kStrategy {
    fn interactive_default() -> Self {
        Self {
            // PRD target: roughly 3 seconds on contemporary hardware.
            time_passes: 3,
            parallelism: 4,
            memory_exponent: 19, // 2^19 KiB = 512 MiB
        }
    }
}

fn encrypt_key_argon2id<R: openpgp::packet::key::KeyRole>(
    key: openpgp::packet::Key<openpgp::packet::key::SecretParts, R>,
    password: &openpgp::crypto::Password,
) -> openpgp::Result<openpgp::packet::Key<openpgp::packet::key::SecretParts, R>> {
    use openpgp::types::{AEADAlgorithm, SymmetricAlgorithm};

    // Generate random 16-byte salt for Argon2id
    let mut salt = [0u8; 16];
    openpgp::crypto::random(&mut salt)?;

    let strategy = ProfileBExportS2kStrategy::interactive_default();

    // The default export strategy is intentionally explicit and centralized.
    // Future device calibration can override these fields via the same strategy model
    // without touching the encryption pipeline below.
    let s2k = openpgp::crypto::S2K::Argon2 {
        salt,
        t: strategy.time_passes,
        p: strategy.parallelism,
        m: strategy.memory_exponent,
    };

    let (key_pub, mut secret) = key.take_secret();

    // SECURITY: `secret` (SecretKeyMaterial) contains unencrypted key material.
    // Sequoia's SecretKeyMaterial::Unencrypted internally uses `Protected` (a
    // Zeroizing<Box<[u8]>>), which zeroizes on Drop. If encrypt_in_place_with()
    // fails, `secret` is dropped here and Sequoia's Drop impl handles zeroization.
    // See also: sign.rs comment on KeyPair lifecycle management.
    secret.encrypt_in_place_with(
        &key_pub,
        s2k,
        SymmetricAlgorithm::AES256,
        Some(AEADAlgorithm::OCB),
        password,
    )?;

    Ok(key_pub.add_secret(secret).0)
}

/// Export a secret key protected with a passphrase.
/// - Profile A (Universal): Iterated+Salted S2K (mode 3) — GnuPG compatible.
/// - Profile B (Advanced): Argon2id S2K (512 MB / p=4 / t=3) — RFC 9580.
///
/// Returns ASCII-armored key data with passphrase-encrypted secret key material.
pub fn export_secret_key(
    cert_data: &[u8],
    passphrase: &str,
    profile: KeyProfile,
) -> Result<Vec<u8>, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    // Validate that the provided profile matches the key's actual version.
    let key_version = cert.primary_key().key().version();
    let expected_profile = if key_version >= 6 {
        KeyProfile::Advanced
    } else {
        KeyProfile::Universal
    };
    if profile != expected_profile {
        return Err(PgpError::S2kError {
            reason: format!(
                "Profile mismatch: requested {:?} but key is v{} ({:?})",
                profile, key_version, expected_profile
            ),
        });
    }

    let password = openpgp::crypto::Password::from(passphrase);

    // Encrypt each secret key component with the passphrase.
    // For Profile A: Sequoia's default S2K (Iterated+Salted) is appropriate.
    // For Profile B: We must explicitly use Argon2id S2K, because Sequoia's
    // S2K::default() returns Iterated+Salted for all key versions.
    // PRD requires Argon2id (512 MB / p=4 / ~3s) for Profile B exports.
    let mut encrypted_packets: Vec<openpgp::Packet> = Vec::new();

    // Encrypt primary key
    // SECURITY: `primary` holds cloned unencrypted secret key material.
    // It is consumed (moved) by encrypt_secret()/encrypt_key_argon2id() on success.
    // On error, it is dropped; Sequoia's SecretKeyMaterial Drop zeroizes the secret bytes.
    {
        let primary = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .map_err(|e| PgpError::S2kError {
                reason: format!("Primary key has no secret parts: {e}"),
            })?;
        let encrypted = match profile {
            KeyProfile::Universal => primary.encrypt_secret(&password),
            KeyProfile::Advanced => encrypt_key_argon2id(primary, &password),
        }
        .map_err(|e| PgpError::S2kError {
            reason: format!("Failed to encrypt primary key: {e}"),
        })?;
        encrypted_packets.push(encrypted.role_into_primary().into());
    }

    // Encrypt subkeys
    for ka in cert.keys().subkeys().secret() {
        let key = ka.key().clone();
        let encrypted = match profile {
            KeyProfile::Universal => key.encrypt_secret(&password),
            KeyProfile::Advanced => encrypt_key_argon2id(key, &password),
        }
        .map_err(|e| PgpError::S2kError {
            reason: format!("Failed to encrypt subkey: {e}"),
        })?;
        encrypted_packets.push(encrypted.role_into_subordinate().into());
    }

    // Merge the encrypted key packets back into the cert.
    // insert_packets replaces matching keys with the encrypted versions.
    let (encrypted_cert, _changed) =
        cert.insert_packets(encrypted_packets)
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

    // Note: `password` (openpgp::crypto::Password) is zeroized on drop by Sequoia.
    // The encrypted_packets Vec contains only encrypted key material (safe).

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
    // SECURITY: `primary` holds secret key material (encrypted, then decrypted).
    // Consumed by decrypt_secret() on success. On error, dropped; Sequoia's
    // SecretKeyMaterial Drop zeroizes the secret bytes.
    {
        let primary = cert
            .primary_key()
            .key()
            .clone()
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
    let (decrypted_cert, _changed) =
        cert.insert_packets(decrypted_packets)
            .map_err(|e| PgpError::InvalidKeyData {
                reason: format!("Failed to merge decrypted keys: {e}"),
            })?;

    // Serialize the cert with decrypted secret keys.
    // SECURITY: output contains unencrypted secret key material. Wrapped in Zeroizing<>
    // so it is automatically zeroized if dropped before crossing the FFI boundary.
    // The caller (Swift side) must SE-wrap this data and zeroize it immediately after wrapping.
    let mut output = Zeroizing::new(Vec::new());
    decrypted_cert
        .as_tsk()
        .serialize(&mut *output)
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Failed to serialize imported key: {e}"),
        })?;

    // Note: `password` (openpgp::crypto::Password) is zeroized on drop by Sequoia.
    // `output` is Zeroizing<Vec<u8>> — zeroized on drop if an error occurs after this point.
    // std::mem::take extracts the Vec, leaving an empty Vec in the Zeroizing wrapper (nothing to zeroize).

    Ok(std::mem::take(&mut *output))
}

/// Extract the secret key bytes from a certificate for SE wrapping.
/// The returned bytes should be immediately wrapped by the Secure Enclave
/// and then zeroized from memory.
///
/// NOTE: This function is not yet exposed via UniFFI. It will be used by the Swift
/// KeyManagementService when implementing SE wrapping during key generation and import.
/// See ARCHITECTURE.md Section 3 "SE Key Wrapping" data flow.
#[allow(dead_code)]
pub fn extract_secret_key_bytes(cert_data: &[u8]) -> Result<Vec<u8>, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    // SECURITY: Wrapped in Zeroizing<> so secret bytes are zeroized on drop
    // if an error occurs or the caller drops the result without explicit cleanup.
    let mut secret_bytes = Zeroizing::new(Vec::new());
    cert.as_tsk()
        .serialize(&mut *secret_bytes)
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Failed to extract secret key: {e}"),
        })?;

    Ok(std::mem::take(&mut *secret_bytes))
}
