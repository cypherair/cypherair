use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::{HashAlgoSecurity, Policy, StandardPolicy};
use openpgp::serialize::Serialize;
use openpgp::types::{ReasonForRevocation, RevocationStatus};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

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
///
/// SECURITY: `cert_data` contains unencrypted secret key material. The Swift caller must:
/// 1. SE-wrap the secret key immediately after receiving this struct.
/// 2. Zeroize `cert_data` (via `resetBytes(in:)`) after wrapping is confirmed.
/// 3. Store `revocation_cert` securely and zeroize the in-memory copy.
/// `public_key_data` does not contain sensitive material and does not need zeroizing.
#[derive(uniffi::Record)]
pub struct GeneratedKey {
    /// Full certificate (public + secret) in binary OpenPGP format.
    /// MUST be zeroized by the caller after SE wrapping.
    pub cert_data: Vec<u8>,
    /// Public key only in binary OpenPGP format.
    pub public_key_data: Vec<u8>,
    /// Revocation certificate in binary OpenPGP format.
    /// Should be zeroized after secure storage.
    pub revocation_cert: Vec<u8>,
    /// Key fingerprint as lowercase hex string.
    pub fingerprint: String,
    /// Key version (4 for Profile A, 6 for Profile B).
    pub key_version: u8,
    /// The profile used to generate this key.
    pub profile: KeyProfile,
}

/// Information extracted from a parsed key.
#[derive(Debug, uniffi::Record)]
pub struct KeyInfo {
    /// Key fingerprint as lowercase hex string.
    pub fingerprint: String,
    /// Key version (4 or 6).
    pub key_version: u8,
    /// Policy-selected primary User ID string for display and identity matching.
    pub user_id: Option<String>,
    /// Whether the key has a valid encryption subkey.
    pub has_encryption_subkey: bool,
    /// Whether the key is revoked.
    pub is_revoked: bool,
    /// Whether the key has expired.
    pub is_expired: bool,
    /// Detected profile based on key version and algorithms.
    pub profile: KeyProfile,
    /// Primary key algorithm name (e.g., "Ed25519", "Ed448").
    pub primary_algo: String,
    /// Encryption subkey algorithm name (e.g., "X25519", "X448"), if present.
    pub subkey_algo: Option<String>,
    /// Expiration timestamp as seconds since Unix epoch. None if the key never expires.
    pub expiry_timestamp: Option<u64>,
}

/// Public-certificate validation result for contact import.
#[derive(Debug, uniffi::Record)]
pub struct PublicCertificateValidationResult {
    /// Canonical binary OpenPGP public certificate bytes.
    pub public_cert_data: Vec<u8>,
    /// Parsed key metadata for the validated public certificate.
    pub key_info: KeyInfo,
    /// Detected profile of the validated public certificate.
    pub profile: KeyProfile,
}

/// Stable `InvalidKeyData.reason` token for contact-import public-only violations.
pub const CONTACT_IMPORT_PUBLIC_ONLY_REASON: &str = "contact_import_public_only";

/// Semantic outcome of a same-fingerprint public certificate merge/update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CertificateMergeOutcome {
    /// Incoming material was already present; the merged public cert is a no-op.
    NoOp,
    /// Incoming material changed the public cert (for example, new bindings or revocations).
    Updated,
}

/// Result of merging same-fingerprint public certificate update material.
#[derive(Debug, uniffi::Record)]
pub struct CertificateMergeResult {
    /// Merged public certificate bytes in binary OpenPGP format.
    pub merged_cert_data: Vec<u8>,
    /// Whether the merge materially changed the public certificate.
    pub outcome: CertificateMergeOutcome,
}

#[derive(Debug)]
struct UserIdCandidate {
    user_id_bytes: Vec<u8>,
    revoked: bool,
    primary: bool,
    signature_creation_time: SystemTime,
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
            // Explicitly set RFC4880 profile and strip SEIPDv2 feature.
            // Sequoia 2.2.0 defaults to advertising SEIPDv2 support in the
            // Features subpacket (because the library itself supports it).
            // For Profile A (GnuPG-compatible), we must advertise only SEIPDv1
            // so that other implementations send SEIPDv1 messages to this key.
            // Without this, GnuPG users cannot decrypt messages sent to Profile A keys.
            builder = builder
                .set_cipher_suite(CipherSuite::Cv25519)
                .set_profile(openpgp::Profile::RFC4880)
                .map_err(|e| PgpError::KeyGenerationFailed {
                    reason: format!("Failed to set profile: {e}"),
                })?
                .set_features(openpgp::types::Features::empty().set_seipdv1())
                .map_err(|e| PgpError::KeyGenerationFailed {
                    reason: format!("Failed to set features: {e}"),
                })?;
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
        builder = builder
            .set_validity_period(Some(std::time::Duration::from_secs(2 * 365 * 24 * 60 * 60)));
    }

    let (cert, rev) = builder
        .generate()
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: e.to_string(),
        })?;

    // Serialize full cert (public + secret).
    // SECURITY: cert_data contains unencrypted secret key material. Wrapped in Zeroizing<>
    // so it is automatically zeroized on error paths (dropped without reaching the caller).
    let mut cert_data = Zeroizing::new(Vec::new());
    cert.as_tsk()
        .serialize(&mut *cert_data)
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
        cert_data: std::mem::take(&mut *cert_data),
        public_key_data,
        revocation_cert,
        fingerprint: fingerprint.to_lowercase(),
        key_version,
        profile,
    })
}

/// Parse a certificate (public key or full key) and extract key information.
pub fn parse_key_info(key_data: &[u8]) -> Result<KeyInfo, PgpError> {
    let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    let policy = StandardPolicy::new();
    let now = SystemTime::now();

    let fingerprint = cert.fingerprint().to_hex().to_lowercase();
    let key_version = cert.primary_key().key().version();

    // Extract the primary User ID using Sequoia's policy-selected value when the
    // certificate is fully valid. If the certificate is expired or revoked, fall back
    // to a best-effort ranking that keeps display identity aligned with Sequoia's
    // primary-selection rules as closely as possible.
    let user_id = select_display_user_id(&cert, &policy, now);

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

    // Extract primary key algorithm name (Display gives human-readable names like "EdDSA", "Ed448")
    let primary_algo = cert.primary_key().key().pk_algo().to_string();

    // Extract encryption subkey algorithm name (first encryption-capable subkey)
    let subkey_algo = cert
        .keys()
        .subkeys()
        .with_policy(&policy, Some(now))
        .for_transport_encryption()
        .next()
        .map(|ka| ka.key().pk_algo().to_string())
        .or_else(|| {
            // Fallback for display only: if no policy-valid encryption subkey found
            // (e.g., expired key), report the first subkey's algorithm name.
            // This does NOT affect encryption operations — encrypt() independently
            // uses with_policy() to find valid encryption subkeys and will correctly
            // reject keys with no valid encryption-capable subkey.
            cert.keys()
                .subkeys()
                .next()
                .map(|ka| ka.key().pk_algo().to_string())
        });

    // Extract expiry timestamp from the primary key's self-signature.
    // key_expiration_time() returns the absolute time at which the key expires.
    let expiry_timestamp = cert
        .with_policy(&policy, Some(now))
        .ok()
        .and_then(|valid_cert| valid_cert.primary_key().key_expiration_time())
        .or_else(|| {
            // Fallback for expired certs: validate without temporal check
            // to retrieve the expiry timestamp for display purposes.
            cert.with_policy(&policy, None)
                .ok()
                .and_then(|valid_cert| valid_cert.primary_key().key_expiration_time())
        })
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    Ok(KeyInfo {
        fingerprint,
        key_version,
        user_id,
        has_encryption_subkey,
        is_revoked,
        is_expired,
        profile,
        primary_algo,
        subkey_algo,
        expiry_timestamp,
    })
}

/// Validate that contact-import data is a public certificate and return normalized metadata.
pub fn validate_public_certificate(
    cert_data: &[u8],
) -> Result<PublicCertificateValidationResult, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: CONTACT_IMPORT_PUBLIC_ONLY_REASON.to_string(),
        });
    }

    let public_cert_data = serialize_public_cert(&cert)?;
    let key_info = parse_key_info(&public_cert_data)?;
    let profile = key_info.profile;

    Ok(PublicCertificateValidationResult {
        public_cert_data,
        key_info,
        profile,
    })
}

fn select_display_user_id(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    now: SystemTime,
) -> Option<String> {
    if let Ok(valid_cert) = cert.with_policy(policy, Some(now)) {
        if let Ok(primary_user_id) = valid_cert.primary_userid() {
            return Some(user_id_bytes_to_string(primary_user_id.userid().value()));
        }
    }

    select_ranked_user_id(cert, policy, Some(now))
        .or_else(|| select_ranked_user_id(cert, policy, None))
        .or_else(|| {
            cert.userids()
                .next()
                .map(|user_id| user_id_bytes_to_string(user_id.userid().value()))
        })
}

fn select_ranked_user_id(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    now: Option<SystemTime>,
) -> Option<String> {
    cert.userids()
        .filter_map(|user_id| make_user_id_candidate(user_id, policy, now))
        .max_by(compare_user_id_candidates)
        .map(|candidate| user_id_bytes_to_string(&candidate.user_id_bytes))
}

fn make_user_id_candidate(
    user_id: UserIDAmalgamation<'_>,
    policy: &StandardPolicy,
    now: Option<SystemTime>,
) -> Option<UserIdCandidate> {
    let signature = match now {
        Some(time) => user_id
            .binding_signature(policy, Some(time))
            .ok()
            .or_else(|| user_id.self_signatures().next())?,
        None => user_id.self_signatures().next()?,
    };

    let signature_creation_time = signature.signature_creation_time()?;
    let latest_self_revocation_time = user_id
        .self_revocations()
        .filter(|signature| {
            policy
                .signature(signature, HashAlgoSecurity::SecondPreImageResistance)
                .is_ok()
        })
        .filter_map(|signature| signature.signature_creation_time())
        .max();

    Some(UserIdCandidate {
        user_id_bytes: user_id.userid().value().to_vec(),
        revoked: latest_self_revocation_time
            .map(|revocation_time| revocation_time >= signature_creation_time)
            .unwrap_or(false),
        primary: signature.primary_userid().unwrap_or(false),
        signature_creation_time,
    })
}

fn compare_user_id_candidates(left: &UserIdCandidate, right: &UserIdCandidate) -> Ordering {
    match (left.revoked, right.revoked) {
        (false, true) => return Ordering::Greater,
        (true, false) => return Ordering::Less,
        _ => {}
    }

    match left.primary.cmp(&right.primary) {
        Ordering::Equal => {}
        ordering => return ordering,
    }

    match left
        .signature_creation_time
        .cmp(&right.signature_creation_time)
    {
        Ordering::Equal => {}
        ordering => return ordering,
    }

    left.user_id_bytes.cmp(&right.user_id_bytes)
}

fn user_id_bytes_to_string(user_id: &[u8]) -> String {
    String::from_utf8_lossy(user_id).to_string()
}

fn serialize_public_cert(cert: &openpgp::Cert) -> Result<Vec<u8>, PgpError> {
    let mut public_key_data = Vec::new();
    cert.serialize(&mut public_key_data)
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Failed to serialize public certificate: {e}"),
        })?;
    Ok(public_key_data)
}

/// Merge same-fingerprint public certificate update material into an existing public certificate.
///
/// Both inputs must parse as public certificates with the same primary fingerprint.
/// Secret-bearing input is rejected as an API precondition failure.
pub fn merge_public_certificate_update(
    existing_cert: &[u8],
    incoming_cert_or_update: &[u8],
) -> Result<CertificateMergeResult, PgpError> {
    let existing_cert =
        openpgp::Cert::from_bytes(existing_cert).map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Invalid existing public certificate: {e}"),
        })?;
    if existing_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "Existing certificate contains secret key material; merge/update accepts public certificates only.".to_string(),
        });
    }

    let incoming_cert = openpgp::Cert::from_bytes(incoming_cert_or_update).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid incoming public certificate update: {e}"),
        }
    })?;
    if incoming_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "Incoming certificate update contains secret key material; merge/update accepts public certificates only.".to_string(),
        });
    }

    if existing_cert.fingerprint() != incoming_cert.fingerprint() {
        return Err(PgpError::InvalidKeyData {
            reason:
                "Public certificate merge/update requires both inputs to have the same fingerprint."
                    .to_string(),
        });
    }

    let existing_public = serialize_public_cert(&existing_cert)?;
    let merged_cert =
        existing_cert
            .merge_public(incoming_cert)
            .map_err(|e| PgpError::InvalidKeyData {
                reason: format!("Failed to merge public certificates: {e}"),
            })?;
    let merged_cert_data = serialize_public_cert(&merged_cert)?;

    let outcome = if merged_cert_data == existing_public {
        CertificateMergeOutcome::NoOp
    } else {
        CertificateMergeOutcome::Updated
    };

    Ok(CertificateMergeResult {
        merged_cert_data,
        outcome,
    })
}

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

/// Get the key version from binary certificate data.
pub fn get_key_version(cert_data: &[u8]) -> Result<u8, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
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

/// S2K (String-to-Key) parameters extracted from a passphrase-protected key.
/// Used by Swift side to check memory requirements before importing.
#[derive(Debug, uniffi::Record)]
pub struct S2kInfo {
    /// S2K type: "iterated-salted" for Profile A, "argon2id" for Profile B, or "unknown".
    pub s2k_type: String,
    /// For Argon2id: memory requirement in KiB (2^encoded_m). 0 for non-Argon2id.
    pub memory_kib: u64,
    /// For Argon2id: parallelism lanes. 0 for non-Argon2id.
    pub parallelism: u32,
    /// For Argon2id: time passes. 0 for non-Argon2id.
    pub time_passes: u32,
}

/// Parse S2K parameters from a passphrase-protected key file.
/// This allows the Swift side to check memory requirements (e.g., Argon2id 512 MB)
/// before calling `import_secret_key`, preventing iOS Jetsam kills.
///
/// Inspects the primary key and all subkeys, returning the S2K info with the
/// highest memory requirement. This handles keys where the primary key and
/// subkeys may use different S2K parameters (e.g., imported from external tools).
pub fn parse_s2k_params(armored_data: &[u8]) -> Result<S2kInfo, PgpError> {
    let cert = openpgp::Cert::from_bytes(armored_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    // Iterate primary key + all subkeys, extract S2K info from each encrypted key.
    let mut best: Option<S2kInfo> = None;
    let mut has_unencrypted = false;

    // Helper closure to extract S2K info from secret key material
    let mut check_secret = |secret: Option<&openpgp::packet::key::SecretKeyMaterial>| match secret {
        Some(openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted)) => {
            let info = match encrypted.s2k() {
                openpgp::crypto::S2K::Argon2 { t, p, m, .. } => {
                    let memory_kib: u64 = 1u64 << (*m as u64);
                    S2kInfo {
                        s2k_type: "argon2id".to_string(),
                        memory_kib,
                        parallelism: *p as u32,
                        time_passes: *t as u32,
                    }
                }
                openpgp::crypto::S2K::Iterated { .. } => S2kInfo {
                    s2k_type: "iterated-salted".to_string(),
                    memory_kib: 0,
                    parallelism: 0,
                    time_passes: 0,
                },
                _ => S2kInfo {
                    s2k_type: "unknown".to_string(),
                    memory_kib: 0,
                    parallelism: 0,
                    time_passes: 0,
                },
            };
            if best
                .as_ref()
                .map_or(true, |b| info.memory_kib > b.memory_kib)
            {
                best = Some(info);
            }
        }
        Some(openpgp::packet::key::SecretKeyMaterial::Unencrypted(_)) => {
            has_unencrypted = true;
        }
        None => {}
    };

    // Check primary key
    check_secret(cert.primary_key().key().optional_secret());
    // Check all subkeys
    for ka in cert.keys().subkeys() {
        check_secret(ka.key().optional_secret());
    }

    if let Some(info) = best {
        Ok(info)
    } else if has_unencrypted {
        Err(PgpError::InvalidKeyData {
            reason: "Key is not passphrase-protected (unencrypted secret key)".to_string(),
        })
    } else {
        Err(PgpError::InvalidKeyData {
            reason: "No secret key material found (public key only)".to_string(),
        })
    }
}

/// Result of modifying a certificate's expiration time.
///
/// SECURITY: `cert_data` contains unencrypted secret key material. The Swift caller must:
/// 1. SE-wrap `cert_data` immediately.
/// 2. Zeroize `cert_data` (via `resetBytes(in:)`) after wrapping is confirmed.
#[derive(Debug, uniffi::Record)]
pub struct ModifyExpiryResult {
    /// Updated full certificate (public + secret) in binary OpenPGP format.
    /// MUST be zeroized by the caller after SE wrapping.
    pub cert_data: Vec<u8>,
    /// Updated public key only in binary OpenPGP format.
    pub public_key_data: Vec<u8>,
    /// Updated key info with new expiry status.
    pub key_info: KeyInfo,
}

/// Modify the expiration time of an existing certificate.
///
/// Requires the full certificate with secret key material, because updating the expiry
/// requires re-signing the primary key's binding signatures (direct key sig + all User ID
/// binding sigs). Works identically for v4 (Profile A) and v6 (Profile B) keys — Sequoia's
/// `Cert::set_expiration_time()` handles both transparently.
///
/// - `cert_data`: Full certificate with secret key material (binary OpenPGP format).
/// - `new_expiry_seconds`: Duration from now in seconds. `None` removes expiry (never expire).
///
/// Returns the updated certificate (with secret keys) and updated public key + key info.
pub fn modify_expiry(
    cert_data: &[u8],
    new_expiry_seconds: Option<u64>,
) -> Result<ModifyExpiryResult, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    let policy = StandardPolicy::new();

    // Extract the primary key as a KeyPair for signing the new binding signatures.
    // SECURITY: `keypair` holds secret key material. Sequoia's KeyPair uses Protected<>
    // internally, which zeroizes on Drop.
    let mut keypair = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("No secret key material for re-signing: {e}"),
        })?
        .into_keypair()
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Cannot create keypair from secret key: {e}"),
        })?;

    // Compute the target expiration time.
    let expiration =
        new_expiry_seconds.map(|secs| SystemTime::now() + std::time::Duration::from_secs(secs));

    // Generate new binding signatures with the updated expiry.
    // This updates: direct key signature + all valid, non-revoked User ID binding signatures.
    let sigs = cert
        .set_expiration_time(&policy, None, &mut keypair, expiration)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to set expiration time: {e}"),
        })?;

    // Insert the new signatures into the certificate.
    let (updated_cert, _) =
        cert.insert_packets(sigs)
            .map_err(|e| PgpError::KeyGenerationFailed {
                reason: format!("Failed to update certificate with new signatures: {e}"),
            })?;

    // Serialize the updated full cert (public + secret).
    // SECURITY: Wrapped in Zeroizing<> for automatic cleanup on error paths.
    let mut cert_output = Zeroizing::new(Vec::new());
    updated_cert
        .as_tsk()
        .serialize(&mut *cert_output)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize updated certificate: {e}"),
        })?;

    // Serialize the public key only.
    let mut public_key_data = Vec::new();
    updated_cert
        .serialize(&mut public_key_data)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize updated public key: {e}"),
        })?;

    // Re-parse key info to get updated expiry status.
    let key_info = parse_key_info(&public_key_data)?;

    Ok(ModifyExpiryResult {
        cert_data: std::mem::take(&mut *cert_output),
        public_key_data,
        key_info,
    })
}
