use std::cmp::Ordering;
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openpgp::cert::prelude::*;
use openpgp::packet::{Signature, UserID};
use openpgp::parse::Parse;
use openpgp::policy::{HashAlgoSecurity, Policy, StandardPolicy};
use openpgp::serialize::Serialize;
use openpgp::types::{ReasonForRevocation, RevocationStatus, SignatureType};
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

/// Selector-bearing discovery result for a certificate.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DiscoveredCertificateSelectors {
    /// Primary certificate fingerprint in canonical lowercase hex.
    pub certificate_fingerprint: String,
    /// All subkeys in the certificate's native iteration order.
    pub subkeys: Vec<DiscoveredSubkey>,
    /// All User IDs in the certificate's native iteration order.
    pub user_ids: Vec<DiscoveredUserId>,
}

/// Selector-bearing metadata for one discovered subkey.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DiscoveredSubkey {
    /// Subkey fingerprint in canonical lowercase hex.
    pub fingerprint: String,
    /// Display-oriented algorithm name.
    pub algorithm_display: String,
    /// Whether this subkey is currently transport-encryption capable under StandardPolicy + now.
    pub is_currently_transport_encryption_capable: bool,
    /// Whether this subkey is currently revoked under StandardPolicy + now.
    pub is_currently_revoked: bool,
    /// Whether this subkey is currently expired under StandardPolicy + now.
    pub is_currently_expired: bool,
}

/// Selector-bearing metadata for one discovered User ID packet.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DiscoveredUserId {
    /// 0-based occurrence index in the certificate's native User ID iteration order.
    pub occurrence_index: u64,
    /// Raw User ID packet bytes.
    pub user_id_data: Vec<u8>,
    /// Display-oriented lossy UTF-8 rendering of `user_id_data`.
    pub display_text: String,
    /// Whether this User ID is currently marked primary under StandardPolicy + now.
    pub is_currently_primary: bool,
    /// Whether this User ID is currently revoked under StandardPolicy + now.
    pub is_currently_revoked: bool,
}

/// Selector identity for a specific User ID occurrence in a certificate snapshot.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UserIdSelectorInput {
    /// Raw User ID packet bytes for the selected occurrence.
    pub user_id_data: Vec<u8>,
    /// 0-based occurrence index in the certificate's native User ID order.
    pub occurrence_index: u64,
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

struct RawUserIdOccurrence {
    user_id: UserID,
    signatures: Vec<Signature>,
}

mod expiry;
mod generation;
mod key_info;
mod profile;
mod public_certificates;
mod revocation;
mod s2k;
mod secret_transfer;
mod selector_discovery;

pub use expiry::{modify_expiry, ModifyExpiryResult};
pub use generation::{generate_key, generate_key_with_profile};
pub use key_info::parse_key_info;
pub use profile::{detect_profile, get_key_version};
pub use public_certificates::{merge_public_certificate_update, validate_public_certificate};
pub use revocation::{
    generate_key_revocation, generate_subkey_revocation, generate_user_id_revocation_by_selector,
    parse_revocation_cert,
};
pub use s2k::{parse_s2k_params, S2kInfo};
pub use secret_transfer::{export_secret_key, extract_secret_key_bytes, import_secret_key};
pub use selector_discovery::discover_certificate_selectors;

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
        .filter_map(|user_id| make_user_id_candidate(&user_id, policy, now))
        .max_by(compare_user_id_candidates)
        .map(|candidate| user_id_bytes_to_string(&candidate.user_id_bytes))
}

fn make_user_id_candidate(
    user_id: &UserIDAmalgamation<'_>,
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

fn discover_subkey(
    cert: &openpgp::Cert,
    subkey: &SubordinateKeyAmalgamation<'_, openpgp::packet::key::PublicParts>,
    policy: &StandardPolicy,
    now: SystemTime,
    currently_valid_subkeys: &HashSet<String>,
    transport_encryption_capable_subkeys: &HashSet<String>,
) -> DiscoveredSubkey {
    let fingerprint = subkey.key().fingerprint().to_hex().to_lowercase();
    let is_currently_revoked = matches!(
        subkey.revocation_status(policy, Some(now)),
        RevocationStatus::Revoked(_)
    );
    let is_currently_expired = if is_currently_revoked {
        false
    } else if currently_valid_subkeys.contains(&fingerprint) {
        false
    } else {
        let creation_time = subkey.key().creation_time();
        cert.keys()
            .subkeys()
            .with_policy(policy, Some(creation_time))
            .any(|candidate| candidate.key().fingerprint().to_hex().to_lowercase() == fingerprint)
    };

    DiscoveredSubkey {
        fingerprint: fingerprint.clone(),
        algorithm_display: subkey.key().pk_algo().to_string(),
        is_currently_transport_encryption_capable: transport_encryption_capable_subkeys
            .contains(&fingerprint),
        is_currently_revoked,
        is_currently_expired,
    }
}

fn discover_user_id(
    cert: &openpgp::Cert,
    occurrence: &RawUserIdOccurrence,
    occurrence_index: u64,
    policy: &StandardPolicy,
    now: SystemTime,
) -> DiscoveredUserId {
    let user_id_data = occurrence.user_id.value().to_vec();
    let (is_currently_primary, is_currently_revoked) =
        current_user_id_occurrence_state(cert, occurrence, policy, now);

    DiscoveredUserId {
        occurrence_index,
        display_text: user_id_bytes_to_string(&user_id_data),
        user_id_data,
        is_currently_primary,
        is_currently_revoked,
    }
}

fn current_valid_subkey_fingerprints(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    now: SystemTime,
) -> HashSet<String> {
    cert.keys()
        .subkeys()
        .with_policy(policy, Some(now))
        .map(|subkey| subkey.key().fingerprint().to_hex().to_lowercase())
        .collect()
}

fn current_transport_encryption_capable_subkey_fingerprints(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    now: SystemTime,
) -> HashSet<String> {
    cert.keys()
        .subkeys()
        .with_policy(policy, Some(now))
        .supported()
        .for_transport_encryption()
        .map(|subkey| subkey.key().fingerprint().to_hex().to_lowercase())
        .collect()
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

fn reject_armored_certificate_input(cert_data: &[u8]) -> Result<(), PgpError> {
    let trimmed = cert_data
        .iter()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .copied()
        .collect::<Vec<_>>();

    if trimmed.starts_with(b"-----BEGIN PGP") {
        return Err(PgpError::InvalidKeyData {
            reason: "Certificate selector discovery requires binary certificate bytes".to_string(),
        });
    }

    Ok(())
}

fn serialize_public_cert(cert: &openpgp::Cert) -> Result<Vec<u8>, PgpError> {
    let mut public_key_data = Vec::new();
    cert.serialize(&mut public_key_data)
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Failed to serialize public certificate: {e}"),
        })?;
    Ok(public_key_data)
}

pub(crate) fn find_user_id_by_selector<'a>(
    cert_data: &[u8],
    selector: &UserIdSelectorInput,
) -> Result<UserID, PgpError> {
    let Some(user_id) = raw_user_id_occurrences(cert_data)?
        .into_iter()
        .nth(selector.occurrence_index as usize)
        .map(|occurrence| occurrence.user_id)
    else {
        return Err(PgpError::InvalidKeyData {
            reason: "User ID selector occurrence index out of range".to_string(),
        });
    };

    if user_id.value() != selector.user_id_data.as_slice() {
        return Err(PgpError::InvalidKeyData {
            reason: "User ID selector bytes do not match the selected occurrence".to_string(),
        });
    }

    Ok(user_id)
}

fn raw_user_id_occurrences(cert_data: &[u8]) -> Result<Vec<RawUserIdOccurrence>, PgpError> {
    let raw_cert = openpgp::cert::raw::RawCert::from_bytes(cert_data).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: e.to_string(),
        }
    })?;
    let mut occurrences = Vec::new();
    let mut current: Option<RawUserIdOccurrence> = None;

    for packet in raw_cert.packets() {
        let packet = openpgp::Packet::from_bytes(packet.as_bytes()).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Failed to parse raw certificate packet: {e}"),
            }
        })?;

        match packet {
            openpgp::Packet::UserID(user_id) => {
                if let Some(current_occurrence) = current.take() {
                    occurrences.push(current_occurrence);
                }
                current = Some(RawUserIdOccurrence {
                    user_id,
                    signatures: Vec::new(),
                });
            }
            openpgp::Packet::Signature(signature) => {
                if let Some(current_occurrence) = current.as_mut() {
                    current_occurrence.signatures.push(signature);
                }
            }
            _ => {
                if let Some(current_occurrence) = current.take() {
                    occurrences.push(current_occurrence);
                }
            }
        }
    }

    if let Some(current_occurrence) = current.take() {
        occurrences.push(current_occurrence);
    }

    Ok(occurrences)
}

fn current_user_id_occurrence_state(
    cert: &openpgp::Cert,
    occurrence: &RawUserIdOccurrence,
    policy: &StandardPolicy,
    now: SystemTime,
) -> (bool, bool) {
    let primary_key = cert.primary_key().key();
    let binding_signature = occurrence
        .signatures
        .iter()
        .filter(|signature| {
            matches!(
                signature.typ(),
                SignatureType::GenericCertification
                    | SignatureType::PersonaCertification
                    | SignatureType::CasualCertification
                    | SignatureType::PositiveCertification
            )
        })
        .filter(|signature| {
            signature
                .signature_creation_time()
                .map(|creation_time| creation_time <= now)
                .unwrap_or(false)
                && signature.signature_alive(now, Duration::ZERO).is_ok()
                && policy
                    .signature(signature, HashAlgoSecurity::SecondPreImageResistance)
                    .is_ok()
                && signature
                    .verify_userid_binding(primary_key, primary_key, &occurrence.user_id)
                    .is_ok()
        })
        .max_by_key(|signature| {
            signature
                .signature_creation_time()
                .expect("active binding signatures always have a creation time")
        });

    let latest_revocation = occurrence
        .signatures
        .iter()
        .filter(|signature| signature.typ() == SignatureType::CertificationRevocation)
        .filter(|signature| {
            signature
                .signature_creation_time()
                .map(|creation_time| creation_time <= now)
                .unwrap_or(false)
                && signature.signature_alive(now, Duration::ZERO).is_ok()
                && policy
                    .signature(signature, HashAlgoSecurity::SecondPreImageResistance)
                    .is_ok()
                && signature
                    .verify_userid_revocation(primary_key, primary_key, &occurrence.user_id)
                    .is_ok()
        })
        .max_by_key(|signature| {
            signature
                .signature_creation_time()
                .expect("active revocation signatures always have a creation time")
        });

    let is_currently_primary = binding_signature
        .and_then(|signature| signature.primary_userid())
        .unwrap_or(false);
    let is_currently_revoked = match (
        binding_signature.and_then(|signature| signature.signature_creation_time()),
        latest_revocation.and_then(|signature| signature.signature_creation_time()),
    ) {
        (Some(binding_time), Some(revocation_time)) => revocation_time >= binding_time,
        (None, Some(_)) => true,
        _ => false,
    };

    (is_currently_primary, is_currently_revoked)
}
