//! Portable Post-Quantum key lifecycle tests (RFC 9980 — issue #567 Phase 2).
//! Covers generation shape, algorithm-aware profile classification,
//! passphrase export/import (Argon2id), and profile-mismatch guards.

mod common;

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::PublicKeyAlgorithm;
use pgp_mobile::keys::{self, KeyProfile};
use sequoia_openpgp as openpgp;

fn generate_pq() -> keys::GeneratedKey {
    keys::generate_key_with_profile(
        "PQ Lifecycle".to_string(),
        Some("pq@lifecycle.example".to_string()),
        None,
        KeyProfile::PostQuantum,
    )
    .expect("Post-Quantum key gen should succeed")
}

#[test]
fn test_generate_post_quantum_cert_shape() {
    let key = generate_pq();
    let cert = openpgp::Cert::from_bytes(&key.public_key_data).expect("parse public cert");
    let policy = &StandardPolicy::new();

    assert_eq!(cert.primary_key().key().version(), 6, "PQ cert must be v6");
    assert_eq!(
        cert.primary_key().key().pk_algo(),
        PublicKeyAlgorithm::MLDSA65_Ed25519,
        "primary must be composite ML-DSA-65+Ed25519"
    );

    let enc_keys: Vec<_> = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect();
    assert_eq!(enc_keys.len(), 1, "exactly one encryption subkey");
    assert_eq!(
        enc_keys[0].key().pk_algo(),
        PublicKeyAlgorithm::MLKEM768_X25519,
        "encryption subkey must be composite ML-KEM-768+X25519"
    );
}

#[test]
fn test_detect_profile_classifies_post_quantum() {
    let key = generate_pq();
    assert_eq!(
        keys::detect_profile(&key.public_key_data).expect("detect"),
        KeyProfile::PostQuantum
    );

    let info = keys::parse_key_info(&key.public_key_data).expect("parse_key_info");
    assert_eq!(info.profile, KeyProfile::PostQuantum);
    assert_eq!(info.key_version, 6);
}

/// A foreign (sq-style) RFC 9980 cert must classify as Post-Quantum, not
/// Modern High — the pre-fix version-only heuristic mislabeled it Advanced.
#[test]
fn test_detect_profile_classifies_foreign_pq_cert() {
    let (_tsk, pub_armored) = common::pq::generate_foreign_pq();
    assert_eq!(
        keys::detect_profile(&pub_armored).expect("detect"),
        KeyProfile::PostQuantum
    );
}

/// The higher RFC 9980 tier (ML-DSA-87+Ed448) classifies as its own
/// Post-Quantum · High profile — distinct from the 65/768 Post-Quantum tier.
#[test]
fn test_detect_profile_classifies_mldsa87_tier_as_post_quantum_high() {
    use openpgp::cert::{CertBuilder, CipherSuite};
    use openpgp::serialize::SerializeInto;

    let (cert, _rev) = CertBuilder::general_purpose(Some("PQ87 <pq87@interop.example>"))
        .set_cipher_suite(CipherSuite::MLDSA87_Ed448)
        .set_profile(openpgp::Profile::RFC9580)
        .expect("set RFC 9580 profile")
        .generate()
        .expect("generate 87-tier cert");
    let pub_armored = cert.armored().to_vec().expect("armor");
    assert_eq!(
        keys::detect_profile(&pub_armored).expect("detect"),
        KeyProfile::PostQuantumHigh
    );
}

/// The classical fallbacks must be unchanged by the algorithm-aware rule.
#[test]
fn test_detect_profile_classical_fallbacks_unchanged() {
    let universal =
        keys::generate_key_with_profile("A".to_string(), None, None, KeyProfile::Universal)
            .expect("gen A");
    let advanced =
        keys::generate_key_with_profile("B".to_string(), None, None, KeyProfile::Advanced)
            .expect("gen B");

    assert_eq!(
        keys::detect_profile(&universal.public_key_data).expect("detect A"),
        KeyProfile::Universal
    );
    assert_eq!(
        keys::detect_profile(&advanced.public_key_data).expect("detect B"),
        KeyProfile::Advanced
    );
}

#[test]
fn test_export_import_roundtrip_post_quantum_uses_argon2id() {
    let key = generate_pq();

    let exported =
        keys::export_secret_key(&key.cert_data, "correct horse", KeyProfile::PostQuantum)
            .expect("PQ export should succeed");

    let s2k = keys::parse_s2k_params(&exported).expect("parse S2K");
    assert_eq!(
        s2k.s2k_type, "argon2id",
        "Post-Quantum exports must use Argon2id like Modern High"
    );

    // Every secret packet must carry Argon2id individually — parse_s2k_params
    // reports the strongest S2K, which would mask a subkey silently falling
    // back to iterated-salted.
    let exported_cert = openpgp::Cert::from_bytes(&exported).expect("parse exported");
    let mut secret_packets = 0;
    for ka in exported_cert.keys().secret() {
        secret_packets += 1;
        match ka.key().secret() {
            openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted) => {
                assert!(
                    matches!(encrypted.s2k(), openpgp::crypto::S2K::Argon2 { .. }),
                    "every PQ secret packet must use Argon2id, got {:?}",
                    encrypted.s2k()
                );
            }
            openpgp::packet::key::SecretKeyMaterial::Unencrypted(_) => {
                panic!("exported secret material must be passphrase-protected");
            }
        }
    }
    assert!(
        secret_packets >= 3,
        "primary + both subkeys must be present"
    );

    let imported = keys::import_secret_key(&exported, "correct horse").expect("PQ import");
    let imported_info = keys::parse_key_info(&imported).expect("info");
    assert_eq!(imported_info.fingerprint, key.fingerprint);
    assert_eq!(imported_info.profile, KeyProfile::PostQuantum);
}

/// Negative: a PQ cert exported under the Advanced profile must be rejected —
/// the guard must be algorithm-aware, not just version-aware.
#[test]
fn test_export_wrong_profile_pq_cert_as_advanced_fails() {
    let key = generate_pq();
    let result = keys::export_secret_key(&key.cert_data, "passphrase", KeyProfile::Advanced);
    match result {
        Err(pgp_mobile::error::PgpError::S2kError { reason }) => {
            assert!(
                reason.contains("Profile mismatch"),
                "should be a profile mismatch: {reason}"
            );
        }
        other => panic!("Expected S2kError profile mismatch, got: {other:?}"),
    }
}

/// Negative: an Advanced (classical v6) cert exported as Post-Quantum must
/// be rejected for the same reason in the other direction.
#[test]
fn test_export_wrong_profile_advanced_cert_as_pq_fails() {
    let key = keys::generate_key_with_profile("B".to_string(), None, None, KeyProfile::Advanced)
        .expect("gen B");
    let result = keys::export_secret_key(&key.cert_data, "passphrase", KeyProfile::PostQuantum);
    match result {
        Err(pgp_mobile::error::PgpError::S2kError { reason }) => {
            assert!(
                reason.contains("Profile mismatch"),
                "should be a profile mismatch: {reason}"
            );
        }
        other => panic!("Expected S2kError profile mismatch, got: {other:?}"),
    }
}
