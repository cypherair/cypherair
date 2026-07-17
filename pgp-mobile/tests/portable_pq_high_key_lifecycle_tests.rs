//! Portable Post-Quantum · High key lifecycle tests
//! (RFC 9980 ML-DSA-87+Ed448 / ML-KEM-1024+X448).
//! Mirrors the 65/768 lifecycle: generation shape, classification as its own
//! Post-Quantum · High tier (distinct from the 65/768 Post-Quantum tier),
//! Argon2id export/import, and cross-tier mismatch guards.

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::PublicKeyAlgorithm;
use pgp_mobile::keys::{self, KeyProfile};
use sequoia_openpgp as openpgp;

fn generate_pq_high() -> keys::GeneratedKey {
    keys::generate_key_with_profile(
        "PQ High Lifecycle".to_string(),
        Some("pqhigh@lifecycle.example".to_string()),
        None,
        KeyProfile::PostQuantumHigh,
    )
    .expect("Post-Quantum · High key gen should succeed")
}

#[test]
fn test_generate_post_quantum_high_cert_shape() {
    let key = generate_pq_high();
    let cert = openpgp::Cert::from_bytes(&key.public_key_data).expect("parse public cert");
    let policy = &StandardPolicy::new();

    assert_eq!(
        cert.primary_key().key().version(),
        6,
        "PQ-High cert must be v6"
    );
    assert_eq!(
        cert.primary_key().key().pk_algo(),
        PublicKeyAlgorithm::MLDSA87_Ed448,
        "primary must be composite ML-DSA-87+Ed448"
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
        PublicKeyAlgorithm::MLKEM1024_X448,
        "encryption subkey must be composite ML-KEM-1024+X448"
    );
}

#[test]
fn test_detect_profile_classifies_post_quantum_high() {
    let key = generate_pq_high();
    assert_eq!(
        keys::detect_profile(&key.public_key_data).expect("detect"),
        KeyProfile::PostQuantumHigh
    );

    let info = keys::parse_key_info(&key.public_key_data).expect("parse_key_info");
    assert_eq!(info.profile, KeyProfile::PostQuantumHigh);
    assert_eq!(info.key_version, 6);
}

#[test]
fn test_export_import_roundtrip_post_quantum_high_uses_argon2id() {
    let key = generate_pq_high();

    let exported =
        keys::export_secret_key(&key.cert_data, "correct horse", KeyProfile::PostQuantumHigh)
            .expect("PQ-High export should succeed");

    let s2k = keys::parse_s2k_params(&exported).expect("parse S2K");
    assert_eq!(
        s2k.s2k_type, "argon2id",
        "Post-Quantum · High exports must use Argon2id"
    );

    let exported_cert = openpgp::Cert::from_bytes(&exported).expect("parse exported");
    let mut secret_packets = 0;
    for ka in exported_cert.keys().secret() {
        secret_packets += 1;
        match ka.key().secret() {
            openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted) => {
                assert!(
                    matches!(encrypted.s2k(), openpgp::crypto::S2K::Argon2 { .. }),
                    "every PQ-High secret packet must use Argon2id, got {:?}",
                    encrypted.s2k()
                );
            }
            openpgp::packet::key::SecretKeyMaterial::Unencrypted(_) => {
                panic!("exported secret material must be passphrase-protected");
            }
        }
    }
    assert!(secret_packets >= 2, "primary + encryption subkey must be present");

    let imported = keys::import_secret_key(&exported, "correct horse").expect("PQ-High import");
    let imported_info = keys::parse_key_info(&imported).expect("info");
    assert_eq!(imported_info.fingerprint, key.fingerprint);
    assert_eq!(imported_info.profile, KeyProfile::PostQuantumHigh);
}

/// Negative: the two RFC 9980 tiers must not be interchangeable — exporting a
/// PQ-High cert under the 65/768 Post-Quantum profile is a mismatch.
#[test]
fn test_export_wrong_profile_pq_high_cert_as_post_quantum_fails() {
    let key = generate_pq_high();
    let result = keys::export_secret_key(&key.cert_data, "passphrase", KeyProfile::PostQuantum);
    match result {
        // The typed S2kError variant (with panic on any other) is the guarantee;
        // this controlled wrong-profile export reaches it only through the
        // profile/key-version mismatch, so the prose reason adds nothing.
        Err(pgp_mobile::error::PgpError::S2kError { .. }) => {}
        other => panic!("Expected S2kError profile mismatch, got: {other:?}"),
    }
}

/// Negative: the reverse direction — a 65/768 Post-Quantum cert exported as
/// PQ-High must also be rejected.
#[test]
fn test_export_wrong_profile_post_quantum_cert_as_pq_high_fails() {
    let key =
        keys::generate_key_with_profile("PQ".to_string(), None, None, KeyProfile::PostQuantum)
            .expect("gen PQ");
    let result = keys::export_secret_key(&key.cert_data, "passphrase", KeyProfile::PostQuantumHigh);
    match result {
        // The typed S2kError variant (with panic on any other) is the guarantee;
        // this controlled wrong-profile export reaches it only through the
        // profile/key-version mismatch, so the prose reason adds nothing.
        Err(pgp_mobile::error::PgpError::S2kError { .. }) => {}
        other => panic!("Expected S2kError profile mismatch, got: {other:?}"),
    }
}
