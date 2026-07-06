//! Portable Modern key lifecycle tests (v6 Ed25519+X25519, RFC 9580 — issue #591 Phase 2).
//! Covers generation shape, algorithm-aware profile classification (an Ed25519
//! primary distinguishes Modern from the Ed448 Advanced tier), passphrase
//! export/import (Argon2id, like every v6 profile), and profile-mismatch guards.

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::PublicKeyAlgorithm;
use pgp_mobile::keys::{self, KeyProfile};
use sequoia_openpgp as openpgp;

fn generate_modern() -> keys::GeneratedKey {
    keys::generate_key_with_profile(
        "Modern Lifecycle".to_string(),
        Some("modern@lifecycle.example".to_string()),
        None,
        KeyProfile::Modern,
    )
    .expect("Modern key gen should succeed")
}

#[test]
fn test_generate_modern_cert_shape() {
    let key = generate_modern();
    let cert = openpgp::Cert::from_bytes(&key.public_key_data).expect("parse public cert");
    let policy = &StandardPolicy::new();

    assert_eq!(
        cert.primary_key().key().version(),
        6,
        "Modern cert must be v6"
    );
    assert_eq!(
        cert.primary_key().key().pk_algo(),
        PublicKeyAlgorithm::Ed25519,
        "primary must be the dedicated v6 Ed25519 (27), not the v4 EdDSALegacy"
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
        PublicKeyAlgorithm::X25519,
        "encryption subkey must be the dedicated v6 X25519 (25)"
    );
}

#[test]
fn test_detect_profile_classifies_modern() {
    let key = generate_modern();
    assert_eq!(
        keys::detect_profile(&key.public_key_data).expect("detect"),
        KeyProfile::Modern
    );

    let info = keys::parse_key_info(&key.public_key_data).expect("parse_key_info");
    assert_eq!(info.profile, KeyProfile::Modern);
    assert_eq!(info.key_version, 6);
}

#[test]
fn test_export_import_roundtrip_modern_uses_argon2id() {
    let key = generate_modern();

    let exported = keys::export_secret_key(&key.cert_data, "correct horse", KeyProfile::Modern)
        .expect("Modern export should succeed");

    let s2k = keys::parse_s2k_params(&exported).expect("parse S2K");
    assert_eq!(
        s2k.s2k_type, "argon2id",
        "Modern exports must use Argon2id like every v6 profile"
    );

    // Every secret packet must carry Argon2id individually — parse_s2k_params
    // reports the strongest S2K, which would mask a subkey silently falling
    // back to iterated-salted.
    let exported_cert = openpgp::Cert::from_bytes(&exported).expect("parse exported");
    for ka in exported_cert.keys().secret() {
        match ka.key().secret() {
            openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted) => {
                assert!(
                    matches!(encrypted.s2k(), openpgp::crypto::S2K::Argon2 { .. }),
                    "every Modern secret packet must use Argon2id, got {:?}",
                    encrypted.s2k()
                );
            }
            openpgp::packet::key::SecretKeyMaterial::Unencrypted(_) => {
                panic!("exported secret material must be passphrase-protected");
            }
        }
    }

    let imported = keys::import_secret_key(&exported, "correct horse").expect("Modern import");
    let imported_info = keys::parse_key_info(&imported).expect("info");
    assert_eq!(imported_info.fingerprint, key.fingerprint);
    assert_eq!(imported_info.profile, KeyProfile::Modern);
}

/// Negative: a Modern (v6 Ed25519) cert exported under Universal must be
/// rejected — the guard is algorithm-aware, so v6 material never takes the v4
/// iterated-salted path.
#[test]
fn test_export_wrong_profile_modern_cert_as_universal_fails() {
    let key = generate_modern();
    let result = keys::export_secret_key(&key.cert_data, "passphrase", KeyProfile::Universal);
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

/// Negative: the Modern (Ed25519) and Advanced (Ed448) classical tiers must not
/// be interchangeable — exporting an Advanced cert as Modern is a mismatch,
/// proving the guard distinguishes the two v6 classical curves.
#[test]
fn test_export_wrong_profile_advanced_cert_as_modern_fails() {
    let key = keys::generate_key_with_profile("B".to_string(), None, None, KeyProfile::Advanced)
        .expect("gen Advanced");
    let result = keys::export_secret_key(&key.cert_data, "passphrase", KeyProfile::Modern);
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
