use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeySuite, CONTACT_IMPORT_PUBLIC_ONLY_REASON};

fn generate_key(suite: KeySuite, name: &str) -> keys::GeneratedKey {
    keys::generate_key_with_suite(
        name.to_string(),
        Some(format!("{}@example.com", name.to_lowercase())),
        None,
        suite,
    )
    .expect("key generation should succeed")
}

#[test]
fn test_validate_public_certificate_accepts_legacy_public_cert() {
    let generated = generate_key(KeySuite::Ed25519LegacyCurve25519Legacy, "ValidatePublicA");

    let result = keys::validate_public_certificate(&generated.public_key_data)
        .expect("legacy public cert should validate");

    assert_eq!(result.key_info.fingerprint, generated.fingerprint);
    assert_eq!(result.suite, KeySuite::Ed25519LegacyCurve25519Legacy);
    assert_eq!(result.public_cert_data, generated.public_key_data);
}

#[test]
fn test_validate_public_certificate_accepts_modern_high_public_cert() {
    let generated = generate_key(KeySuite::Ed448X448, "ValidatePublicB");

    let result = keys::validate_public_certificate(&generated.public_key_data)
        .expect("modern high public cert should validate");

    assert_eq!(result.key_info.fingerprint, generated.fingerprint);
    assert_eq!(result.suite, KeySuite::Ed448X448);
    assert_eq!(result.public_cert_data, generated.public_key_data);
}

#[test]
fn test_validate_public_certificate_rejects_legacy_secret_cert() {
    let generated = generate_key(KeySuite::Ed25519LegacyCurve25519Legacy, "ValidateSecretA");

    let error = keys::validate_public_certificate(&generated.cert_data)
        .expect_err("legacy secret cert must be rejected");

    match error {
        PgpError::InvalidKeyData { reason } => {
            assert_eq!(reason, CONTACT_IMPORT_PUBLIC_ONLY_REASON);
        }
        other => panic!("expected InvalidKeyData, got {other:?}"),
    }
}

#[test]
fn test_validate_public_certificate_rejects_modern_high_secret_cert() {
    let generated = generate_key(KeySuite::Ed448X448, "ValidateSecretB");

    let error = keys::validate_public_certificate(&generated.cert_data)
        .expect_err("modern high secret cert must be rejected");

    match error {
        PgpError::InvalidKeyData { reason } => {
            assert_eq!(reason, CONTACT_IMPORT_PUBLIC_ONLY_REASON);
        }
        other => panic!("expected InvalidKeyData, got {other:?}"),
    }
}
