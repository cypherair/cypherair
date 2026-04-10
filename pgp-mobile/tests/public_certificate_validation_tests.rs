use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile, CONTACT_IMPORT_PUBLIC_ONLY_REASON};

fn generate_key(profile: KeyProfile, name: &str) -> keys::GeneratedKey {
    keys::generate_key_with_profile(
        name.to_string(),
        Some(format!("{}@example.com", name.to_lowercase())),
        None,
        profile,
    )
    .expect("key generation should succeed")
}

#[test]
fn test_validate_public_certificate_accepts_profile_a_public_cert() {
    let generated = generate_key(KeyProfile::Universal, "ValidatePublicA");

    let result = keys::validate_public_certificate(&generated.public_key_data)
        .expect("profile A public cert should validate");

    assert_eq!(result.key_info.fingerprint, generated.fingerprint);
    assert_eq!(result.profile, KeyProfile::Universal);
    assert_eq!(result.public_cert_data, generated.public_key_data);
}

#[test]
fn test_validate_public_certificate_accepts_profile_b_public_cert() {
    let generated = generate_key(KeyProfile::Advanced, "ValidatePublicB");

    let result = keys::validate_public_certificate(&generated.public_key_data)
        .expect("profile B public cert should validate");

    assert_eq!(result.key_info.fingerprint, generated.fingerprint);
    assert_eq!(result.profile, KeyProfile::Advanced);
    assert_eq!(result.public_cert_data, generated.public_key_data);
}

#[test]
fn test_validate_public_certificate_rejects_profile_a_secret_cert() {
    let generated = generate_key(KeyProfile::Universal, "ValidateSecretA");

    let error = keys::validate_public_certificate(&generated.cert_data)
        .expect_err("profile A secret cert must be rejected");

    match error {
        PgpError::InvalidKeyData { reason } => {
            assert_eq!(reason, CONTACT_IMPORT_PUBLIC_ONLY_REASON);
        }
        other => panic!("expected InvalidKeyData, got {other:?}"),
    }
}

#[test]
fn test_validate_public_certificate_rejects_profile_b_secret_cert() {
    let generated = generate_key(KeyProfile::Advanced, "ValidateSecretB");

    let error = keys::validate_public_certificate(&generated.cert_data)
        .expect_err("profile B secret cert must be rejected");

    match error {
        PgpError::InvalidKeyData { reason } => {
            assert_eq!(reason, CONTACT_IMPORT_PUBLIC_ONLY_REASON);
        }
        other => panic!("expected InvalidKeyData, got {other:?}"),
    }
}
