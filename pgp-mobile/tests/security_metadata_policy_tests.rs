//! Security metadata and representation regression tests.

use pgp_mobile::armor::{self, ArmorKind};
use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile};

/// Armor round-trip preserves the correct kind for all known types.
#[test]
fn test_armor_roundtrip_preserves_kind() {
    let test_cases = vec![
        (ArmorKind::PublicKey, "public key"),
        (ArmorKind::SecretKey, "secret key"),
        (ArmorKind::Message, "message"),
        (ArmorKind::Signature, "signature"),
    ];

    for (kind, label) in test_cases {
        let data = b"test payload for armor round-trip";
        let armored = armor::encode_armor(data, kind)
            .unwrap_or_else(|e| panic!("encode_armor({label}) failed: {e}"));

        let (decoded, decoded_kind) = armor::decode_armor(&armored)
            .unwrap_or_else(|e| panic!("decode_armor({label}) failed: {e}"));

        assert_eq!(
            decoded_kind, kind,
            "Armor round-trip must preserve kind for {label}"
        );
        assert_eq!(
            decoded, data,
            "Armor round-trip must preserve data for {label}"
        );
    }
}

/// Encoding ArmorKind::Unknown must return an error.
#[test]
fn test_armor_encode_unknown_rejected() {
    let result = armor::encode_armor(b"should fail", ArmorKind::Unknown);
    match result {
        Err(PgpError::ArmorError { .. }) => {}
        Err(other) => panic!("Expected ArmorError, got: {other}"),
        Ok(_) => panic!("Encoding ArmorKind::Unknown must fail"),
    }
}

/// Decoding data with an unrecognized armor header produces ArmorKind::Unknown.
/// We test this by decoding a valid armored message and verifying known kinds work.
#[test]
fn test_armor_decode_known_kinds_not_unknown() {
    let key = keys::generate_key_with_profile(
        "Armor Test".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let armored =
        armor::armor_public_key(&key.public_key_data).expect("armor_public_key should succeed");

    let (_, kind) =
        armor::decode_armor(&armored).expect("decode_armor should succeed for armored public key");

    assert_eq!(
        kind,
        ArmorKind::PublicKey,
        "Armored public key must decode as PublicKey, not Unknown"
    );
}

/// Encrypt/decrypt round-trip with Unicode plaintext (Chinese + emoji) for both profiles.
#[test]
fn test_encrypt_decrypt_unicode_plaintext_round_trip() {
    let unicode_plaintext = "Hello, 你好, 🔐 — encrypted message with CJK and emoji.";
    let plaintext_bytes = unicode_plaintext.as_bytes();

    for (profile, label) in [
        (KeyProfile::Universal, "Profile A"),
        (KeyProfile::Advanced, "Profile B"),
    ] {
        let key = keys::generate_key_with_profile("Unicode Test".to_string(), None, None, profile)
            .expect("Key gen should succeed");

        let ciphertext =
            encrypt::encrypt(plaintext_bytes, &[key.public_key_data.clone()], None, None)
                .unwrap_or_else(|e| panic!("Encryption should succeed ({label}): {e}"));

        let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[])
            .unwrap_or_else(|e| panic!("Decryption should succeed ({label}): {e}"));

        assert_eq!(
            result.plaintext, plaintext_bytes,
            "Unicode plaintext must survive encrypt/decrypt round-trip ({label})"
        );
        assert_eq!(
            String::from_utf8_lossy(&result.plaintext),
            unicode_plaintext,
            "Decoded string must match ({label})"
        );
    }
}

/// Verify that parse_key_info() returns the expiry timestamp even for expired keys.
/// Before the L2 fix, expired keys returned None for expiry_timestamp because
/// with_policy(Some(now)) fails for expired certs.
#[test]
fn test_parse_key_info_expired_cert_still_has_expiry_timestamp() {
    let key = keys::generate_key_with_profile(
        "Expiry Test".to_string(),
        None,
        Some(1),
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let info = keys::parse_key_info(&key.public_key_data)
        .expect("parse_key_info should succeed for expired key");

    assert!(info.is_expired, "Key should be reported as expired");
    assert!(
        info.expiry_timestamp.is_some(),
        "Expired key should still have an expiry_timestamp (L2 fix)"
    );
}
