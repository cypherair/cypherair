//! Security policy tests for recipient handling and recipient-facing encryption rules.

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::sign;

/// parse_recipients() returns valid hex key IDs for a Profile A message.
#[test]
fn test_parse_recipients_valid_message_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let ciphertext =
        encrypt::encrypt_binary(b"Phase 1 test", &[key.public_key_data.clone()], None, None)
            .expect("Encrypt should succeed");

    let recipients =
        decrypt::parse_recipients(&ciphertext).expect("parse_recipients should succeed");

    assert!(!recipients.is_empty(), "Must have at least one recipient");
    for rid in &recipients {
        assert!(
            rid.chars().all(|c| c.is_ascii_hexdigit()),
            "Recipient ID must be hex, got: {rid}"
        );
    }
}

/// parse_recipients() returns valid key IDs for a Profile B message.
#[test]
fn test_parse_recipients_valid_message_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Phase 1 test B",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let recipients =
        decrypt::parse_recipients(&ciphertext).expect("parse_recipients should succeed");

    assert!(!recipients.is_empty(), "Must have at least one recipient");
}

/// parse_recipients() returns multiple IDs for multi-recipient messages.
#[test]
fn test_parse_recipients_multi_recipient() {
    let alice =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
        .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Multi-recipient test",
        &[alice.public_key_data.clone(), bob.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let recipients =
        decrypt::parse_recipients(&ciphertext).expect("parse_recipients should succeed");

    assert!(
        recipients.len() >= 2,
        "Multi-recipient message must have >= 2 PKESKs, got {}",
        recipients.len()
    );
}

/// parse_recipients() fails on non-OpenPGP data.
#[test]
fn test_parse_recipients_corrupt_data() {
    let garbage = b"This is not an OpenPGP message at all.";
    let result = decrypt::parse_recipients(garbage);
    assert!(
        result.is_err(),
        "parse_recipients must fail on non-OpenPGP data"
    );
}

/// parse_recipients() fails on a cleartext-signed message (no PKESK).
#[test]
fn test_parse_recipients_signed_not_encrypted() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let signed = sign::sign_cleartext(b"Just signed, not encrypted", &key.cert_data)
        .expect("Sign should succeed");

    let result = decrypt::parse_recipients(&signed);
    assert!(
        result.is_err(),
        "parse_recipients must fail on signed-only message (no PKESK)"
    );
}

/// Encrypting to an expired key must fail (Profile A).
/// Uses 1-second expiry + sleep to create a genuinely expired key.
#[test]
fn test_encrypt_to_expired_key_rejected_profile_a() {
    let key = keys::generate_key_with_profile(
        "Expiring".to_string(),
        None,
        Some(1),
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result =
        encrypt::encrypt_binary(b"Should fail", &[key.public_key_data.clone()], None, None);

    assert!(result.is_err(), "Encrypting to an expired v4 key must fail");
}

/// Encrypting to an expired key must fail (Profile B).
#[test]
fn test_encrypt_to_expired_key_rejected_profile_b() {
    let key = keys::generate_key_with_profile(
        "Expiring".to_string(),
        None,
        Some(1),
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result =
        encrypt::encrypt_binary(b"Should fail", &[key.public_key_data.clone()], None, None);

    assert!(result.is_err(), "Encrypting to an expired v6 key must fail");
}

/// Encrypting to a revoked key must fail.
/// Applies the auto-generated revocation cert to the key, then attempts encryption.
#[test]
fn test_encrypt_to_revoked_key_rejected() {
    use openpgp::parse::Parse;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp as openpgp;

    let key =
        keys::generate_key_with_profile("Revoked".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let cert =
        openpgp::Cert::from_bytes(&key.public_key_data).expect("Parse public key should succeed");
    let rev_sig = openpgp::Packet::from_bytes(&key.revocation_cert)
        .expect("Parse revocation cert should succeed");
    let (revoked_cert, _) = cert
        .insert_packets(vec![rev_sig])
        .expect("Insert revocation should succeed");

    let mut revoked_pubkey = Vec::new();
    revoked_cert
        .serialize(&mut revoked_pubkey)
        .expect("Serialize revoked cert should succeed");

    let result = encrypt::encrypt_binary(b"Should fail", &[revoked_pubkey], None, None);
    assert!(result.is_err(), "Encrypting to a revoked key must fail");
}

/// Encrypting to a revoked Profile B key must fail.
/// Complements test_encrypt_to_revoked_key_rejected (Profile A).
#[test]
fn test_encrypt_to_revoked_key_profile_b_rejected() {
    use openpgp::parse::Parse;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp as openpgp;

    let key =
        keys::generate_key_with_profile("Revoked-v6".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let cert =
        openpgp::Cert::from_bytes(&key.public_key_data).expect("Parse public key should succeed");
    let rev_sig = openpgp::Packet::from_bytes(&key.revocation_cert)
        .expect("Parse revocation cert should succeed");
    let (revoked_cert, _) = cert
        .insert_packets(vec![rev_sig])
        .expect("Insert revocation should succeed");

    let mut revoked_pubkey = Vec::new();
    revoked_cert
        .serialize(&mut revoked_pubkey)
        .expect("Serialize revoked cert should succeed");

    let result = encrypt::encrypt_binary(b"Should fail", &[revoked_pubkey], None, None);
    assert!(
        result.is_err(),
        "Encrypting to a revoked Profile B key must fail"
    );
}

/// Encrypting with no recipients and no encrypt-to-self must fail.
#[test]
fn test_encrypt_empty_recipients_rejected() {
    let result = encrypt::encrypt_binary(b"Should fail", &[], None, None);
    assert!(
        result.is_err(),
        "Encrypting with no recipients and no encrypt-to-self must fail"
    );
}

/// Encrypting with no recipients but with encrypt-to-self should succeed.
#[test]
fn test_encrypt_empty_recipients_but_encrypt_to_self_succeeds() {
    let self_key =
        keys::generate_key_with_profile("Self".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let result = encrypt::encrypt_binary(
        b"Self-only message",
        &[],
        None,
        Some(&self_key.public_key_data),
    );
    assert!(result.is_ok(), "encrypt-to-self should allow empty recipient list");
}

/// Encrypting to a signing-only cert (no encryption subkey) must fail (Profile B / v6).
/// Complements test_encrypt_binary_rejects_no_encryption_subkey (Profile A) in
/// profile_a_message_tests.rs.
#[test]
fn test_encrypt_rejects_signing_only_cert_profile_b() {
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp as openpgp;

    let (cert, _rev) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv448)
        .set_profile(openpgp::Profile::RFC9580)
        .expect("set_profile should succeed")
        .add_userid("SignOnly-v6")
        .add_signing_subkey()
        .generate()
        .expect("Cert gen should succeed");

    assert_eq!(cert.primary_key().key().version(), 6, "Must be v6 cert");

    let mut pubkey_data = Vec::new();
    cert.serialize(&mut pubkey_data)
        .expect("Serialize should succeed");

    let result = encrypt::encrypt(b"Should fail", &[pubkey_data.clone()], None, None);
    assert!(
        result.is_err(),
        "encrypt should reject v6 recipient without encryption subkey"
    );

    let result_binary = encrypt::encrypt_binary(b"Should fail", &[pubkey_data], None, None);
    assert!(
        result_binary.is_err(),
        "encrypt_binary should reject v6 recipient without encryption subkey"
    );
}
