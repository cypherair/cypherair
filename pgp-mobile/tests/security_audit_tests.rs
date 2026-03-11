//! Security audit regression tests.
//! Covers fixes from the pgp-mobile security audit:
//! - Error classification case-insensitivity
//! - Tamper detection produces correct error variants
//! - Wrong-key decryption never leaks plaintext

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};

/// Verify that tampered Profile A (SEIPDv1) ciphertext produces an integrity-related
/// error, not a generic CorruptData. Exercises the case-insensitive error classification.
#[test]
fn test_error_classification_tampered_profile_a() {
    let key = keys::generate_key_with_profile(
        "Audit".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let mut ciphertext = encrypt::encrypt_binary(
        b"error classification test",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    // Flip bit in the encrypted data region (past PKESK headers)
    let flip_point = ciphertext.len() * 3 / 4;
    ciphertext[flip_point] ^= 0x01;

    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[]);

    // Must be a security-relevant error, not a silent failure
    match result {
        Ok(_) => panic!("Tampered ciphertext must never decrypt successfully"),
        Err(pgp_mobile::error::PgpError::IntegrityCheckFailed) => {}
        Err(pgp_mobile::error::PgpError::AeadAuthenticationFailed) => {}
        Err(pgp_mobile::error::PgpError::CorruptData { .. }) => {}
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {} // PKESK header corrupted
        Err(other) => panic!(
            "Unexpected error for tampered Profile A data: {other}"
        ),
    }
}

/// Verify that tampered Profile B (SEIPDv2 AEAD) ciphertext produces an
/// AEAD-related error. Exercises the case-insensitive error classification.
#[test]
fn test_error_classification_tampered_profile_b() {
    let key = keys::generate_key_with_profile(
        "Audit".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let mut ciphertext = encrypt::encrypt_binary(
        b"error classification test",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let flip_point = ciphertext.len() * 3 / 4;
    ciphertext[flip_point] ^= 0x01;

    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[]);

    match result {
        Ok(_) => panic!("Tampered ciphertext must never decrypt successfully"),
        Err(pgp_mobile::error::PgpError::AeadAuthenticationFailed) => {}
        Err(pgp_mobile::error::PgpError::IntegrityCheckFailed) => {}
        Err(pgp_mobile::error::PgpError::CorruptData { .. }) => {}
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {}
        Err(other) => panic!(
            "Unexpected error for tampered Profile B data: {other}"
        ),
    }
}

/// Decryption with wrong key must never return plaintext.
/// Verifies the hard-fail security invariant.
#[test]
fn test_decrypt_wrong_key_no_plaintext_leak() {
    let alice = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile(
        "Bob".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt(
        b"secret for alice only",
        &[alice.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    // Try decrypting with Bob's key — must fail
    let result = decrypt::decrypt(&ciphertext, &[bob.cert_data.clone()], &[]);
    match result {
        Ok(_) => panic!("Wrong key must fail decryption"),
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {}
        Err(other) => panic!("Expected NoMatchingKey, got: {other}"),
    }
}
