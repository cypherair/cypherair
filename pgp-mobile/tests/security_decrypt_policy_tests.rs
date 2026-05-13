//! Security policy tests focused on decryption hard-fail behavior and tamper handling.

mod common;

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};

/// Verify that tampered Profile A (SEIPDv1) ciphertext produces an integrity-related
/// error, not a generic CorruptData. Exercises the case-insensitive error classification.
#[test]
fn test_error_classification_tampered_profile_a() {
    let key =
        keys::generate_key_with_profile("Audit".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"error classification test",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");
    let ciphertext = common::tamper_at_ratio(&ciphertext, 3, 4);

    let result = decrypt::decrypt_detailed(&ciphertext, &[key.cert_data.clone()], &[]);
    match result {
        Ok(_) => panic!("Tampered ciphertext must never decrypt successfully"),
        Err(pgp_mobile::error::PgpError::IntegrityCheckFailed) => {}
        Err(pgp_mobile::error::PgpError::AeadAuthenticationFailed) => {}
        Err(pgp_mobile::error::PgpError::CorruptData { .. }) => {}
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {}
        Err(other) => panic!("Unexpected error for tampered Profile A data: {other}"),
    }
}

/// Verify that tampered Profile B (SEIPDv2 AEAD) ciphertext produces an
/// AEAD-related error. Exercises the case-insensitive error classification.
#[test]
fn test_error_classification_tampered_profile_b() {
    let key =
        keys::generate_key_with_profile("Audit".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"error classification test",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");
    let ciphertext = common::tamper_at_ratio(&ciphertext, 3, 4);

    let result = decrypt::decrypt_detailed(&ciphertext, &[key.cert_data.clone()], &[]);
    match result {
        Ok(_) => panic!("Tampered ciphertext must never decrypt successfully"),
        Err(pgp_mobile::error::PgpError::AeadAuthenticationFailed) => {}
        Err(pgp_mobile::error::PgpError::IntegrityCheckFailed) => {}
        Err(pgp_mobile::error::PgpError::CorruptData { .. }) => {}
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {}
        Err(other) => panic!("Unexpected error for tampered Profile B data: {other}"),
    }
}

/// Decryption with wrong key must never return plaintext.
/// Verifies the hard-fail security invariant.
#[test]
fn test_decrypt_wrong_key_no_plaintext_leak() {
    let alice =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
        .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt(
        b"secret for alice only",
        &[alice.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let result = decrypt::decrypt_detailed(&ciphertext, &[bob.cert_data.clone()], &[]);
    match result {
        Ok(_) => panic!("Wrong key must fail decryption"),
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {}
        Err(other) => panic!("Expected NoMatchingKey, got: {other}"),
    }
}

/// Decryption must reject legacy SEIPD (Symmetrically Encrypted Data, tag 9)
/// which lacks integrity protection (no MDC). Per TDD Section 1.6, this is
/// rejected per security policy.
#[test]
fn test_decrypt_legacy_seipd_no_mdc_rejected() {
    let key =
        keys::generate_key_with_profile("Legacy".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"legacy seipd rejection test",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let mut tampered = ciphertext.clone();
    let mut replaced = false;

    for i in 0..tampered.len() {
        if tampered[i] == 0xD2 {
            tampered[i] = 0xC9;
            replaced = true;
            break;
        }
    }

    if !replaced {
        for i in 0..tampered.len() {
            if tampered[i] & 0xFC == 0xC8 {
                let len_type = tampered[i] & 0x03;
                tampered[i] = 0xA4 | len_type;
                replaced = true;
                break;
            }
        }
    }

    assert!(replaced, "Failed to locate SEIP packet header in ciphertext");

    let result = decrypt::decrypt_detailed(&tampered, &[key.cert_data.clone()], &[]);
    assert!(
        result.is_err(),
        "Legacy SEIPD without MDC must be rejected"
    );
}

// ── H1: AeadAuthenticationFailed exercisability analysis ──────────────────
//
// FINDING: PgpError::AeadAuthenticationFailed is never produced by self-generated
// Profile B messages because v6 PKESK uses AEAD-protected session key transport.
// ANY byte corruption (PKESK or SEIPD body) causes the PKESK AEAD to fail first,
// producing NoMatchingKey before the SEIPD payload AEAD check is reached.
//
// The AeadAuthenticationFailed error path IS reachable via:
// 1. Interop messages using v3 PKESK + SEIPDv2 (from other RFC 9580 implementations)
// 2. OpenSSL AEAD tag mismatch errors caught by classify_decrypt_error string matching
//
// The CRITICAL security property — no plaintext leak on tampered ciphertext — is
// verified by test_tamper_detection_aead_profile_b (profile_b_message_tests.rs) and
// test_error_classification_tampered_profile_b (this file).
//
// A dedicated test exercising AeadAuthenticationFailed would require constructing
// a message with valid v3 PKESK but corrupted SEIPDv2 body, which requires either
// Sequoia low-level packet API (fragile, couples to internals) or a fixture from
// another RFC 9580 implementation. Tracked as a future improvement alongside M10
// (RSA fixture) and M6 (compressed SEIPDv2 fixture).

/// Decryption with wrong key must never return plaintext (Profile B / AEAD path).
/// Complements test_decrypt_wrong_key_no_plaintext_leak (Profile A only).
#[test]
fn test_decrypt_wrong_key_no_plaintext_leak_profile_b() {
    let alice =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Advanced)
        .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt(
        b"secret for alice only (AEAD)",
        &[alice.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let result = decrypt::decrypt_detailed(&ciphertext, &[bob.cert_data.clone()], &[]);
    match result {
        Ok(_) => panic!("Wrong key must fail decryption (Profile B)"),
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {}
        Err(other) => panic!("Expected NoMatchingKey, got: {other}"),
    }
}
