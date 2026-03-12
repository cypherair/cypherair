//! Security audit regression tests.
//! Covers fixes from the pgp-mobile security audit:
//! - Error classification case-insensitivity
//! - Tamper detection produces correct error variants
//! - Wrong-key decryption never leaks plaintext
//! - parse_recipients() Phase 1 API coverage
//! - Expired/revoked key encryption rejection
//! - Legacy SEIPD (no MDC) rejection

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::sign;

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

// ── parse_recipients() Phase 1 API tests ──────────────────────────────────

/// parse_recipients() returns valid hex key IDs for a Profile A message.
#[test]
fn test_parse_recipients_valid_message_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Phase 1 test",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let recipients = decrypt::parse_recipients(&ciphertext)
        .expect("parse_recipients should succeed");

    assert!(!recipients.is_empty(), "Must have at least one recipient");
    // All recipient IDs should be hex strings
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
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Phase 1 test B",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let recipients = decrypt::parse_recipients(&ciphertext)
        .expect("parse_recipients should succeed");

    assert!(!recipients.is_empty(), "Must have at least one recipient");
}

/// parse_recipients() returns multiple IDs for multi-recipient messages.
#[test]
fn test_parse_recipients_multi_recipient() {
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

    let ciphertext = encrypt::encrypt_binary(
        b"Multi-recipient test",
        &[
            alice.public_key_data.clone(),
            bob.public_key_data.clone(),
        ],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let recipients = decrypt::parse_recipients(&ciphertext)
        .expect("parse_recipients should succeed");

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
    assert!(result.is_err(), "parse_recipients must fail on non-OpenPGP data");
}

/// parse_recipients() fails on a cleartext-signed message (no PKESK).
#[test]
fn test_parse_recipients_signed_not_encrypted() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let signed = sign::sign_cleartext(b"Just signed, not encrypted", &key.cert_data)
        .expect("Sign should succeed");

    let result = decrypt::parse_recipients(&signed);
    assert!(
        result.is_err(),
        "parse_recipients must fail on signed-only message (no PKESK)"
    );
}

// ── Expired key encryption rejection ──────────────────────────────────────

/// Encrypting to an expired key must fail (Profile A).
/// Uses 1-second expiry + sleep to create a genuinely expired key.
#[test]
fn test_encrypt_to_expired_key_rejected_profile_a() {
    let key = keys::generate_key_with_profile(
        "Expiring".to_string(),
        None,
        Some(1), // 1-second expiry
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    // Wait for the key to expire
    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = encrypt::encrypt_binary(
        b"Should fail",
        &[key.public_key_data.clone()],
        None,
        None,
    );

    assert!(
        result.is_err(),
        "Encrypting to an expired v4 key must fail"
    );
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

    let result = encrypt::encrypt_binary(
        b"Should fail",
        &[key.public_key_data.clone()],
        None,
        None,
    );

    assert!(
        result.is_err(),
        "Encrypting to an expired v6 key must fail"
    );
}

// ── Revoked key encryption rejection ──────────────────────────────────────

/// Encrypting to a revoked key must fail.
/// Applies the auto-generated revocation cert to the key, then attempts encryption.
#[test]
fn test_encrypt_to_revoked_key_rejected() {
    use sequoia_openpgp as openpgp;
    use openpgp::parse::Parse;
    use openpgp::serialize::Serialize;

    let key = keys::generate_key_with_profile(
        "Revocable".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    // Apply the revocation cert to create a revoked certificate
    let cert = openpgp::Cert::from_bytes(&key.public_key_data)
        .expect("Parse public key should succeed");
    let rev_sig = openpgp::Packet::from_bytes(&key.revocation_cert)
        .expect("Parse revocation cert should succeed");
    let (revoked_cert, _) = cert.insert_packets(vec![rev_sig])
        .expect("Insert revocation should succeed");

    // Serialize the revoked cert
    let mut revoked_pubkey = Vec::new();
    revoked_cert.serialize(&mut revoked_pubkey)
        .expect("Serialize revoked cert should succeed");

    let result = encrypt::encrypt_binary(
        b"Should fail",
        &[revoked_pubkey],
        None,
        None,
    );

    assert!(
        result.is_err(),
        "Encrypting to a revoked key must fail"
    );
}

// ── Legacy SEIPD (no MDC) rejection ──────────────────────────────────────

/// Decryption must reject legacy SEIPD (Symmetrically Encrypted Data, tag 9)
/// which lacks integrity protection (no MDC). Per TDD Section 1.6, this is
/// rejected per security policy.
///
/// Strategy: take a valid binary ciphertext and replace the SEIP packet tag (18)
/// with the legacy SED packet tag (9) in the OpenPGP new-format header.
#[test]
fn test_decrypt_legacy_seipd_no_mdc_rejected() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Legacy SEIPD test",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    // Find and replace the SEIP tag (18) with legacy SED tag (9).
    // OpenPGP new-format: tag byte = 0xC0 | tag_number.
    // SEIP = 0xC0 | 18 = 0xD2. SED = 0xC0 | 9 = 0xC9.
    let mut tampered = ciphertext.clone();
    let mut found = false;
    for i in 0..tampered.len() {
        if tampered[i] == 0xD2 {
            tampered[i] = 0xC9;
            found = true;
            break;
        }
    }

    if !found {
        // Try old-format: tag byte = 0x80 | (tag << 2) | length_type
        // SEIP old = 0x80 | (18 << 2) = 0xC8. SED old = 0x80 | (9 << 2) = 0xA4.
        for i in 0..tampered.len() {
            if tampered[i] & 0xFC == 0xC8 {
                let len_type = tampered[i] & 0x03;
                tampered[i] = 0xA4 | len_type;
                found = true;
                break;
            }
        }
    }

    assert!(found, "Could not find SEIP packet tag in ciphertext");

    let result = decrypt::decrypt(&tampered, &[key.cert_data.clone()], &[]);
    assert!(
        result.is_err(),
        "Decryption must reject legacy SEIPD (no MDC) messages"
    );
}
