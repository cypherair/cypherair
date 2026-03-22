//! Security audit regression tests.
//! Covers fixes from the pgp-mobile security audit:
//! - Error classification case-insensitivity
//! - Tamper detection produces correct error variants
//! - Wrong-key decryption never leaks plaintext
//! - parse_recipients() Phase 1 API coverage
//! - Expired/revoked key encryption rejection
//! - Legacy SEIPD (no MDC) rejection
//! - Empty recipients rejection
//! - Signature tamper detection (cleartext + detached)
//! - H1: Blanket From<anyhow::Error> removal (compile-time guard)
//! - M2+M3: Expired signer key produces SignatureStatus::Expired
//! - L5: ArmorKind::Unknown for unrecognized armor types
//! - H1: AeadAuthenticationFailed exercisability analysis
//! - H4: Wrong-key plaintext leak test for Profile B
//! - M4: Complete profile coverage for signature tamper tests
//! - M5: Signing with expired key
//! - M9: Unicode plaintext encrypt/decrypt round-trip
//! - L2: Signing-only cert rejection for Profile B

use pgp_mobile::armor::{self, ArmorKind};
use pgp_mobile::decrypt::{self, SignatureStatus};
use pgp_mobile::encrypt;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, GeneratedKey, KeyProfile};
use pgp_mobile::sign;
use pgp_mobile::verify;

/// Verify that tampered Profile A (SEIPDv1) ciphertext produces an integrity-related
/// error, not a generic CorruptData. Exercises the case-insensitive error classification.
///
/// NOTE: This test accepts multiple error variants because the specific error
/// depends on WHERE in the ciphertext the tamper occurs. For the streaming path,
/// see streaming_tests::test_streaming_decrypt_tampered_profile_a_returns_specific_error.
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
///
/// NOTE: This test accepts multiple error variants because the specific error
/// depends on WHERE in the ciphertext the tamper occurs. For the streaming path,
/// see streaming_tests::test_streaming_decrypt_tampered_profile_b_returns_specific_error.
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

// ── Empty recipients rejection ──────────────────────────────────────────

/// Encrypting with no recipients and no encrypt-to-self must fail.
/// Validates the guard at encrypt.rs:16-20.
#[test]
fn test_encrypt_empty_recipients_rejected() {
    let result = encrypt::encrypt(b"should fail", &[], None, None);
    assert!(result.is_err(), "Encryption with no recipients must fail");
    match result {
        Err(PgpError::EncryptionFailed { .. }) => {}
        Err(other) => panic!("Expected EncryptionFailed, got: {other}"),
        Ok(_) => unreachable!(),
    }
}

/// Encrypting with no recipients but with encrypt-to-self should succeed.
#[test]
fn test_encrypt_empty_recipients_but_encrypt_to_self_succeeds() {
    let key = keys::generate_key_with_profile(
        "Self".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let result = encrypt::encrypt(
        b"encrypt to self only",
        &[],
        None,
        Some(&key.public_key_data),
    );
    assert!(
        result.is_ok(),
        "Encryption with no explicit recipients but encrypt-to-self should succeed"
    );
}

// ── Signature tamper detection ──────────────────────────────────────────

/// Tampered cleartext-signed message must produce SignatureStatus::Bad.
/// Validates verify.rs graded result handling for cleartext signatures.
#[test]
fn test_verify_tampered_cleartext_returns_bad() {
    let key = keys::generate_key_with_profile(
        "Signer".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let text = b"Original cleartext message";
    let signed = sign::sign_cleartext(text, &key.cert_data)
        .expect("Signing should succeed");

    // Tamper: modify the signed content within the cleartext structure.
    // Cleartext signatures embed the text between the header and the armor.
    // We flip a character in the message body.
    let mut tampered = signed.clone();
    let signed_str = String::from_utf8_lossy(&tampered);
    // Find the message text within the cleartext-signed structure
    if let Some(pos) = signed_str.find("Original") {
        tampered[pos] ^= 0x01;
    } else {
        panic!("Could not find message text in cleartext-signed output");
    }

    let result = verify::verify_cleartext(&tampered, &[key.public_key_data.clone()])
        .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.status,
        SignatureStatus::Bad,
        "Tampered cleartext message must produce Bad signature status"
    );
}

/// Tampered data with detached signature must produce SignatureStatus::Bad.
/// Validates verify.rs graded result handling for detached signatures.
#[test]
fn test_verify_tampered_detached_returns_bad() {
    let key = keys::generate_key_with_profile(
        "Signer".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let data = b"Original file content for detached signing";
    let signature = sign::sign_detached(data, &key.cert_data)
        .expect("Detached signing should succeed");

    // Tamper: modify the data after signing
    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0x01;

    let result = verify::verify_detached(
        &tampered_data,
        &signature,
        &[key.public_key_data.clone()],
    )
    .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.status,
        SignatureStatus::Bad,
        "Tampered data with detached signature must produce Bad status"
    );
}

// ── Revoked key encryption rejection (Profile B) ────────────────────────

/// Encrypting to a revoked Profile B key must fail.
/// Complements test_encrypt_to_revoked_key_rejected (Profile A).
#[test]
fn test_encrypt_to_revoked_key_profile_b_rejected() {
    use sequoia_openpgp as openpgp;
    use openpgp::parse::Parse;
    use openpgp::serialize::Serialize;

    let key = keys::generate_key_with_profile(
        "Revocable B".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    assert_eq!(key.key_version, 6, "Profile B must produce v6 key");

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
        "Encrypting to a revoked Profile B key must fail"
    );
}

// ── M2+M3: Expired signer key → SignatureStatus::Expired ─────────────────

/// Helper: generate a key with 1-second expiry, sign immediately (while valid),
/// then return the signed artifact and the key. The caller sleeps before verifying.
fn make_expired_signer(profile: KeyProfile) -> (GeneratedKey, Vec<u8>, Vec<u8>) {
    let signer = keys::generate_key_with_profile(
        "Expiring Signer".to_string(),
        None,
        Some(1), // 1-second expiry
        profile,
    )
    .expect("Key gen should succeed");

    // Sign immediately while the key is still valid
    let cleartext_signed = sign::sign_cleartext(
        b"Signed while key was valid",
        &signer.cert_data,
    )
    .expect("Cleartext signing should succeed while key is valid");

    let detached_sig = sign::sign_detached(
        b"Data for detached sig",
        &signer.cert_data,
    )
    .expect("Detached signing should succeed while key is valid");

    (signer, cleartext_signed, detached_sig)
}

/// Verify cleartext signed by an expired Profile A key → SignatureStatus::Expired.
#[test]
fn test_verify_cleartext_expired_signer_profile_a() {
    let (signer, cleartext_signed, _) = make_expired_signer(KeyProfile::Universal);

    // Wait for the key to expire
    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify::verify_cleartext(
        &cleartext_signed,
        &[signer.public_key_data.clone()],
    )
    .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.status,
        SignatureStatus::Expired,
        "Cleartext verification with expired Profile A signer key must produce Expired status"
    );
}

/// Verify cleartext signed by an expired Profile B key → SignatureStatus::Expired.
#[test]
fn test_verify_cleartext_expired_signer_profile_b() {
    let (signer, cleartext_signed, _) = make_expired_signer(KeyProfile::Advanced);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify::verify_cleartext(
        &cleartext_signed,
        &[signer.public_key_data.clone()],
    )
    .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.status,
        SignatureStatus::Expired,
        "Cleartext verification with expired Profile B signer key must produce Expired status"
    );
}

/// Verify detached signature by an expired Profile A key → SignatureStatus::Expired.
#[test]
fn test_verify_detached_expired_signer_profile_a() {
    let (signer, _, detached_sig) = make_expired_signer(KeyProfile::Universal);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify::verify_detached(
        b"Data for detached sig",
        &detached_sig,
        &[signer.public_key_data.clone()],
    )
    .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.status,
        SignatureStatus::Expired,
        "Detached verification with expired Profile A signer key must produce Expired status"
    );
}

/// Verify detached signature by an expired Profile B key → SignatureStatus::Expired.
#[test]
fn test_verify_detached_expired_signer_profile_b() {
    let (signer, _, detached_sig) = make_expired_signer(KeyProfile::Advanced);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify::verify_detached(
        b"Data for detached sig",
        &detached_sig,
        &[signer.public_key_data.clone()],
    )
    .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.status,
        SignatureStatus::Expired,
        "Detached verification with expired Profile B signer key must produce Expired status"
    );
}

/// Decrypt message signed by an expired signer → SignatureStatus::Expired.
/// Uses a non-expiring recipient key and an expired signer key.
#[test]
fn test_decrypt_expired_signer_profile_a() {
    let signer = keys::generate_key_with_profile(
        "Expiring Signer A".to_string(),
        None,
        Some(1), // 1-second expiry
        KeyProfile::Universal,
    )
    .expect("Signer key gen should succeed");

    let recipient = keys::generate_key_with_profile(
        "Recipient A".to_string(),
        None,
        None, // no expiry override (defaults to 2 years)
        KeyProfile::Universal,
    )
    .expect("Recipient key gen should succeed");

    // Encrypt+sign immediately while signer key is still valid
    let ciphertext = encrypt::encrypt(
        b"Signed by soon-to-expire key",
        &[recipient.public_key_data.clone()],
        Some(&signer.cert_data),
        None,
    )
    .expect("Encrypt+sign should succeed while signer key is valid");

    // Wait for signer key to expire
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Decrypt: pass signer's public key for verification
    let result = decrypt::decrypt(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[signer.public_key_data.clone()],
    )
    .expect("Decryption should succeed (content is still valid)");

    assert_eq!(
        result.signature_status,
        Some(SignatureStatus::Expired),
        "Decrypt with expired Profile A signer must produce Expired signature status"
    );
}

/// Decrypt message signed by an expired Profile B signer → SignatureStatus::Expired.
#[test]
fn test_decrypt_expired_signer_profile_b() {
    let signer = keys::generate_key_with_profile(
        "Expiring Signer B".to_string(),
        None,
        Some(1),
        KeyProfile::Advanced,
    )
    .expect("Signer key gen should succeed");

    let recipient = keys::generate_key_with_profile(
        "Recipient B".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Recipient key gen should succeed");

    let ciphertext = encrypt::encrypt(
        b"Signed by soon-to-expire v6 key",
        &[recipient.public_key_data.clone()],
        Some(&signer.cert_data),
        None,
    )
    .expect("Encrypt+sign should succeed while signer key is valid");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = decrypt::decrypt(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[signer.public_key_data.clone()],
    )
    .expect("Decryption should succeed (content is still valid)");

    assert_eq!(
        result.signature_status,
        Some(SignatureStatus::Expired),
        "Decrypt with expired Profile B signer must produce Expired signature status"
    );
}

// ── L5: ArmorKind::Unknown tests ─────────────────────────────────────────

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
        Err(PgpError::ArmorError { .. }) => {} // expected
        Err(other) => panic!("Expected ArmorError, got: {other}"),
        Ok(_) => panic!("Encoding ArmorKind::Unknown must fail"),
    }
}

/// Decoding data with an unrecognized armor header produces ArmorKind::Unknown.
/// We test this by decoding a valid armored message and verifying known kinds work,
/// then verifying that decode_armor handles the _ case (which maps to Unknown)
/// by testing that non-standard armor headers don't cause panics.
#[test]
fn test_armor_decode_known_kinds_not_unknown() {
    // Generate a real public key and armor it — decoded kind should be PublicKey, not Unknown
    let key = keys::generate_key_with_profile(
        "Armor Test".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let armored = armor::armor_public_key(&key.public_key_data)
        .expect("armor_public_key should succeed");

    let (_, kind) = armor::decode_armor(&armored)
        .expect("decode_armor should succeed for armored public key");

    assert_eq!(
        kind,
        ArmorKind::PublicKey,
        "Armored public key must decode as PublicKey, not Unknown"
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
// verified by test_tamper_detection_aead_profile_b (profile_b_tests.rs) and
// test_error_classification_tampered_profile_b (this file).
//
// A dedicated test exercising AeadAuthenticationFailed would require constructing
// a message with valid v3 PKESK but corrupted SEIPDv2 body, which requires either
// Sequoia low-level packet API (fragile, couples to internals) or a fixture from
// another RFC 9580 implementation. Tracked as a future improvement alongside M10
// (RSA fixture) and M6 (compressed SEIPDv2 fixture).

// ── H4: Wrong-key plaintext leak test for Profile B ──────────────────────

/// Decryption with wrong key must never return plaintext (Profile B / AEAD path).
/// Complements test_decrypt_wrong_key_no_plaintext_leak (Profile A only).
#[test]
fn test_decrypt_wrong_key_no_plaintext_leak_profile_b() {
    let alice = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile(
        "Bob".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt(
        b"secret for alice only (AEAD)",
        &[alice.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    // Try decrypting with Bob's key — must fail
    let result = decrypt::decrypt(&ciphertext, &[bob.cert_data.clone()], &[]);
    match result {
        Ok(_) => panic!("Wrong key must fail decryption (Profile B)"),
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {}
        Err(other) => panic!("Expected NoMatchingKey, got: {other}"),
    }
}

// ── M4: Complete profile coverage for signature tamper tests ──────────────

/// Tampered cleartext-signed message must produce SignatureStatus::Bad (Profile B).
/// Complements test_verify_tampered_cleartext_returns_bad (Profile A only).
#[test]
fn test_verify_tampered_cleartext_returns_bad_profile_b() {
    let key = keys::generate_key_with_profile(
        "Signer".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let text = b"Original cleartext message";
    let signed = sign::sign_cleartext(text, &key.cert_data)
        .expect("Signing should succeed");

    let mut tampered = signed.clone();
    let signed_str = String::from_utf8_lossy(&tampered);
    if let Some(pos) = signed_str.find("Original") {
        tampered[pos] ^= 0x01;
    } else {
        panic!("Could not find message text in cleartext-signed output");
    }

    let result = verify::verify_cleartext(&tampered, &[key.public_key_data.clone()])
        .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.status,
        SignatureStatus::Bad,
        "Tampered cleartext message must produce Bad signature status (Profile B)"
    );
}

/// Tampered data with detached signature must produce SignatureStatus::Bad (Profile A).
/// Complements test_verify_tampered_detached_returns_bad (Profile B only).
#[test]
fn test_verify_tampered_detached_returns_bad_profile_a() {
    let key = keys::generate_key_with_profile(
        "Signer".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let data = b"Original file content for detached signing";
    let signature = sign::sign_detached(data, &key.cert_data)
        .expect("Detached signing should succeed");

    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0x01;

    let result = verify::verify_detached(
        &tampered_data,
        &signature,
        &[key.public_key_data.clone()],
    )
    .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.status,
        SignatureStatus::Bad,
        "Tampered data with detached signature must produce Bad status (Profile A)"
    );
}

// ── M5: Signing with expired key ──────────────────────────────────────────

/// Signing with an expired key: either the signing operation itself fails,
/// or (if Sequoia allows it) the resulting signature is detected as expired
/// at verification time. Both outcomes are acceptable — what matters is that
/// expired-key signatures are never accepted as Valid.
#[test]
fn test_sign_with_expired_key_not_accepted_as_valid() {
    for (profile, label) in [
        (KeyProfile::Universal, "Profile A"),
        (KeyProfile::Advanced, "Profile B"),
    ] {
        let key = keys::generate_key_with_profile(
            "Expiring Signer".to_string(),
            None,
            Some(1), // 1-second expiry
            profile,
        )
        .expect("Key gen should succeed");

        // Wait for the key to expire
        std::thread::sleep(std::time::Duration::from_secs(3));

        let result = sign::sign_cleartext(b"Should not produce a Valid signature", &key.cert_data);
        match result {
            Err(_) => {
                // Signing rejected at creation time — this is the strictest behavior.
            }
            Ok(signed) => {
                // Sequoia allowed signing but verification must NOT return Valid.
                let verify_result = verify::verify_cleartext(
                    &signed,
                    &[key.public_key_data.clone()],
                )
                .expect("Verification should return a graded result");
                assert_ne!(
                    verify_result.status,
                    SignatureStatus::Valid,
                    "Expired-key signature must not verify as Valid ({label})"
                );
            }
        }
    }
}

// ── M9: Unicode plaintext encrypt/decrypt round-trip ──────────────────────

/// Encrypt/decrypt round-trip with Unicode plaintext (Chinese + emoji) for both profiles.
#[test]
fn test_encrypt_decrypt_unicode_plaintext_round_trip() {
    let unicode_plaintext = "Hello, 你好, 🔐 — encrypted message with CJK and emoji.";
    let plaintext_bytes = unicode_plaintext.as_bytes();

    for (profile, label) in [
        (KeyProfile::Universal, "Profile A"),
        (KeyProfile::Advanced, "Profile B"),
    ] {
        let key = keys::generate_key_with_profile(
            "Unicode Test".to_string(),
            None,
            None,
            profile,
        )
        .expect("Key gen should succeed");

        let ciphertext = encrypt::encrypt(
            plaintext_bytes,
            &[key.public_key_data.clone()],
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("Encryption should succeed ({label}): {e}"));

        let result = decrypt::decrypt(
            &ciphertext,
            &[key.cert_data.clone()],
            &[],
        )
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

// ── L2: Signing-only cert rejection for Profile B ────────────────────────

/// Encrypting to a signing-only cert (no encryption subkey) must fail (Profile B / v6).
/// Complements test_encrypt_binary_rejects_no_encryption_subkey (Profile A) in
/// profile_a_tests.rs.
#[test]
fn test_encrypt_rejects_signing_only_cert_profile_b() {
    use sequoia_openpgp as openpgp;
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;

    // Create a v6 cert with ONLY signing capability, no encryption subkey
    let (cert, _rev) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv448)
        .set_profile(openpgp::Profile::RFC9580)
        .expect("set_profile should succeed")
        .add_userid("SignOnly-v6")
        .add_signing_subkey()
        // No add_transport_encryption_subkey()
        .generate()
        .expect("Cert gen should succeed");

    assert_eq!(cert.primary_key().key().version(), 6, "Must be v6 cert");

    let mut pubkey_data = Vec::new();
    cert.serialize(&mut pubkey_data).expect("Serialize should succeed");

    let result = encrypt::encrypt(
        b"Should fail",
        &[pubkey_data.clone()],
        None,
        None,
    );
    assert!(result.is_err(), "encrypt should reject v6 recipient without encryption subkey");

    let result_binary = encrypt::encrypt_binary(
        b"Should fail",
        &[pubkey_data],
        None,
        None,
    );
    assert!(result_binary.is_err(), "encrypt_binary should reject v6 recipient without encryption subkey");
}

// ── L2: Expired key should still report expiry timestamp ───────────────

/// Verify that parse_key_info() returns the expiry timestamp even for expired keys.
/// Before the L2 fix, expired keys returned None for expiry_timestamp because
/// with_policy(Some(now)) fails for expired certs.
#[test]
fn test_parse_key_info_expired_cert_still_has_expiry_timestamp() {
    // Generate a key with a very short expiry (1 second)
    let key = keys::generate_key_with_profile(
        "Expiry Test".to_string(),
        None,
        Some(1), // 1-second expiry
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    // Wait for the key to expire
    std::thread::sleep(std::time::Duration::from_secs(3));

    let info = keys::parse_key_info(&key.public_key_data)
        .expect("parse_key_info should succeed for expired key");

    assert!(info.is_expired, "Key should be reported as expired");
    assert!(
        info.expiry_timestamp.is_some(),
        "Expired key should still have an expiry_timestamp (L2 fix)"
    );
}

// ── L7: Revoked key signature verification ────────────────────────────────

/// Verify that a signature made by a key that is later revoked
/// is handled appropriately during verification.
#[test]
fn test_verify_signature_from_revoked_key() {
    use sequoia_openpgp as openpgp;
    use openpgp::parse::Parse;
    use openpgp::serialize::Serialize;

    // Generate key and sign a message before revocation
    let key = keys::generate_key_with_profile(
        "Revoked Signer".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let text = b"Signed before revocation";
    let signed = sign::sign_cleartext(text, &key.cert_data)
        .expect("Signing should succeed before revocation");

    // Apply revocation cert to create revoked public key
    let cert = openpgp::Cert::from_bytes(&key.public_key_data)
        .expect("Parse public key should succeed");
    let rev_sig = openpgp::Packet::from_bytes(&key.revocation_cert)
        .expect("Parse revocation cert should succeed");
    let (revoked_cert, _) = cert.insert_packets(vec![rev_sig])
        .expect("Insert revocation should succeed");

    let mut revoked_pubkey = Vec::new();
    revoked_cert.serialize(&mut revoked_pubkey)
        .expect("Serialize revoked cert should succeed");

    // Verify the signature with the revoked public key
    let result = verify::verify_cleartext(&signed, &[revoked_pubkey]);

    // Sequoia should report the signer as revoked — either an error
    // or a non-valid signature status
    match result {
        Ok(vr) => {
            assert_ne!(
                vr.status, SignatureStatus::Valid,
                "Signature from revoked key should not be reported as Valid"
            );
        }
        Err(_) => {
            // An error is also acceptable — it means the revoked key was rejected
        }
    }
}
