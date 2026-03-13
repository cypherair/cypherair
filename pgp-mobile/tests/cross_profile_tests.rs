//! Cross-Profile Interoperability tests.
//! Covers POC test cases C2X.1–C2X.5.
//! Validates format auto-selection by recipient key version.

mod common;
use common::detect_message_format;

use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::encrypt;
use pgp_mobile::decrypt;
use pgp_mobile::sign;
use pgp_mobile::verify;
use pgp_mobile::decrypt::SignatureStatus;

/// C2X.1: Profile A encrypts to Profile B recipient (v6 key).
/// Pass: message format is SEIPDv2. Recipient decrypts.
#[test]
fn test_profile_a_encrypts_to_profile_b() {
    let sender_a = keys::generate_key_with_profile(
        "Alice (A)".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Sender key gen should succeed");

    let recipient_b = keys::generate_key_with_profile(
        "Bob (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Recipient key gen should succeed");

    let plaintext = b"From Profile A sender to Profile B recipient.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_b.public_key_data.clone()],
        Some(&sender_a.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    // Profile B recipient should decrypt
    let result = decrypt::decrypt(
        &ciphertext,
        &[recipient_b.cert_data.clone()],
        &[sender_a.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.signature_status, Some(SignatureStatus::Valid));
}

/// C2X.2: Profile B encrypts to Profile A recipient (v4 key).
/// Pass: message format is SEIPDv1. Recipient decrypts.
#[test]
fn test_profile_b_encrypts_to_profile_a() {
    let sender_b = keys::generate_key_with_profile(
        "Alice (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Sender key gen should succeed");

    let recipient_a = keys::generate_key_with_profile(
        "Bob (A)".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Recipient key gen should succeed");

    let plaintext = b"From Profile B sender to Profile A recipient.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_a.public_key_data.clone()],
        Some(&sender_b.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    // Profile A recipient should decrypt
    let result = decrypt::decrypt(
        &ciphertext,
        &[recipient_a.cert_data.clone()],
        &[sender_b.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.signature_status, Some(SignatureStatus::Valid));
}

/// C2X.3: Profile B encrypts to mixed recipients (v4 + v6).
/// Pass: format is SEIPDv1 (lowest common). Both decrypt.
#[test]
fn test_mixed_recipients_v4_and_v6() {
    let _sender_b = keys::generate_key_with_profile(
        "Alice (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Sender key gen should succeed");

    let recipient_a = keys::generate_key_with_profile(
        "Bob (A)".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("v4 recipient key gen should succeed");

    let recipient_b = keys::generate_key_with_profile(
        "Charlie (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("v6 recipient key gen should succeed");

    let plaintext = b"Message to mixed v4+v6 recipients.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[
            recipient_a.public_key_data.clone(),
            recipient_b.public_key_data.clone(),
        ],
        None,
        None,
    )
    .expect("Encryption should succeed");

    // v4 recipient decrypts
    let result_a = decrypt::decrypt(
        &ciphertext,
        &[recipient_a.cert_data.clone()],
        &[],
    )
    .expect("v4 recipient should decrypt");
    assert_eq!(result_a.plaintext, plaintext);

    // v6 recipient decrypts
    let result_b = decrypt::decrypt(
        &ciphertext,
        &[recipient_b.cert_data.clone()],
        &[],
    )
    .expect("v6 recipient should decrypt");
    assert_eq!(result_b.plaintext, plaintext);
}

/// C2X.4: Profile B with encrypt-to-self encrypts to v4 recipient.
/// Pass: SEIPDv1 (mixed rule). Both sender and recipient decrypt.
#[test]
fn test_profile_b_encrypt_to_self_with_v4_recipient() {
    let sender_b = keys::generate_key_with_profile(
        "Alice (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Sender key gen should succeed");

    let recipient_a = keys::generate_key_with_profile(
        "Bob (A)".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Recipient key gen should succeed");

    let plaintext = b"B->A with encrypt-to-self (mixed -> SEIPDv1).";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_a.public_key_data.clone()],
        None,
        Some(&sender_b.public_key_data),
    )
    .expect("Encryption should succeed");

    // v4 recipient decrypts
    let result_a = decrypt::decrypt(
        &ciphertext,
        &[recipient_a.cert_data.clone()],
        &[],
    )
    .expect("v4 recipient should decrypt");
    assert_eq!(result_a.plaintext, plaintext);

    // v6 sender decrypts (encrypt-to-self)
    let result_b = decrypt::decrypt(
        &ciphertext,
        &[sender_b.cert_data.clone()],
        &[],
    )
    .expect("v6 sender should decrypt own message");
    assert_eq!(result_b.plaintext, plaintext);
}

/// C2X.5: Profile A signature verified by Profile B user, and vice versa.
#[test]
fn test_cross_profile_signature_verification() {
    let key_a = keys::generate_key_with_profile(
        "Alice (A)".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Profile A key gen should succeed");

    let key_b = keys::generate_key_with_profile(
        "Bob (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Profile B key gen should succeed");

    let text = b"Cross-profile signature test.";

    // Profile A signs, Profile B verifies
    let signed_a = sign::sign_cleartext(text, &key_a.cert_data)
        .expect("Profile A signing should succeed");
    let verify_a_by_b = verify::verify_cleartext(
        &signed_a,
        &[key_a.public_key_data.clone()],
    )
    .expect("Profile B should verify Profile A signature");
    assert_eq!(verify_a_by_b.status, SignatureStatus::Valid);

    // Profile B signs, Profile A verifies
    let signed_b = sign::sign_cleartext(text, &key_b.cert_data)
        .expect("Profile B signing should succeed");
    let verify_b_by_a = verify::verify_cleartext(
        &signed_b,
        &[key_b.public_key_data.clone()],
    )
    .expect("Profile A should verify Profile B signature");
    assert_eq!(verify_b_by_a.status, SignatureStatus::Valid);
}

/// Extended: Profile A sender signs encrypted message for Profile B recipient.
/// Full round-trip: sign + encrypt + decrypt + verify.
#[test]
fn test_cross_profile_signed_encrypted_round_trip() {
    let sender_a = keys::generate_key_with_profile(
        "Alice (A)".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Sender key gen should succeed");

    let recipient_b = keys::generate_key_with_profile(
        "Bob (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Recipient key gen should succeed");

    let plaintext = b"Full round-trip: A->B signed+encrypted.";

    // Encrypt and sign
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_b.public_key_data.clone()],
        Some(&sender_a.cert_data),
        Some(&sender_a.public_key_data),  // encrypt-to-self
    )
    .expect("Encryption should succeed");

    // Decrypt and verify
    let result = decrypt::decrypt(
        &ciphertext,
        &[recipient_b.cert_data.clone()],
        &[sender_a.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.signature_status, Some(SignatureStatus::Valid));
    assert_eq!(
        result.signer_fingerprint,
        Some(sender_a.fingerprint.clone())
    );
}

/// Extended: Profile B sender signs encrypted message for Profile A recipient.
/// Full round-trip: sign + encrypt + decrypt + verify.
/// Complements test_cross_profile_signed_encrypted_round_trip (which tests A→B).
#[test]
fn test_cross_profile_b_to_a_signed_encrypted_round_trip() {
    let sender_b = keys::generate_key_with_profile(
        "Alice (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Sender key gen should succeed");

    let recipient_a = keys::generate_key_with_profile(
        "Bob (A)".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Recipient key gen should succeed");

    let plaintext = b"Full round-trip: B->A signed+encrypted.";

    // Encrypt and sign (B sender → A recipient)
    // Per PRD: v4 recipient → SEIPDv1 format auto-selected
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_a.public_key_data.clone()],
        Some(&sender_b.cert_data),
        Some(&sender_b.public_key_data),  // encrypt-to-self
    )
    .expect("Encryption should succeed");

    // Recipient A decrypts and verifies sender B's signature
    let result = decrypt::decrypt(
        &ciphertext,
        &[recipient_a.cert_data.clone()],
        &[sender_b.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.signature_status, Some(SignatureStatus::Valid));
    assert_eq!(
        result.signer_fingerprint,
        Some(sender_b.fingerprint.clone())
    );

    // Sender B can also decrypt (encrypt-to-self)
    let result_self = decrypt::decrypt(
        &ciphertext,
        &[sender_b.cert_data.clone()],
        &[sender_b.public_key_data.clone()],
    )
    .expect("Sender should decrypt via encrypt-to-self");

    assert_eq!(result_self.plaintext, plaintext);
    assert_eq!(result_self.signature_status, Some(SignatureStatus::Valid));
}

/// Verify that encrypting to v4 recipient produces SEIPDv1.
/// This directly validates PRD Section 3.4 format auto-selection rule.
#[test]
fn test_format_selection_v4_recipient_produces_seipd_v1() {
    let recipient_a = keys::generate_key_with_profile(
        "Bob (A)".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Format check v4",
        &[recipient_a.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    let (has_v1, has_v2) = detect_message_format(&ciphertext);
    assert!(has_v1, "v4 recipient should produce SEIPDv1");
    assert!(!has_v2, "v4 recipient should NOT produce SEIPDv2");
}

/// Verify that encrypting to v6 recipient produces SEIPDv2 (AEAD).
#[test]
fn test_format_selection_v6_recipient_produces_seipd_v2() {
    let recipient_b = keys::generate_key_with_profile(
        "Bob (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Format check v6",
        &[recipient_b.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    let (has_v1, has_v2) = detect_message_format(&ciphertext);
    assert!(!has_v1, "v6 recipient should NOT produce SEIPDv1");
    assert!(has_v2, "v6 recipient should produce SEIPDv2 (AEAD)");
}

/// Verify that mixed v4+v6 recipients produce SEIPDv1 (lowest common denominator).
#[test]
fn test_format_selection_mixed_recipients_produces_seipd_v1() {
    let recipient_a = keys::generate_key_with_profile(
        "Bob (A)".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let recipient_b = keys::generate_key_with_profile(
        "Charlie (B)".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Format check mixed",
        &[
            recipient_a.public_key_data.clone(),
            recipient_b.public_key_data.clone(),
        ],
        None,
        None,
    )
    .expect("Encryption should succeed");

    let (has_v1, has_v2) = detect_message_format(&ciphertext);
    assert!(has_v1, "Mixed v4+v6 recipients should produce SEIPDv1");
    assert!(!has_v2, "Mixed v4+v6 recipients should NOT produce SEIPDv2");
}

/// Revocation cert from Profile A key should not verify against Profile B key (and vice versa).
#[test]
fn test_revocation_cert_cross_profile_mismatch() {
    let key_a = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Profile A key gen should succeed");

    let key_b = keys::generate_key_with_profile(
        "Bob".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Profile B key gen should succeed");

    // Profile A revocation cert vs Profile B cert
    let result = keys::parse_revocation_cert(&key_a.revocation_cert, &key_b.cert_data);
    assert!(result.is_err(), "Profile A revocation cert should not verify against Profile B key");

    // Profile B revocation cert vs Profile A cert
    let result = keys::parse_revocation_cert(&key_b.revocation_cert, &key_a.cert_data);
    assert!(result.is_err(), "Profile B revocation cert should not verify against Profile A key");
}
