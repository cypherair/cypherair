//! Cross-Profile Interoperability tests.
//! Validates format auto-selection by recipient key version.

mod common;
use common::detect_message_format;

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeySuite};
use pgp_mobile::sign;
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::verify;

/// Legacy encrypts to Modern High recipient (v6 key).
/// Pass: message format is SEIPDv2. Recipient decrypts.
#[test]
fn test_legacy_encrypts_to_modern_high() {
    let sender_a =
        keys::generate_key_with_suite("Alice (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Sender key gen should succeed");

    let recipient_b =
        keys::generate_key_with_suite("Bob (B)".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Recipient key gen should succeed");

    let plaintext = b"From Legacy sender to Modern High recipient.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_b.public_key_data.clone()],
        Some(&sender_a.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    // Modern High recipient should decrypt
    let result = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient_b.cert_data.clone()],
        &[sender_a.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}

/// Modern High encrypts to Legacy recipient (v4 key).
/// Pass: message format is SEIPDv1. Recipient decrypts.
#[test]
fn test_modern_high_encrypts_to_legacy() {
    let sender_b =
        keys::generate_key_with_suite("Alice (B)".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Sender key gen should succeed");

    let recipient_a =
        keys::generate_key_with_suite("Bob (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Recipient key gen should succeed");

    let plaintext = b"From Modern High sender to Legacy recipient.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_a.public_key_data.clone()],
        Some(&sender_b.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    // Legacy recipient should decrypt
    let result = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient_a.cert_data.clone()],
        &[sender_b.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}

/// Modern High encrypts to mixed recipients (v4 + v6).
/// Pass: format is SEIPDv1 (lowest common). Both decrypt.
#[test]
fn test_mixed_recipients_v4_and_v6() {
    let sender_b =
        keys::generate_key_with_suite("Alice (B)".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Sender key gen should succeed");

    let recipient_a =
        keys::generate_key_with_suite("Bob (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("v4 recipient key gen should succeed");

    let recipient_b = keys::generate_key_with_suite(
        "Charlie (B)".to_string(),
        None,
        None,
        KeySuite::Ed448X448,
    )
    .expect("v6 recipient key gen should succeed");

    let plaintext = b"Message to mixed v4+v6 recipients.";

    // Use sender_b as the signing key
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[
            recipient_a.public_key_data.clone(),
            recipient_b.public_key_data.clone(),
        ],
        Some(&sender_b.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    // v4 recipient decrypts
    let result_a = decrypt::decrypt_detailed(&ciphertext, &[recipient_a.cert_data.clone()], &[])
        .expect("v4 recipient should decrypt");
    assert_eq!(result_a.plaintext, plaintext);

    // v6 recipient decrypts
    let result_b = decrypt::decrypt_detailed(&ciphertext, &[recipient_b.cert_data.clone()], &[])
        .expect("v6 recipient should decrypt");
    assert_eq!(result_b.plaintext, plaintext);
}

/// Modern High with encrypt-to-self encrypts to v4 recipient.
/// Pass: SEIPDv1 (mixed rule). Both sender and recipient decrypt.
#[test]
fn test_modern_high_encrypt_to_self_with_v4_recipient() {
    let sender_b =
        keys::generate_key_with_suite("Alice (B)".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Sender key gen should succeed");

    let recipient_a =
        keys::generate_key_with_suite("Bob (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
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
    let result_a = decrypt::decrypt_detailed(&ciphertext, &[recipient_a.cert_data.clone()], &[])
        .expect("v4 recipient should decrypt");
    assert_eq!(result_a.plaintext, plaintext);

    // v6 sender decrypts (encrypt-to-self)
    let result_b = decrypt::decrypt_detailed(&ciphertext, &[sender_b.cert_data.clone()], &[])
        .expect("v6 sender should decrypt own message");
    assert_eq!(result_b.plaintext, plaintext);
}

/// Legacy signature verified by Modern High user, and vice versa.
#[test]
fn test_cross_profile_signature_verification() {
    let key_a =
        keys::generate_key_with_suite("Alice (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Legacy key gen should succeed");

    let key_b =
        keys::generate_key_with_suite("Bob (B)".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Modern High key gen should succeed");

    let text = b"Cross-profile signature test.";

    // Legacy signs, Modern High verifies
    let signed_a =
        sign::sign_cleartext(text, &key_a.cert_data).expect("Legacy signing should succeed");
    let verify_a_by_b =
        verify::verify_cleartext_detailed(&signed_a, &[key_a.public_key_data.clone()])
            .expect("Modern High should verify Legacy signature");
    assert_eq!(
        verify_a_by_b.summary_state,
        SignatureVerificationState::Verified
    );

    // Modern High signs, Legacy verifies
    let signed_b =
        sign::sign_cleartext(text, &key_b.cert_data).expect("Modern High signing should succeed");
    let verify_b_by_a =
        verify::verify_cleartext_detailed(&signed_b, &[key_b.public_key_data.clone()])
            .expect("Legacy should verify Modern High signature");
    assert_eq!(
        verify_b_by_a.summary_state,
        SignatureVerificationState::Verified
    );
}

/// Extended: Legacy sender signs encrypted message for Modern High recipient.
/// Full round-trip: sign + encrypt + decrypt + verify.
#[test]
fn test_cross_profile_signed_encrypted_round_trip() {
    let sender_a =
        keys::generate_key_with_suite("Alice (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Sender key gen should succeed");

    let recipient_b =
        keys::generate_key_with_suite("Bob (B)".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Recipient key gen should succeed");

    let plaintext = b"Full round-trip: A->B signed+encrypted.";

    // Encrypt and sign
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_b.public_key_data.clone()],
        Some(&sender_a.cert_data),
        Some(&sender_a.public_key_data), // encrypt-to-self
    )
    .expect("Encryption should succeed");

    // Decrypt and verify
    let result = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient_b.cert_data.clone()],
        &[sender_a.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    let summary_entry = &result.signatures[result
        .summary_entry_index
        .expect("summary should reference an entry")
        as usize];
    assert_eq!(
        summary_entry.signer_primary_fingerprint,
        Some(sender_a.fingerprint.clone())
    );
}

/// Extended: Modern High sender signs encrypted message for Legacy recipient.
/// Full round-trip: sign + encrypt + decrypt + verify.
/// Complements test_cross_profile_signed_encrypted_round_trip (which tests A→B).
#[test]
fn test_cross_modern_high_to_a_signed_encrypted_round_trip() {
    let sender_b =
        keys::generate_key_with_suite("Alice (B)".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Sender key gen should succeed");

    let recipient_a =
        keys::generate_key_with_suite("Bob (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Recipient key gen should succeed");

    let plaintext = b"Full round-trip: B->A signed+encrypted.";

    // Encrypt and sign (B sender → A recipient)
    // Per PRD: v4 recipient → SEIPDv1 format auto-selected
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_a.public_key_data.clone()],
        Some(&sender_b.cert_data),
        Some(&sender_b.public_key_data), // encrypt-to-self
    )
    .expect("Encryption should succeed");

    // Recipient A decrypts and verifies sender B's signature
    let result = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient_a.cert_data.clone()],
        &[sender_b.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    let summary_entry = &result.signatures[result
        .summary_entry_index
        .expect("summary should reference an entry")
        as usize];
    assert_eq!(
        summary_entry.signer_primary_fingerprint,
        Some(sender_b.fingerprint.clone())
    );

    // Sender B can also decrypt (encrypt-to-self)
    let result_self = decrypt::decrypt_detailed(
        &ciphertext,
        &[sender_b.cert_data.clone()],
        &[sender_b.public_key_data.clone()],
    )
    .expect("Sender should decrypt via encrypt-to-self");

    assert_eq!(result_self.plaintext, plaintext);
    assert_eq!(
        result_self.summary_state,
        SignatureVerificationState::Verified
    );
}

/// Verify that encrypting to v4 recipient produces SEIPDv1.
/// This directly validates the PRD Section 3.3 / TDD Section 1.4 format auto-selection rule.
#[test]
fn test_format_selection_v4_recipient_produces_seipd_v1() {
    let recipient_a =
        keys::generate_key_with_suite("Bob (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
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
    let recipient_b =
        keys::generate_key_with_suite("Bob (B)".to_string(), None, None, KeySuite::Ed448X448)
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
    let recipient_a =
        keys::generate_key_with_suite("Bob (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Key gen should succeed");

    let recipient_b = keys::generate_key_with_suite(
        "Charlie (B)".to_string(),
        None,
        None,
        KeySuite::Ed448X448,
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

// ── Format verification for cross-profile encrypt (sender ≠ recipient profile) ──

/// Legacy sender encrypts to Modern High recipient → must produce SEIPDv2.
/// Validates that format selection depends on RECIPIENT key version, not sender's profile.
#[test]
fn test_format_selection_a_sender_to_b_recipient_produces_seipd_v2() {
    let sender_a =
        keys::generate_key_with_suite("Sender A".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Key gen should succeed");

    let recipient_b = keys::generate_key_with_suite(
        "Recipient B".to_string(),
        None,
        None,
        KeySuite::Ed448X448,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Cross-profile format check A->B",
        &[recipient_b.public_key_data.clone()],
        Some(&sender_a.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    let (has_v1, has_v2) = detect_message_format(&ciphertext);
    assert!(!has_v1, "A sender to v6 recipient must NOT produce SEIPDv1");
    assert!(has_v2, "A sender to v6 recipient must produce SEIPDv2");
}

/// Modern High sender encrypts to Legacy recipient → must produce SEIPDv1.
/// Validates format downgrade for v4 recipients regardless of sender's profile.
#[test]
fn test_format_selection_b_sender_to_a_recipient_produces_seipd_v1() {
    let sender_b =
        keys::generate_key_with_suite("Sender B".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let recipient_a = keys::generate_key_with_suite(
        "Recipient A".to_string(),
        None,
        None,
        KeySuite::Ed25519LegacyCurve25519Legacy,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Cross-profile format check B->A",
        &[recipient_a.public_key_data.clone()],
        Some(&sender_b.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    let (has_v1, has_v2) = detect_message_format(&ciphertext);
    assert!(has_v1, "B sender to v4 recipient must produce SEIPDv1");
    assert!(!has_v2, "B sender to v4 recipient must NOT produce SEIPDv2");
}

// ── Legacy sender + encrypt-to-self + v6 recipient ────────────────

/// Legacy sender with encrypt-to-self encrypts to v6 recipient.
/// Mixed v4 (sender) + v6 (recipient) → must use SEIPDv1.
/// Inverse of test_modern_high_encrypt_to_self_with_v4_recipient.
#[test]
fn test_legacy_encrypt_to_self_with_v6_recipient() {
    let sender_a =
        keys::generate_key_with_suite("Alice (A)".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Sender key gen should succeed");

    let recipient_b =
        keys::generate_key_with_suite("Bob (B)".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Recipient key gen should succeed");

    let plaintext = b"A->B with encrypt-to-self (mixed -> SEIPDv1).";

    // Encrypt to v6 recipient with v4 encrypt-to-self → mixed → SEIPDv1
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient_b.public_key_data.clone()],
        None,
        Some(&sender_a.public_key_data),
    )
    .expect("Encryption should succeed");

    // v6 recipient decrypts
    let result_b = decrypt::decrypt_detailed(&ciphertext, &[recipient_b.cert_data.clone()], &[])
        .expect("v6 recipient should decrypt");
    assert_eq!(result_b.plaintext, plaintext);

    // v4 sender decrypts (encrypt-to-self)
    let result_a = decrypt::decrypt_detailed(&ciphertext, &[sender_a.cert_data.clone()], &[])
        .expect("v4 sender should decrypt own message");
    assert_eq!(result_a.plaintext, plaintext);

    // Verify format is SEIPDv1 (mixed v4+v6 → lowest common denominator)
    let ciphertext_binary = encrypt::encrypt_binary(
        plaintext,
        &[recipient_b.public_key_data.clone()],
        None,
        Some(&sender_a.public_key_data),
    )
    .expect("Binary encryption should succeed");

    let (has_v1, has_v2) = detect_message_format(&ciphertext_binary);
    assert!(has_v1, "Mixed v4+v6 (encrypt-to-self) must produce SEIPDv1");
    assert!(
        !has_v2,
        "Mixed v4+v6 (encrypt-to-self) must NOT produce SEIPDv2"
    );
}

/// Revocation cert from Legacy key should not verify against Modern High key (and vice versa).
#[test]
fn test_revocation_cert_cross_profile_mismatch() {
    let key_a =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Legacy key gen should succeed");

    let key_b =
        keys::generate_key_with_suite("Bob".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Modern High key gen should succeed");

    // Legacy revocation cert vs Modern High cert
    let result = keys::parse_revocation_cert(&key_a.revocation_cert, &key_b.cert_data);
    assert!(
        result.is_err(),
        "Legacy revocation cert should not verify against Modern High key"
    );

    // Modern High revocation cert vs Legacy cert
    let result = keys::parse_revocation_cert(&key_b.revocation_cert, &key_a.cert_data);
    assert!(
        result.is_err(),
        "Modern High revocation cert should not verify against Legacy key"
    );
}

// ── match_recipients cross-profile tests ────────────────────────────

/// match_recipients: cross-profile — Modern High sender encrypts to Legacy recipient.
/// Message format is SEIPDv1 (mixed/v4 recipient). match_recipients should still find the match.
#[test]
fn test_match_recipients_cross_modern_high_sender_a_recipient() {
    let sender_b =
        keys::generate_key_with_suite("Sender B".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let recipient_a = keys::generate_key_with_suite(
        "Recipient A".to_string(),
        None,
        None,
        KeySuite::Ed25519LegacyCurve25519Legacy,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"cross profile",
        &[recipient_a.public_key_data.clone()],
        Some(&sender_b.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    let matched = decrypt::match_recipients(&ciphertext, &[recipient_a.public_key_data.clone()])
        .expect("match_recipients should work cross-profile");

    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0], recipient_a.fingerprint);
}

/// match_recipients: cross-profile — Legacy sender encrypts to Modern High recipient.
/// Message format is SEIPDv2 (v6 recipient). match_recipients should find the match.
#[test]
fn test_match_recipients_cross_legacy_sender_b_recipient() {
    let sender_a =
        keys::generate_key_with_suite("Sender A".to_string(), None, None, KeySuite::Ed25519LegacyCurve25519Legacy)
            .expect("Key gen should succeed");

    let recipient_b = keys::generate_key_with_suite(
        "Recipient B".to_string(),
        None,
        None,
        KeySuite::Ed448X448,
    )
    .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"cross profile reverse",
        &[recipient_b.public_key_data.clone()],
        Some(&sender_a.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    let matched = decrypt::match_recipients(&ciphertext, &[recipient_b.public_key_data.clone()])
        .expect("match_recipients should work cross-profile");

    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0], recipient_b.fingerprint);
}

// ── Modify Expiry: Negative Tests ───────────────────────────────────────

/// modify_expiry with public key only (no secret material) must fail.
/// Tests both Legacy and Modern High.
#[test]
fn test_modify_expiry_public_key_only_fails_legacy() {
    let generated = keys::generate_key_with_suite(
        "Alice".to_string(),
        None,
        Some(365 * 24 * 3600),
        KeySuite::Ed25519LegacyCurve25519Legacy,
    )
    .expect("Key generation should succeed");

    // Pass public key only — should fail because secret key is needed for re-signing
    let result = keys::modify_expiry(&generated.public_key_data, Some(3 * 365 * 24 * 3600));
    assert!(
        result.is_err(),
        "modify_expiry should fail with public key only"
    );
    // Match on the error variant only — the exact reason string is an implementation
    // detail of Sequoia and may change across versions. The InvalidKeyData variant match
    // is sufficient to confirm the correct error category.
    match result.unwrap_err() {
        pgp_mobile::error::PgpError::InvalidKeyData { .. } => {} // expected
        other => panic!("Expected InvalidKeyData error, got: {other:?}"),
    }
}

#[test]
fn test_modify_expiry_public_key_only_fails_modern_high() {
    let generated = keys::generate_key_with_suite(
        "Alice".to_string(),
        None,
        Some(365 * 24 * 3600),
        KeySuite::Ed448X448,
    )
    .expect("Key generation should succeed");

    // Pass public key only — should fail because secret key is needed for re-signing
    let result = keys::modify_expiry(&generated.public_key_data, Some(3 * 365 * 24 * 3600));
    assert!(
        result.is_err(),
        "modify_expiry should fail with public key only"
    );
    // Match on the error variant only — see comment in Legacy test above.
    match result.unwrap_err() {
        pgp_mobile::error::PgpError::InvalidKeyData { .. } => {} // expected
        other => panic!("Expected InvalidKeyData error, got: {other:?}"),
    }
}

/// Re-homed from the retired FFI `get_key_version` oracle: the certificate a
/// suite produces must carry that suite's key version on the wire, as seen by
/// an independent parse of the public bytes (not just the generation result).
#[test]
fn test_generated_public_certificates_carry_suite_key_version() {
    let expectations = [
        (KeySuite::Ed25519LegacyCurve25519Legacy, 4),
        (KeySuite::Ed25519X25519, 6),
        (KeySuite::Ed448X448, 6),
    ];
    for (suite, expected_version) in expectations {
        let generated =
            keys::generate_key_with_suite("Version Probe".to_string(), None, None, suite)
                .expect("key generation should succeed");
        assert_eq!(generated.key_version, expected_version, "{suite:?}");
        assert_eq!(
            keys::get_key_version(&generated.public_key_data).expect("version should parse"),
            expected_version,
            "{suite:?} public certificate version"
        );
        assert_eq!(
            keys::detect_suite(&generated.public_key_data).expect("suite should classify"),
            suite,
            "{suite:?} round-trip classification"
        );
    }
}
