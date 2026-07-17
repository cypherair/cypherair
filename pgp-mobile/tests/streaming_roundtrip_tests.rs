//! Streaming round-trip tests.
//! Covers successful file encrypt/decrypt, detached signature verification,
//! recipient matching, and cross-suite streaming behavior.

mod common;

use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeySuite};
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::streaming;
use std::fs;

/// Helper to generate a key pair for testing.
fn gen_key(name: &str, suite: KeySuite) -> keys::GeneratedKey {
    keys::generate_key_with_suite(name.to_string(), None, None, suite)
        .expect("Key generation should succeed")
}

// ── Encrypt/Decrypt Round-Trip Tests ───────────────────────────────────

#[test]
fn test_encrypt_decrypt_file_legacy_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeySuite::Ed25519LegacyCurve25519Legacy);

    // Write test data to input file
    let plaintext = b"Hello from Legacy streaming test!";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    // Encrypt
    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        None,
    )
    .expect("Encrypt should succeed");

    assert!(encrypted_path.exists(), "Encrypted file should exist");
    assert!(
        fs::metadata(&encrypted_path).unwrap().len() > 0,
        "Encrypted file should not be empty"
    );

    // Decrypt
    let result = streaming::decrypt_file_detailed(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    assert!(decrypted_path.exists(), "Decrypted file should exist");
    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(
        decrypted, plaintext,
        "Decrypted content must match original"
    );

    // No signing key was used, so signature should be NotSigned
    assert_eq!(
        result.summary_state,
        SignatureVerificationState::NotSigned,
        "Unsigned message should report NotSigned"
    );
}

#[test]
fn test_encrypt_decrypt_file_modern_high_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Bob", KeySuite::Ed448X448);

    let plaintext = b"Hello from Modern High streaming test with AEAD!";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let result = streaming::decrypt_file_detailed(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::NotSigned);
}

// ── Signed Encrypt/Decrypt Tests ───────────────────────────────────────

#[test]
fn test_encrypt_decrypt_file_with_signature_legacy() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeySuite::Ed25519LegacyCurve25519Legacy);

    let plaintext = b"Signed Legacy streaming message";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    // Encrypt with signing
    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        Some(&key.cert_data),
        None,
        None,
    )
    .expect("Signed encrypt should succeed");

    // Decrypt with verification
    let result = streaming::decrypt_file_detailed(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(
        result.summary_state,
        SignatureVerificationState::Verified,
        "Signature should be valid"
    );
    let summary_entry = &result.signatures[result
        .summary_entry_index
        .expect("summary should reference an entry")
        as usize];
    assert_eq!(
        summary_entry.signer_primary_fingerprint,
        Some(key.fingerprint.clone()),
        "Signer fingerprint should match"
    );
}

#[test]
fn test_encrypt_decrypt_file_with_signature_modern_high() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Bob", KeySuite::Ed448X448);

    let plaintext = b"Signed Modern High streaming message with AEAD";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        Some(&key.cert_data),
        None,
        None,
    )
    .expect("Signed encrypt should succeed");

    let result = streaming::decrypt_file_detailed(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    let summary_entry = &result.signatures[result
        .summary_entry_index
        .expect("summary should reference an entry")
        as usize];
    assert_eq!(
        summary_entry.signer_primary_fingerprint,
        Some(key.fingerprint.clone())
    );
}

// ── Sign/Verify Detached File Tests ────────────────────────────────────

#[test]
fn test_sign_verify_detached_file_legacy() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeySuite::Ed25519LegacyCurve25519Legacy);

    let data = b"File content to sign with Legacy";
    let data_path = dir.path().join("document.txt");
    fs::write(&data_path, data).unwrap();

    // Sign
    let signature =
        streaming::sign_detached_file(data_path.to_str().unwrap(), &key.cert_data, None)
            .expect("Signing should succeed");

    assert!(!signature.is_empty(), "Signature should not be empty");

    // Verify
    let result = streaming::verify_detached_file_detailed(
        data_path.to_str().unwrap(),
        &signature,
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Verification should succeed");

    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    let summary_entry = &result.signatures[result
        .summary_entry_index
        .expect("summary should reference an entry")
        as usize];
    assert_eq!(
        summary_entry.signer_primary_fingerprint,
        Some(key.fingerprint.clone())
    );
}

#[test]
fn test_sign_verify_detached_file_modern_high() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Bob", KeySuite::Ed448X448);

    let data = b"File content to sign with Modern High";
    let data_path = dir.path().join("document.txt");
    fs::write(&data_path, data).unwrap();

    let signature =
        streaming::sign_detached_file(data_path.to_str().unwrap(), &key.cert_data, None)
            .expect("Signing should succeed");

    let result = streaming::verify_detached_file_detailed(
        data_path.to_str().unwrap(),
        &signature,
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Verification should succeed");

    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    let summary_entry = &result.signatures[result
        .summary_entry_index
        .expect("summary should reference an entry")
        as usize];
    assert_eq!(
        summary_entry.signer_primary_fingerprint,
        Some(key.fingerprint.clone())
    );
}

// ── Match Recipients From File Test ────────────────────────────────────

#[test]
fn test_match_recipients_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let alice = gen_key("Alice", KeySuite::Ed25519LegacyCurve25519Legacy);
    let bob = gen_key("Bob", KeySuite::Ed448X448);

    let plaintext = b"Recipient matching test";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    fs::write(&input_path, plaintext).unwrap();

    // Encrypt to Alice only
    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[alice.public_key_data.clone()],
        None,
        None,
        None,
    )
    .unwrap();

    // Match against both Alice and Bob
    let matched = streaming::match_recipients_from_file(
        encrypted_path.to_str().unwrap(),
        &[alice.public_key_data.clone(), bob.public_key_data.clone()],
    )
    .expect("Matching should succeed");

    assert_eq!(matched.len(), 1, "Only Alice should match");
    assert_eq!(matched[0], alice.fingerprint);

    // Match against Bob only — should fail
    let result = streaming::match_recipients_from_file(
        encrypted_path.to_str().unwrap(),
        &[bob.public_key_data.clone()],
    );
    assert!(
        matches!(result, Err(PgpError::NoMatchingKey)),
        "Bob's key should not match"
    );
}

// ── Cross-Profile Test ─────────────────────────────────────────────────

#[test]
fn test_encrypt_file_cross_suite() {
    let dir = tempfile::tempdir().unwrap();
    let sender_b = gen_key("Bob", KeySuite::Ed448X448);
    let recipient_a = gen_key("Alice", KeySuite::Ed25519LegacyCurve25519Legacy);

    let plaintext = b"Cross-suite streaming: B sender to A recipient";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    // Encrypt from Modern High sender to Legacy recipient (should use SEIPDv1)
    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[recipient_a.public_key_data.clone()],
        Some(&sender_b.cert_data),
        None,
        None,
    )
    .expect("Cross-suite encrypt should succeed");

    // Verify the ciphertext uses SEIPDv1 (because recipient is v4)
    let ciphertext = fs::read(&encrypted_path).unwrap();
    let (has_v1, has_v2) = common::detect_message_format(&ciphertext);
    assert!(has_v1, "Cross-suite message should use SEIPDv1");
    assert!(!has_v2, "Cross-suite message should NOT use SEIPDv2");

    // Decrypt with Legacy recipient key
    let result = streaming::decrypt_file_detailed(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[recipient_a.cert_data.clone()],
        &[sender_b.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}
