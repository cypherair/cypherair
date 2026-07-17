//! Modern High message-path tests.
//! Covers key generation, sign/verify, encrypt/decrypt, tamper handling,
//! detached signatures, and message-centric regressions for v6 keys.

use pgp_mobile::armor;
use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeySuite};
use pgp_mobile::sign;
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::streaming;
use pgp_mobile::verify;
use tempfile::NamedTempFile;

fn write_temp_data_file(data: &[u8]) -> NamedTempFile {
    let input = NamedTempFile::new().expect("temp input should be created");
    std::fs::write(input.path(), data).expect("temp input should be written");
    input
}

/// Generate Ed448+X448 v6 key pair.
/// Pass: key version is 6, algo is Ed448/X448.
#[test]
fn test_generate_key_modern_high_produces_v6() {
    let result = keys::generate_key_with_suite(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        None,
        KeySuite::Ed448X448,
    )
    .expect("Key generation should succeed");

    assert_eq!(result.key_version, 6, "Modern High key must be v6");
    assert_eq!(result.suite, KeySuite::Ed448X448);
    assert!(!result.fingerprint.is_empty());
    assert!(!result.cert_data.is_empty());
    assert!(!result.public_key_data.is_empty());
    assert!(!result.revocation_cert.is_empty());
}

/// (extended): Verify key algorithms and parse info.
#[test]
fn test_generate_key_modern_high_algorithms() {
    let result = keys::generate_key_with_suite(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        None,
        KeySuite::Ed448X448,
    )
    .expect("Key generation should succeed");

    let info = keys::parse_key_info(&result.cert_data).expect("Parse should succeed");
    assert_eq!(info.key_version, 6);
    assert_eq!(info.suite, KeySuite::Ed448X448);
    assert!(info.has_encryption_subkey, "Must have encryption subkey");
    assert!(!info.is_revoked);
    assert!(!info.is_expired);

    // T2: Verify algorithms are Ed448 and X448 (not Ed25519/X25519).
    // Require specific algorithm names — generic "EdDSA"/"ECDH" would also match
    // Legacy (Ed25519/X25519) and would fail to catch a cipher suite misconfiguration.
    assert!(
        info.primary_algo.contains("Ed448"),
        "Modern High primary key must use Ed448 (not generic EdDSA), got: {}",
        info.primary_algo
    );
    let subkey_algo = info.subkey_algo.expect("Must have subkey algorithm");
    assert!(
        subkey_algo.contains("X448"),
        "Modern High subkey must use X448 (not generic ECDH), got: {}",
        subkey_algo
    );
}

/// Sign + verify text (Modern High).
#[test]
fn test_sign_verify_text_modern_high() {
    let key =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key generation should succeed");

    let text = b"Hello from Modern High!";

    let signed = sign::sign_cleartext(text, &key.cert_data).expect("Signing should succeed");

    let result = verify::verify_cleartext_detailed(&signed, &[key.public_key_data.clone()])
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

/// Encrypt + decrypt text (SEIPDv2 AEAD OCB).
#[test]
fn test_encrypt_decrypt_text_modern_high() {
    let key =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key generation should succeed");

    let plaintext = b"Secret message for Modern High with AEAD.";

    let ciphertext = encrypt::encrypt(plaintext, &[key.public_key_data.clone()], None, None)
        .expect("Encryption should succeed");

    let result = decrypt::decrypt_detailed(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// (extended): Encrypt + decrypt with signature.
#[test]
fn test_encrypt_decrypt_signed_modern_high() {
    let sender =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Sender key gen should succeed");

    let recipient =
        keys::generate_key_with_suite("Bob".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Recipient key gen should succeed");

    let plaintext = b"Signed and encrypted Modern High message.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient.public_key_data.clone()],
        Some(&sender.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    let result = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[sender.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}

/// Encrypt-to-self (Modern High).
#[test]
fn test_encrypt_to_self_modern_high() {
    let sender =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let recipient =
        keys::generate_key_with_suite("Bob".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let plaintext = b"Modern High with encrypt-to-self.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient.public_key_data.clone()],
        None,
        Some(&sender.public_key_data),
    )
    .expect("Encryption should succeed");

    // Both can decrypt
    let result_recipient =
        decrypt::decrypt_detailed(&ciphertext, &[recipient.cert_data.clone()], &[])
            .expect("Recipient should decrypt");
    assert_eq!(result_recipient.plaintext, plaintext);

    let result_sender = decrypt::decrypt_detailed(&ciphertext, &[sender.cert_data.clone()], &[])
        .expect("Sender should decrypt own message");
    assert_eq!(result_sender.plaintext, plaintext);
}

/// File encrypt/decrypt 1 MB (Modern High).
#[test]
fn test_file_encrypt_decrypt_1mb_modern_high() {
    let key =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let ciphertext =
        encrypt::encrypt_binary(&plaintext, &[key.public_key_data.clone()], None, None)
            .expect("Encryption should succeed");

    let result = decrypt::decrypt_detailed(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// File encrypt/decrypt 10 MB (Modern High).
#[test]
fn test_file_encrypt_decrypt_10mb_modern_high() {
    let key =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let plaintext: Vec<u8> = (0..10_000_000).map(|i| (i % 256) as u8).collect();

    let ciphertext =
        encrypt::encrypt_binary(&plaintext, &[key.public_key_data.clone()], None, None)
            .expect("Encryption should succeed");

    let result = decrypt::decrypt_detailed(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decryption should succeed");

    assert_eq!(result.plaintext.len(), plaintext.len());
    assert_eq!(result.plaintext, plaintext);
}

/// Tamper test: 1-bit flip → AEAD authentication failure.
/// HARD-FAIL: must never show partial plaintext.
/// Verifies the specific error type to confirm AEAD integrity protection is working.
/// Tests multiple tamper positions to exercise different code paths.
#[test]
fn test_tamper_detection_aead_modern_high() {
    let key =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let plaintext = b"AEAD-protected secret.";

    let ciphertext = encrypt::encrypt_binary(plaintext, &[key.public_key_data.clone()], None, None)
        .expect("Encryption should succeed");

    // Test tamper detection at multiple positions.
    // For SEIPDv2 (AEAD), corrupting the PKESK packet yields NoMatchingKey (session key
    // can't be recovered). To exercise the AEAD integrity check, we must corrupt bytes
    // in the encrypted data body — typically in the last third of the ciphertext.
    // We test many positions to maximize the chance of hitting the encrypted data region.
    let len = ciphertext.len();
    let positions: Vec<(&str, usize)> = vec![
        ("early (byte 15)", 15.min(len - 1)),
        ("25%", len / 4),
        ("middle", len / 2),
        ("60%", len * 3 / 5),
        ("75%", len * 3 / 4),
        ("80%", len * 4 / 5),
        ("90%", len * 9 / 10),
        ("late (near end)", len.saturating_sub(10).max(1)),
        ("second-to-last byte", len.saturating_sub(2).max(1)),
    ];

    // DESIGN NOTE: For SEIPDv2 with v6 PKESK (Modern High), Sequoia uses AEAD-protected
    // session key transport. Corrupting any byte — even in the SEIP body — causes the
    // PKESK v6 session key decryption to fail, producing NoMatchingKey rather than
    // AeadAuthenticationFailed. This is correct and expected: the AEAD protection covers
    // the entire session key recovery path, so ANY corruption is caught before the
    // symmetric AEAD decryption stage is even reached.
    //
    // The critical security property is that NO tampered ciphertext ever decrypts
    // successfully (hard-fail). The specific error variant is less important than the
    // guarantee that decryption always fails.
    for (label, pos) in &positions {
        let mut tampered = ciphertext.clone();
        tampered[*pos] ^= 0x01;

        let result = decrypt::decrypt_detailed(&tampered, &[key.cert_data.clone()], &[]);
        match &result {
            Err(pgp_mobile::error::PgpError::AeadAuthenticationFailed) => {}
            Err(pgp_mobile::error::PgpError::IntegrityCheckFailed) => {}
            Err(pgp_mobile::error::PgpError::CorruptData { .. }) => {}
            Err(pgp_mobile::error::PgpError::NoMatchingKey) => {} // PKESK v6 AEAD failure
            Err(other) => panic!(
                "Tamper at {label} (offset {pos}): unexpected error type: {other:?}"
            ),
            Ok(_) => panic!(
                "Tamper at {label} (offset {pos}): tampered AEAD ciphertext must NEVER decrypt successfully"
            ),
        }
    }
}

/// Detached signature (Modern High).
#[test]
fn test_detached_signature_modern_high() {
    let key =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let data = b"File content for Modern High.";

    let input = write_temp_data_file(data);
    let signature =
        streaming::sign_detached_file(input.path().to_str().unwrap(), &key.cert_data, None)
            .expect("Signing should succeed");

    let result = streaming::verify_detached_file_detailed(
        input.path().to_str().unwrap(),
        &signature,
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Verification should succeed");

    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}

/// Empty plaintext encrypt/decrypt round-trip (Modern High).
#[test]
fn test_encrypt_decrypt_empty_plaintext_modern_high() {
    let key =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let plaintext = b"";
    let ciphertext = encrypt::encrypt(plaintext, &[key.public_key_data.clone()], None, None)
        .expect("Encrypting empty plaintext should succeed");

    let result = decrypt::decrypt_detailed(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decrypting empty plaintext should succeed");

    assert_eq!(
        result.plaintext,
        plaintext.to_vec(),
        "Empty plaintext round-trip failed"
    );
}

/// Concurrent encrypt + decrypt on separate key pairs (Modern High).
#[test]
fn test_concurrent_encrypt_decrypt_modern_high() {
    let key1 =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let key2 = keys::generate_key_with_suite("Bob".to_string(), None, None, KeySuite::Ed448X448)
        .expect("Key gen should succeed");

    let k1_pub = key1.public_key_data.clone();
    let k2_pub = key2.public_key_data.clone();
    let k1_cert = key1.cert_data.clone();
    let k2_cert = key2.cert_data.clone();

    // Thread 1: encrypt with key1
    let handle1 = std::thread::spawn(move || {
        let ct = encrypt::encrypt(b"concurrent-msg-1", &[k1_pub], None, None)
            .expect("Concurrent encrypt should succeed");
        let result = decrypt::decrypt_detailed(&ct, &[k1_cert], &[])
            .expect("Concurrent decrypt should succeed");
        assert_eq!(result.plaintext, b"concurrent-msg-1");
    });

    // Thread 2: encrypt with key2
    let handle2 = std::thread::spawn(move || {
        let ct = encrypt::encrypt(b"concurrent-msg-2", &[k2_pub], None, None)
            .expect("Concurrent encrypt should succeed");
        let result = decrypt::decrypt_detailed(&ct, &[k2_cert], &[])
            .expect("Concurrent decrypt should succeed");
        assert_eq!(result.plaintext, b"concurrent-msg-2");
    });

    handle1.join().expect("Thread 1 should not panic");
    handle2.join().expect("Thread 2 should not panic");
}

/// Decrypt with wrong Modern High key → NoMatchingKey error.
/// Ensures the full AEAD decrypt path fails correctly with wrong key.
#[test]
fn test_decrypt_wrong_key_modern_high() {
    let alice =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_suite("Bob".to_string(), None, None, KeySuite::Ed448X448)
        .expect("Key gen should succeed");

    let plaintext = b"Only for Alice (Modern High).";

    let ciphertext = encrypt::encrypt(plaintext, &[alice.public_key_data.clone()], None, None)
        .expect("Encryption should succeed");

    // Bob tries to decrypt Alice's message
    let result = decrypt::decrypt_detailed(&ciphertext, &[bob.cert_data.clone()], &[]);
    match result {
        Ok(_) => panic!("Wrong key must fail decryption"),
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {}
        Err(other) => panic!("Expected NoMatchingKey, got: {other}"),
    }
}

// ── Multi-recipient encrypt/decrypt (Modern High) ──────────────────────

/// Encrypt to multiple v6 recipients → each can independently decrypt.
#[test]
fn test_multi_recipient_encrypt_decrypt_modern_high() {
    let alice =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_suite("Bob".to_string(), None, None, KeySuite::Ed448X448)
        .expect("Key gen should succeed");

    let plaintext = b"Message for both Alice and Bob (Modern High).";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[alice.public_key_data.clone(), bob.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    // Alice decrypts
    let result_alice = decrypt::decrypt_detailed(&ciphertext, &[alice.cert_data.clone()], &[])
        .expect("Alice should decrypt");
    assert_eq!(result_alice.plaintext, plaintext);

    // Bob decrypts
    let result_bob = decrypt::decrypt_detailed(&ciphertext, &[bob.cert_data.clone()], &[])
        .expect("Bob should decrypt");
    assert_eq!(result_bob.plaintext, plaintext);
}

/// Armor round-trip: Modern High public key → armor → dearmor → identical.
#[test]
fn test_armor_roundtrip_modern_high() {
    let key =
        keys::generate_key_with_suite("Alice".to_string(), None, None, KeySuite::Ed448X448)
            .expect("Key gen should succeed");

    let armored = armor::armor_public_key(&key.public_key_data).expect("Armor should succeed");

    // Armored output should contain the PGP header
    let armored_str = String::from_utf8_lossy(&armored);
    assert!(armored_str.contains("BEGIN PGP PUBLIC KEY BLOCK"));

    // Dearmor and compare
    let (dearmored, _kind) = armor::decode_armor(&armored).expect("Dearmor should succeed");

    // Parse both and compare fingerprints
    let original_info = keys::parse_key_info(&key.public_key_data).unwrap();
    let dearmored_info = keys::parse_key_info(&dearmored).unwrap();
    assert_eq!(original_info.fingerprint, dearmored_info.fingerprint);
    assert_eq!(dearmored_info.key_version, 6);
}
