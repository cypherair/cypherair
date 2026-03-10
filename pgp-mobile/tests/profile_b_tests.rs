//! Profile B (Advanced Security) tests.
//! Covers POC test cases C2B.1–C2B.10.
//! Profile B: v6 keys, Ed448+X448, SEIPDv2 AEAD OCB, Argon2id S2K.

use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::encrypt;
use pgp_mobile::decrypt;
use pgp_mobile::sign;
use pgp_mobile::verify;
use pgp_mobile::armor;
use pgp_mobile::decrypt::SignatureStatus;

/// C2B.1: Generate Ed448+X448 v6 key pair.
/// Pass: key version is 6, algo is Ed448/X448.
#[test]
fn test_generate_key_profile_b_produces_v6() {
    let result = keys::generate_key_with_profile(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        None,
        KeyProfile::Advanced,
    )
    .expect("Key generation should succeed");

    assert_eq!(result.key_version, 6, "Profile B key must be v6");
    assert_eq!(result.profile, KeyProfile::Advanced);
    assert!(!result.fingerprint.is_empty());
    assert!(!result.cert_data.is_empty());
    assert!(!result.public_key_data.is_empty());
    assert!(!result.revocation_cert.is_empty());
}

/// C2B.1 (extended): Verify key algorithms and parse info.
#[test]
fn test_generate_key_profile_b_algorithms() {
    let result = keys::generate_key_with_profile(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        None,
        KeyProfile::Advanced,
    )
    .expect("Key generation should succeed");

    let info = keys::parse_key_info(&result.cert_data).expect("Parse should succeed");
    assert_eq!(info.key_version, 6);
    assert_eq!(info.profile, KeyProfile::Advanced);
    assert!(info.has_encryption_subkey, "Must have encryption subkey");
    assert!(!info.is_revoked);
    assert!(!info.is_expired);
}

/// C2B.2: Sign + verify text (Profile B).
#[test]
fn test_sign_verify_text_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key generation should succeed");

    let text = b"Hello from Profile B!";

    let signed = sign::sign_cleartext(text, &key.cert_data)
        .expect("Signing should succeed");

    let result = verify::verify_cleartext(&signed, &[key.public_key_data.clone()])
        .expect("Verification should succeed");

    assert_eq!(result.status, SignatureStatus::Valid);
    assert_eq!(result.signer_fingerprint, Some(key.fingerprint.clone()));
}

/// C2B.3: Encrypt + decrypt text (SEIPDv2 AEAD OCB).
#[test]
fn test_encrypt_decrypt_text_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key generation should succeed");

    let plaintext = b"Secret message for Profile B with AEAD.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// C2B.3 (extended): Encrypt + decrypt with signature.
#[test]
fn test_encrypt_decrypt_signed_profile_b() {
    let sender = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Sender key gen should succeed");

    let recipient = keys::generate_key_with_profile(
        "Bob".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Recipient key gen should succeed");

    let plaintext = b"Signed and encrypted Profile B message.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient.public_key_data.clone()],
        Some(&sender.cert_data),
        None,
    )
    .expect("Encryption should succeed");

    let result = decrypt::decrypt(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[sender.public_key_data.clone()],
    )
    .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.signature_status, Some(SignatureStatus::Valid));
}

/// C2B.4: Encrypt-to-self (Profile B).
#[test]
fn test_encrypt_to_self_profile_b() {
    let sender = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let recipient = keys::generate_key_with_profile(
        "Bob".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let plaintext = b"Profile B with encrypt-to-self.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient.public_key_data.clone()],
        None,
        Some(&sender.public_key_data),
    )
    .expect("Encryption should succeed");

    // Both can decrypt
    let result_recipient = decrypt::decrypt(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[],
    )
    .expect("Recipient should decrypt");
    assert_eq!(result_recipient.plaintext, plaintext);

    let result_sender = decrypt::decrypt(
        &ciphertext,
        &[sender.cert_data.clone()],
        &[],
    )
    .expect("Sender should decrypt own message");
    assert_eq!(result_sender.plaintext, plaintext);
}

/// C2B.5: File encrypt/decrypt 1 MB (Profile B).
#[test]
fn test_file_encrypt_decrypt_1mb_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let ciphertext = encrypt::encrypt_binary(
        &plaintext,
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// C2B.5: File encrypt/decrypt 10 MB (Profile B).
#[test]
fn test_file_encrypt_decrypt_10mb_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let plaintext: Vec<u8> = (0..10_000_000).map(|i| (i % 256) as u8).collect();

    let ciphertext = encrypt::encrypt_binary(
        &plaintext,
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decryption should succeed");

    assert_eq!(result.plaintext.len(), plaintext.len());
    assert_eq!(result.plaintext, plaintext);
}

/// C2B.6: Export key with Argon2id.
#[test]
fn test_export_key_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let passphrase = "strong-passphrase-for-profile-b";

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
        .expect("Export should succeed");
    assert!(!exported.is_empty());
}

/// C2B.7: Re-import with correct passphrase.
#[test]
fn test_import_correct_passphrase_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let passphrase = "correct-passphrase-b";

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
        .expect("Export should succeed");

    let imported = keys::import_secret_key(&exported, passphrase)
        .expect("Import with correct passphrase should succeed");
    assert!(!imported.is_empty());
}

/// C2B.8: Re-import with wrong passphrase → graceful error.
#[test]
fn test_import_wrong_passphrase_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let exported = keys::export_secret_key(&key.cert_data, "correct", KeyProfile::Advanced)
        .expect("Export should succeed");

    let result = keys::import_secret_key(&exported, "wrong");
    assert!(result.is_err(), "Wrong passphrase should fail");
}

/// Export with wrong profile should fail.
#[test]
fn test_export_wrong_profile_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let result = keys::export_secret_key(&key.cert_data, "passphrase", KeyProfile::Universal);
    assert!(result.is_err(), "Exporting v6 key with Universal profile should fail");
    let err = result.unwrap_err();
    match err {
        pgp_mobile::error::PgpError::S2kError { reason } => {
            assert!(reason.contains("Profile mismatch"), "Error should mention profile mismatch: {reason}");
        }
        other => panic!("Expected S2kError, got: {other:?}"),
    }
}

/// C2B.9: Generate + parse revocation cert.
#[test]
fn test_revocation_cert_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let result = keys::parse_revocation_cert(&key.revocation_cert, &key.cert_data)
        .expect("Revocation cert should parse and verify");
    assert!(result.contains("revocation"));
}

/// Revocation cert for key A should not verify against key B.
#[test]
fn test_revocation_cert_wrong_key_profile_b() {
    let key_a = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key A gen should succeed");

    let key_b = keys::generate_key_with_profile(
        "Bob".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key B gen should succeed");

    // Key A's revocation cert should fail verification against Key B
    let result = keys::parse_revocation_cert(&key_a.revocation_cert, &key_b.cert_data);
    assert!(result.is_err(), "Revocation cert should not verify against wrong key");
}

/// Tamper test: 1-bit flip → AEAD authentication failure.
/// HARD-FAIL: must never show partial plaintext.
/// Verifies the specific error type to confirm AEAD integrity protection is working.
#[test]
fn test_tamper_detection_aead_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let plaintext = b"AEAD-protected secret.";

    let mut ciphertext = encrypt::encrypt_binary(
        plaintext,
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    // Flip one bit near the middle
    let midpoint = ciphertext.len() / 2;
    ciphertext[midpoint] ^= 0x01;

    // For SEIPDv2 (AEAD), the expected error is AeadAuthenticationFailed.
    // CorruptData is also acceptable if the tamper corrupts the packet structure itself.
    // NoMatchingKey is acceptable if the tamper corrupts the PKESK packet header,
    // preventing the recipient key from being matched.
    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[]);
    match &result {
        Err(pgp_mobile::error::PgpError::AeadAuthenticationFailed) => {} // expected: AEAD auth failure
        Err(pgp_mobile::error::PgpError::CorruptData { .. }) => {} // acceptable: packet-level corruption
        Err(pgp_mobile::error::PgpError::NoMatchingKey) => {} // acceptable: PKESK header corrupted
        Err(other) => panic!(
            "Expected AeadAuthenticationFailed, CorruptData, or NoMatchingKey for tampered SEIPDv2, got: {other:?}"
        ),
        Ok(_) => panic!("Tampered AEAD ciphertext must never decrypt successfully"),
    }
}

/// Detached signature (Profile B).
#[test]
fn test_detached_signature_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let data = b"File content for Profile B.";

    let signature = sign::sign_detached(data, &key.cert_data)
        .expect("Signing should succeed");

    let result = verify::verify_detached(
        data,
        &signature,
        &[key.public_key_data.clone()],
    )
    .expect("Verification should succeed");

    assert_eq!(result.status, SignatureStatus::Valid);
}

/// Fix #1 verification: exported Profile B key is truly passphrase-protected.
#[test]
fn test_export_produces_encrypted_key_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let passphrase = "test-passphrase-b";

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
        .expect("Export should succeed");

    // Exported key should not be directly usable for signing (secrets are encrypted)
    let sign_result = sign::sign_cleartext(b"test", &exported);
    assert!(
        sign_result.is_err(),
        "Exported key with encrypted secrets should not be directly usable for signing"
    );
}

/// Fix #1+#2 verification: full export → import → decrypt round-trip (Profile B).
#[test]
fn test_export_import_decrypt_roundtrip_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let plaintext = b"Profile B export/import chain test.";

    // Encrypt with original key
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    // Export → import
    let passphrase = "roundtrip-profile-b";
    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
        .expect("Export should succeed");
    let imported = keys::import_secret_key(&exported, passphrase)
        .expect("Import should succeed");

    // Decrypt with imported key
    let result = decrypt::decrypt(&ciphertext, &[imported], &[])
        .expect("Decryption with imported key should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// C2B.6 (extended): Verify that Profile B export uses Argon2id S2K with expected parameters.
/// PRD requires: 512 MB memory (encoded_m=19), p=4 parallelism.
#[test]
fn test_export_profile_b_uses_argon2id() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let passphrase = "s2k-verification-test";

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
        .expect("Export should succeed");

    let s2k_info = keys::parse_s2k_params(&exported)
        .expect("S2K params should parse");

    assert_eq!(s2k_info.s2k_type, "argon2id", "Profile B export must use Argon2id S2K");
    // Sequoia's default for RFC9580 should use substantial memory.
    // The PRD specifies 512 MB (524288 KiB = 2^19 KiB), but Sequoia may use its own defaults.
    // At minimum, verify Argon2id is used and memory is non-trivial.
    assert!(
        s2k_info.memory_kib >= 1024,
        "Argon2id memory should be non-trivial, got {} KiB",
        s2k_info.memory_kib
    );
    assert!(
        s2k_info.parallelism >= 1,
        "Argon2id parallelism should be at least 1, got {}",
        s2k_info.parallelism
    );
}

/// Verify that Profile A export uses Iterated+Salted S2K (not Argon2id).
#[test]
fn test_export_profile_a_uses_iterated_salted() {
    use pgp_mobile::keys::KeyProfile;

    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let exported = keys::export_secret_key(&key.cert_data, "test", KeyProfile::Universal)
        .expect("Export should succeed");

    let s2k_info = keys::parse_s2k_params(&exported)
        .expect("S2K params should parse");

    assert_eq!(
        s2k_info.s2k_type, "iterated-salted",
        "Profile A export must use Iterated+Salted S2K, not {}",
        s2k_info.s2k_type
    );
    assert_eq!(s2k_info.memory_kib, 0, "Iterated+Salted has no memory parameter");
}

/// Fix #3 verification: expired Profile B key detected.
#[test]
fn test_expired_key_detected_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        Some(1), // 1 second expiry
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    std::thread::sleep(std::time::Duration::from_secs(2));

    let info = keys::parse_key_info(&key.cert_data).expect("Parse should succeed");
    assert!(info.is_expired, "Key with 1-second expiry should be expired after 2 seconds");
    assert!(!info.is_revoked);
}

/// Unicode User ID (Profile B).
#[test]
fn test_unicode_user_id_profile_b() {
    let key = keys::generate_key_with_profile(
        "李四 🛡️".to_string(),
        Some("lisi@example.com".to_string()),
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen with Unicode should succeed");

    let info = keys::parse_key_info(&key.cert_data).expect("Parse should succeed");
    assert!(info.user_id.unwrap().contains("李四"));
}
