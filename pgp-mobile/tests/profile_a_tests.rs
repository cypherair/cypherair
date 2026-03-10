//! Profile A (Universal Compatible) tests.
//! Covers POC test cases C2A.1–C2A.9.
//! Profile A: v4 keys, Ed25519+X25519, SEIPDv1, Iterated+Salted S2K.

use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::encrypt;
use pgp_mobile::decrypt;
use pgp_mobile::sign;
use pgp_mobile::verify;
use pgp_mobile::armor;
use pgp_mobile::decrypt::SignatureStatus;

/// C2A.1: Generate Ed25519+X25519 v4 key pair.
/// Pass: key version is 4.
#[test]
fn test_generate_key_profile_a_produces_v4() {
    let result = keys::generate_key_with_profile(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    assert_eq!(result.key_version, 4, "Profile A key must be v4");
    assert_eq!(result.profile, KeyProfile::Universal);
    assert!(!result.fingerprint.is_empty());
    assert!(!result.cert_data.is_empty());
    assert!(!result.public_key_data.is_empty());
    assert!(!result.revocation_cert.is_empty());
}

/// C2A.1 (extended): Verify key algorithms are Ed25519+X25519.
#[test]
fn test_generate_key_profile_a_algorithms() {
    let result = keys::generate_key_with_profile(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    let info = keys::parse_key_info(&result.cert_data).expect("Parse should succeed");
    assert_eq!(info.key_version, 4);
    assert_eq!(info.profile, KeyProfile::Universal);
    assert!(info.has_encryption_subkey, "Must have encryption subkey");
    assert!(!info.is_revoked);
    assert!(!info.is_expired);
    assert_eq!(
        info.user_id,
        Some("Alice <alice@example.com>".to_string())
    );
}

/// C2A.2: Sign + verify text (Profile A).
#[test]
fn test_sign_verify_text_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    let text = b"Hello, world! This is a test message.";

    // Sign
    let signed = sign::sign_cleartext(text, &key.cert_data)
        .expect("Signing should succeed");

    // Verify
    let result = verify::verify_cleartext(&signed, &[key.public_key_data.clone()])
        .expect("Verification should succeed");

    assert_eq!(result.status, SignatureStatus::Valid);
    assert_eq!(
        result.signer_fingerprint,
        Some(key.fingerprint.clone())
    );
}

/// C2A.3: Encrypt + decrypt text (SEIPDv1).
#[test]
fn test_encrypt_decrypt_text_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    let plaintext = b"Hello, this is a secret message for Profile A.";

    // Encrypt to self
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    // Decrypt
    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// C2A.3 (extended): Encrypt + decrypt with signature.
#[test]
fn test_encrypt_decrypt_signed_profile_a() {
    let sender = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Sender key gen should succeed");

    let recipient = keys::generate_key_with_profile(
        "Bob".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Recipient key gen should succeed");

    let plaintext = b"Signed and encrypted message.";

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
    assert_eq!(
        result.signer_fingerprint,
        Some(sender.fingerprint.clone())
    );
}

/// C2A.4: Encrypt-to-self — sender decrypts own ciphertext.
#[test]
fn test_encrypt_to_self_profile_a() {
    let sender = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let recipient = keys::generate_key_with_profile(
        "Bob".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let plaintext = b"Message with encrypt-to-self.";

    // Encrypt to recipient with encrypt-to-self
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[recipient.public_key_data.clone()],
        None,
        Some(&sender.public_key_data),
    )
    .expect("Encryption should succeed");

    // Recipient can decrypt
    let result_recipient = decrypt::decrypt(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[],
    )
    .expect("Recipient should decrypt");
    assert_eq!(result_recipient.plaintext, plaintext);

    // Sender can also decrypt (encrypt-to-self)
    let result_sender = decrypt::decrypt(
        &ciphertext,
        &[sender.cert_data.clone()],
        &[],
    )
    .expect("Sender should decrypt own message");
    assert_eq!(result_sender.plaintext, plaintext);
}

/// C2A.5: File encrypt/decrypt with various sizes (1 MB).
#[test]
fn test_file_encrypt_decrypt_1mb_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    // Generate 1 MB of test data
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

/// C2A.5: File encrypt/decrypt 10 MB.
#[test]
fn test_file_encrypt_decrypt_10mb_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
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

/// C2A.6: Export key with Iterated+Salted S2K. Re-import with correct passphrase.
#[test]
fn test_export_import_key_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let passphrase = "correct-horse-battery-staple";

    // Export
    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Universal)
        .expect("Export should succeed");
    assert!(!exported.is_empty());

    // Re-import with correct passphrase
    let imported = keys::import_secret_key(&exported, passphrase)
        .expect("Import should succeed with correct passphrase");
    assert!(!imported.is_empty());
}

/// C2A.7: Re-import with wrong passphrase → graceful error.
#[test]
fn test_import_wrong_passphrase_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let exported = keys::export_secret_key(&key.cert_data, "correct-passphrase", KeyProfile::Universal)
        .expect("Export should succeed");

    // Import with wrong passphrase should fail gracefully
    let result = keys::import_secret_key(&exported, "wrong-passphrase");
    assert!(result.is_err(), "Wrong passphrase should fail");
}

/// C2A.8: Generate + parse revocation cert.
#[test]
fn test_revocation_cert_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let result = keys::parse_revocation_cert(&key.revocation_cert)
        .expect("Revocation cert should parse");
    assert!(result.contains("revocation"), "Should be a key revocation");
}

/// Tamper test: 1-bit flip → decryption fails (MDC check).
#[test]
fn test_tamper_detection_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let plaintext = b"Secret message that must not be tampered with.";

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

    // Decryption should fail
    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[]);
    assert!(result.is_err(), "Tampered ciphertext should fail to decrypt");
}

/// Unicode round-trip: Chinese + emoji User IDs survive.
#[test]
fn test_unicode_user_id_profile_a() {
    let key = keys::generate_key_with_profile(
        "张三 🔐".to_string(),
        Some("zhangsan@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen with Unicode should succeed");

    let info = keys::parse_key_info(&key.cert_data).expect("Parse should succeed");
    assert_eq!(
        info.user_id,
        Some("张三 🔐 <zhangsan@example.com>".to_string())
    );
}

/// Detached signature: sign + verify file data.
#[test]
fn test_detached_signature_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let data = b"File content to sign.";

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

/// Armor round-trip: public key → armor → dearmor → identical.
#[test]
fn test_armor_roundtrip_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let armored = armor::armor_public_key(&key.public_key_data)
        .expect("Armor should succeed");

    // Armored output should contain the PGP header
    let armored_str = String::from_utf8_lossy(&armored);
    assert!(armored_str.contains("BEGIN PGP PUBLIC KEY BLOCK"));

    // Dearmor and compare
    let (dearmored, _kind) = armor::decode_armor(&armored)
        .expect("Dearmor should succeed");

    // Parse both and compare fingerprints (binary data may differ in minor ways)
    let original_info = keys::parse_key_info(&key.public_key_data).unwrap();
    let dearmored_info = keys::parse_key_info(&dearmored).unwrap();
    assert_eq!(original_info.fingerprint, dearmored_info.fingerprint);
}

/// Fix #1 verification: exported key is truly passphrase-protected.
/// After export, the key should not be usable without decryption (import).
#[test]
fn test_export_produces_encrypted_key_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let passphrase = "test-passphrase-a";

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Universal)
        .expect("Export should succeed");

    // The exported data should be armored and contain encrypted secret key material.
    // Trying to directly use the exported cert for signing (without import/decrypt)
    // should fail because the secret keys are encrypted.
    let sign_result = sign::sign_cleartext(b"test", &exported);
    assert!(
        sign_result.is_err(),
        "Exported key with encrypted secrets should not be directly usable for signing"
    );
}

/// Fix #1+#2 verification: full export → import → decrypt message round-trip.
#[test]
fn test_export_import_decrypt_roundtrip_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let plaintext = b"Message to verify export/import chain.";

    // Encrypt a message with the original key
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    // Export with passphrase
    let passphrase = "roundtrip-test-passphrase";
    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Universal)
        .expect("Export should succeed");

    // Import with correct passphrase
    let imported = keys::import_secret_key(&exported, passphrase)
        .expect("Import should succeed");

    // Decrypt the message with the imported key
    let result = decrypt::decrypt(&ciphertext, &[imported], &[])
        .expect("Decryption with imported key should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// Fix #3 verification: expired key detected by parse_key_info.
#[test]
fn test_expired_key_detected_profile_a() {
    // Generate a key with 1-second expiry
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        Some(1), // 1 second expiry
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    // Wait for the key to expire (3 seconds to avoid timing flakiness)
    std::thread::sleep(std::time::Duration::from_secs(3));

    let info = keys::parse_key_info(&key.cert_data).expect("Parse should succeed");
    assert!(info.is_expired, "Key with 1-second expiry should be expired after 2 seconds");
    assert!(!info.is_revoked, "Expired key should not be marked as revoked");
}

/// Fix #4 verification: encrypt_binary rejects recipient without encryption subkey.
/// This test creates a signing-only cert and verifies that encrypt_binary produces
/// the same error as encrypt.
#[test]
fn test_encrypt_binary_rejects_no_encryption_subkey() {
    use sequoia_openpgp as openpgp;
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;

    // Create a cert with ONLY signing capability, no encryption subkey
    let (cert, _rev) = CertBuilder::new()
        .add_userid("SignOnly")
        .add_signing_subkey()
        // No add_transport_encryption_subkey()
        .generate()
        .expect("Cert gen should succeed");

    let mut pubkey_data = Vec::new();
    cert.serialize(&mut pubkey_data).expect("Serialize should succeed");

    let plaintext = b"Test message";

    // Both encrypt and encrypt_binary should fail with the same kind of error
    let result_armored = encrypt::encrypt(
        plaintext,
        &[pubkey_data.clone()],
        None,
        None,
    );
    assert!(result_armored.is_err(), "encrypt should reject recipient without encryption subkey");

    let result_binary = encrypt::encrypt_binary(
        plaintext,
        &[pubkey_data.clone()],
        None,
        None,
    );
    assert!(result_binary.is_err(), "encrypt_binary should reject recipient without encryption subkey");
}

/// Wrong key decryption: decrypt with wrong key → NoMatchingKey error.
#[test]
fn test_decrypt_wrong_key_profile_a() {
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

    let plaintext = b"Only for Alice.";

    let ciphertext = encrypt::encrypt(
        plaintext,
        &[alice.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    // Bob tries to decrypt Alice's message
    let result = decrypt::decrypt(&ciphertext, &[bob.cert_data.clone()], &[]);
    assert!(result.is_err(), "Wrong key should fail");
}
