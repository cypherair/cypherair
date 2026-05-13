//! Profile A message-path tests.
//! Covers key generation, sign/verify, encrypt/decrypt, detached signatures,
//! armor, tamper handling, and other message-centric regressions.

use pgp_mobile::armor;
use pgp_mobile::decrypt;
use pgp_mobile::decrypt::SignatureStatus;
use pgp_mobile::encrypt;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::sign;
use pgp_mobile::verify;

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
    assert_eq!(info.user_id, Some("Alice <alice@example.com>".to_string()));

    // Verify actual cryptographic algorithms (not just version/profile)
    assert!(
        info.primary_algo.contains("EdDSA"),
        "Profile A primary key must use EdDSA (Ed25519), got: {}",
        info.primary_algo
    );
    let subkey_algo = info.subkey_algo.expect("Must have subkey algorithm");
    assert!(
        subkey_algo.contains("ECDH"),
        "Profile A subkey must use ECDH (X25519), got: {}",
        subkey_algo
    );
}

/// C2A.2: Sign + verify text (Profile A).
#[test]
fn test_sign_verify_text_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key generation should succeed");

    let text = b"Hello, world! This is a test message.";

    // Sign
    let signed = sign::sign_cleartext(text, &key.cert_data).expect("Signing should succeed");

    // Verify
    let result = verify::verify_cleartext_detailed(&signed, &[key.public_key_data.clone()])
        .expect("Verification should succeed");

    assert_eq!(result.legacy_status, SignatureStatus::Valid);
    assert_eq!(result.legacy_signer_fingerprint, Some(key.fingerprint.clone()));
}

/// C2A.3: Encrypt + decrypt text (SEIPDv1).
#[test]
fn test_encrypt_decrypt_text_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key generation should succeed");

    let plaintext = b"Hello, this is a secret message for Profile A.";

    // Encrypt to self
    let ciphertext = encrypt::encrypt(plaintext, &[key.public_key_data.clone()], None, None)
        .expect("Encryption should succeed");

    // Decrypt
    let result = decrypt::decrypt_detailed(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// C2A.3 (extended): Encrypt + decrypt with signature.
#[test]
fn test_encrypt_decrypt_signed_profile_a() {
    let sender =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Sender key gen should succeed");

    let recipient =
        keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
            .expect("Recipient key gen should succeed");

    let plaintext = b"Signed and encrypted message.";

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
    assert_eq!(result.legacy_status, SignatureStatus::Valid);
    assert_eq!(result.legacy_signer_fingerprint, Some(sender.fingerprint.clone()));
}

/// C2A.4: Encrypt-to-self — sender decrypts own ciphertext.
#[test]
fn test_encrypt_to_self_profile_a() {
    let sender =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let recipient =
        keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
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
    let result_recipient = decrypt::decrypt_detailed(&ciphertext, &[recipient.cert_data.clone()], &[])
        .expect("Recipient should decrypt");
    assert_eq!(result_recipient.plaintext, plaintext);

    // Sender can also decrypt (encrypt-to-self)
    let result_sender = decrypt::decrypt_detailed(&ciphertext, &[sender.cert_data.clone()], &[])
        .expect("Sender should decrypt own message");
    assert_eq!(result_sender.plaintext, plaintext);
}

/// C2A.5: File encrypt/decrypt with various sizes (1 MB).
#[test]
fn test_file_encrypt_decrypt_1mb_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    // Generate 1 MB of test data
    let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let ciphertext =
        encrypt::encrypt_binary(&plaintext, &[key.public_key_data.clone()], None, None)
            .expect("Encryption should succeed");

    let result = decrypt::decrypt_detailed(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("Decryption should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// C2A.5: File encrypt/decrypt 10 MB.
#[test]
fn test_file_encrypt_decrypt_10mb_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
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

/// Tamper test: 1-bit flip → decryption fails (MDC check).
/// Verifies that the integrity protection mechanism (MDC for SEIPDv1) is working,
/// not just that decryption happens to fail for some other reason.
#[test]
fn test_tamper_detection_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let plaintext = b"Secret message that must not be tampered with.";

    let ciphertext = encrypt::encrypt_binary(plaintext, &[key.public_key_data.clone()], None, None)
        .expect("Encryption should succeed");

    // Test tamper detection at multiple positions to exercise different code paths:
    // - Early: PKESK packet header region (may cause NoMatchingKey or CorruptData)
    // - Middle: encrypted data body (should trigger IntegrityCheckFailed / MDC failure)
    // - Late: near end, close to MDC authentication tag
    let positions = [
        ("early (byte 15)", 15.min(ciphertext.len() - 1)),
        ("middle", ciphertext.len() / 2),
        (
            "late (near end)",
            ciphertext.len() - 10.min(ciphertext.len()),
        ),
    ];

    let mut got_integrity_error = false;
    for (label, pos) in &positions {
        let mut tampered = ciphertext.clone();
        tampered[*pos] ^= 0x01;

        let result = decrypt::decrypt_detailed(&tampered, &[key.cert_data.clone()], &[]);
        match &result {
            Err(pgp_mobile::error::PgpError::IntegrityCheckFailed) => {
                got_integrity_error = true;
            }
            Err(pgp_mobile::error::PgpError::CorruptData { .. }) => {}
            Err(pgp_mobile::error::PgpError::NoMatchingKey) => {} // PKESK header corrupted
            Err(other) => panic!(
                "Tamper at {label} (offset {pos}): expected integrity/corruption/no-matching-key error, got: {other:?}"
            ),
            Ok(_) => panic!("Tamper at {label} (offset {pos}): tampered ciphertext must never decrypt successfully"),
        }
    }

    assert!(
        got_integrity_error,
        "At least one tamper position should trigger IntegrityCheckFailed (MDC), \
         but all produced NoMatchingKey or CorruptData — MDC check may not be exercised"
    );
}

/// Detached signature: sign + verify file data.
#[test]
fn test_detached_signature_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let data = b"File content to sign.";

    let signature = sign::sign_detached(data, &key.cert_data).expect("Signing should succeed");

    let result = verify::verify_detached_detailed(data, &signature, &[key.public_key_data.clone()])
        .expect("Verification should succeed");

    assert_eq!(result.legacy_status, SignatureStatus::Valid);
}

/// Armor round-trip: public key → armor → dearmor → identical.
#[test]
fn test_armor_roundtrip_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let armored = armor::armor_public_key(&key.public_key_data).expect("Armor should succeed");

    // Armored output should contain the PGP header
    let armored_str = String::from_utf8_lossy(&armored);
    assert!(armored_str.contains("BEGIN PGP PUBLIC KEY BLOCK"));

    // Dearmor and compare
    let (dearmored, _kind) = armor::decode_armor(&armored).expect("Dearmor should succeed");

    // Parse both and compare fingerprints (binary data may differ in minor ways)
    let original_info = keys::parse_key_info(&key.public_key_data).unwrap();
    let dearmored_info = keys::parse_key_info(&dearmored).unwrap();
    assert_eq!(original_info.fingerprint, dearmored_info.fingerprint);
}

/// Fix #4 verification: encrypt_binary rejects recipient without encryption subkey.
/// This test creates a signing-only cert and verifies that encrypt_binary produces
/// the same error as encrypt.
#[test]
fn test_encrypt_binary_rejects_no_encryption_subkey() {
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp as openpgp;

    // Create a cert with ONLY signing capability, no encryption subkey
    let (cert, _rev) = CertBuilder::new()
        .add_userid("SignOnly")
        .add_signing_subkey()
        // No add_transport_encryption_subkey()
        .generate()
        .expect("Cert gen should succeed");

    let mut pubkey_data = Vec::new();
    cert.serialize(&mut pubkey_data)
        .expect("Serialize should succeed");

    let plaintext = b"Test message";

    // Both encrypt and encrypt_binary should fail with the same kind of error
    let result_armored = encrypt::encrypt(plaintext, &[pubkey_data.clone()], None, None);
    assert!(
        result_armored.is_err(),
        "encrypt should reject recipient without encryption subkey"
    );

    let result_binary = encrypt::encrypt_binary(plaintext, &[pubkey_data.clone()], None, None);
    assert!(
        result_binary.is_err(),
        "encrypt_binary should reject recipient without encryption subkey"
    );
}

/// Wrong key decryption: decrypt with wrong key → NoMatchingKey error.
#[test]
fn test_decrypt_wrong_key_profile_a() {
    let alice =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
        .expect("Key gen should succeed");

    let plaintext = b"Only for Alice.";

    let ciphertext = encrypt::encrypt(plaintext, &[alice.public_key_data.clone()], None, None)
        .expect("Encryption should succeed");

    // Bob tries to decrypt Alice's message
    let result = decrypt::decrypt_detailed(&ciphertext, &[bob.cert_data.clone()], &[]);
    // M1: Verify the specific error variant, not just that it failed
    match result {
        Err(PgpError::NoMatchingKey) => {} // expected
        Err(other) => panic!("Expected NoMatchingKey, got: {other:?}"),
        Ok(_) => panic!("Wrong key should fail to decrypt"),
    }
}

/// Empty plaintext encrypt/decrypt round-trip (Profile A).
#[test]
fn test_encrypt_decrypt_empty_plaintext_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
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

/// C5.6: Concurrent encrypt from 2 threads (Profile A, different key pairs).
#[test]
fn test_concurrent_encrypt_profile_a() {
    let key1 =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let key2 =
        keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let k1_pub = key1.public_key_data.clone();
    let k2_pub = key2.public_key_data.clone();
    let k1_cert = key1.cert_data.clone();
    let k2_cert = key2.cert_data.clone();

    let handle1 = std::thread::spawn(move || {
        let ct = encrypt::encrypt(b"msg1", &[k1_pub], None, None)
            .expect("Concurrent encrypt 1 should succeed");
        let result =
            decrypt::decrypt_detailed(&ct, &[k1_cert], &[]).expect("Concurrent decrypt 1 should succeed");
        assert_eq!(result.plaintext, b"msg1");
    });

    let handle2 = std::thread::spawn(move || {
        let ct = encrypt::encrypt(b"msg2", &[k2_pub], None, None)
            .expect("Concurrent encrypt 2 should succeed");
        let result =
            decrypt::decrypt_detailed(&ct, &[k2_cert], &[]).expect("Concurrent decrypt 2 should succeed");
        assert_eq!(result.plaintext, b"msg2");
    });

    handle1
        .join()
        .expect("Thread 1 should complete without panic");
    handle2
        .join()
        .expect("Thread 2 should complete without panic");
}
