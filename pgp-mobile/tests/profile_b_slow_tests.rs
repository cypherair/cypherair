//! Profile B slow tests.
//! These preserve full Argon2id export/import coverage without keeping the default
//! `cargo test` path stuck on long-running passphrase-protected key operations.

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::sign;

/// C2B.6: Export key with Argon2id.
#[test]
#[ignore = "slow"]
fn test_export_key_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let passphrase = "strong-passphrase-for-profile-b";

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
        .expect("Export should succeed");
    assert!(!exported.is_empty());
}

/// C2B.7: Re-import with correct passphrase.
#[test]
#[ignore = "slow"]
fn test_import_correct_passphrase_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
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
#[ignore = "slow"]
fn test_import_wrong_passphrase_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let exported = keys::export_secret_key(&key.cert_data, "correct", KeyProfile::Advanced)
        .expect("Export should succeed");

    let result = keys::import_secret_key(&exported, "wrong");
    match result {
        Err(pgp_mobile::error::PgpError::WrongPassphrase) => {}
        Err(other) => panic!("Expected WrongPassphrase, got: {other:?}"),
        Ok(_) => panic!("Wrong passphrase should not succeed"),
    }
}

/// Fix #1 verification: exported Profile B key is truly passphrase-protected.
#[test]
#[ignore = "slow"]
fn test_export_produces_encrypted_key_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let passphrase = "test-passphrase-b";

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
        .expect("Export should succeed");

    let sign_result = sign::sign_cleartext(b"test", &exported);
    assert!(
        sign_result.is_err(),
        "Exported key with encrypted secrets should not be directly usable for signing"
    );
}

/// Fix #1+#2 verification: full export → import → decrypt round-trip (Profile B).
#[test]
#[ignore = "slow"]
fn test_export_import_decrypt_roundtrip_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let plaintext = b"Profile B export/import chain test.";

    let ciphertext = encrypt::encrypt(plaintext, &[key.public_key_data.clone()], None, None)
        .expect("Encryption should succeed");

    let passphrase = "roundtrip-profile-b";
    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
        .expect("Export should succeed");
    let imported = keys::import_secret_key(&exported, passphrase).expect("Import should succeed");

    let result = decrypt::decrypt(&ciphertext, &[imported], &[])
        .expect("Decryption with imported key should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// Unicode passphrase export/import round-trip (Profile B, Argon2id).
/// Verifies that passphrases containing CJK, Japanese, and emoji characters
/// survive the Argon2id S2K derivation and produce a usable key.
#[test]
#[ignore = "slow"]
fn test_unicode_passphrase_export_import_profile_b() {
    let key = keys::generate_key_with_profile(
        "Unicode Test".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let passphrases = vec![
        "密码短语测试",
        "パスフレーズ",
        "\u{1F510}\u{1F511}\u{1F6E1}\u{FE0F}\u{1F5DD}\u{FE0F}",
        "Mïxëd Ünîcödé & 中文 \u{1F510}",
    ];

    for passphrase in &passphrases {
        let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
            .unwrap_or_else(|e| {
                panic!("Export with passphrase '{passphrase}' should succeed: {e}")
            });

        let imported = keys::import_secret_key(&exported, passphrase).unwrap_or_else(|e| {
            panic!("Import with passphrase '{passphrase}' should succeed: {e}")
        });

        let plaintext = b"Unicode passphrase round-trip test.";
        let ciphertext =
            encrypt::encrypt_binary(plaintext, &[key.public_key_data.clone()], None, None)
                .expect("Encrypt should succeed");

        let result = decrypt::decrypt(&ciphertext, &[imported.clone()], &[]).unwrap_or_else(|e| {
            panic!("Decrypt with reimported key (passphrase '{passphrase}') should succeed: {e}")
        });

        assert_eq!(
            result.plaintext, plaintext,
            "Plaintext mismatch after Unicode passphrase round-trip with '{passphrase}'"
        );
    }
}
