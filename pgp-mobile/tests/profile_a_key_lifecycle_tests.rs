//! Profile A key lifecycle tests.
//! Covers export/import, revocation, key identity metadata, recipient matching,
//! and expiry modification paths for Universal profile keys.

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::sign;

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

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Universal)
        .expect("Export should succeed");
    assert!(!exported.is_empty());

    let imported = keys::import_secret_key(&exported, passphrase)
        .expect("Import should succeed with correct passphrase");
    assert!(!imported.is_empty());
}

/// C2A.7: Re-import with wrong passphrase → graceful error.
#[test]
fn test_import_wrong_passphrase_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let exported =
        keys::export_secret_key(&key.cert_data, "correct-passphrase", KeyProfile::Universal)
            .expect("Export should succeed");

    let result = keys::import_secret_key(&exported, "wrong-passphrase");
    match result {
        Err(pgp_mobile::error::PgpError::WrongPassphrase) => {}
        Err(other) => panic!("Expected WrongPassphrase, got: {other:?}"),
        Ok(_) => panic!("Wrong passphrase should not succeed"),
    }
}

/// Unicode passphrase round-trip for S2K export/import (Profile A, Iterated+Salted).
#[test]
fn test_unicode_passphrase_export_import_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let passphrases = [
        "密码短语🔐安全",
        "パスワード",
        "🔒🗝️🔑",
        "mïxéd-ünïcödé-pässwörd",
    ];

    for passphrase in &passphrases {
        let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Universal)
            .expect(&format!(
                "Export with passphrase '{passphrase}' should succeed"
            ));

        let imported = keys::import_secret_key(&exported, passphrase).expect(&format!(
            "Import with passphrase '{passphrase}' should succeed"
        ));

        let ciphertext = encrypt::encrypt(b"test", &[key.public_key_data.clone()], None, None)
            .expect("Encrypt should succeed");

        let result = decrypt::decrypt_detailed(&ciphertext, &[imported.clone()], &[]);
        assert!(
            result.is_ok(),
            "Decrypt with imported key (passphrase '{passphrase}') should succeed"
        );
    }
}

/// Export with wrong profile should fail.
#[test]
fn test_export_wrong_profile_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let result = keys::export_secret_key(&key.cert_data, "passphrase", KeyProfile::Advanced);
    assert!(
        result.is_err(),
        "Exporting v4 key with Advanced profile should fail"
    );
    let err = result.unwrap_err();
    match err {
        pgp_mobile::error::PgpError::S2kError { reason } => {
            assert!(
                reason.contains("Profile mismatch"),
                "Error should mention profile mismatch: {reason}"
            );
        }
        other => panic!("Expected S2kError, got: {other:?}"),
    }
}

/// C2A.8: Generate + parse revocation cert.
#[test]
fn test_revocation_cert_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let result = keys::parse_revocation_cert(&key.revocation_cert, &key.cert_data)
        .expect("Revocation cert should parse and verify");
    assert!(result.contains("revocation"), "Should be a key revocation");
}

/// Revocation cert for key A should not verify against key B.
#[test]
fn test_revocation_cert_wrong_key_profile_a() {
    let key_a =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key A gen should succeed");

    let key_b =
        keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
            .expect("Key B gen should succeed");

    let result = keys::parse_revocation_cert(&key_a.revocation_cert, &key_b.cert_data);
    assert!(
        result.is_err(),
        "Revocation cert should not verify against wrong key"
    );
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

/// Fix #1 verification: exported key is truly passphrase-protected.
/// After export, the key should not be usable without decryption (import).
#[test]
fn test_export_produces_encrypted_key_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let passphrase = "test-passphrase-a";

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Universal)
        .expect("Export should succeed");

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

    let ciphertext = encrypt::encrypt(plaintext, &[key.public_key_data.clone()], None, None)
        .expect("Encryption should succeed");

    let passphrase = "roundtrip-test-passphrase";
    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Universal)
        .expect("Export should succeed");

    let imported = keys::import_secret_key(&exported, passphrase).expect("Import should succeed");

    let result = decrypt::decrypt_detailed(&ciphertext, &[imported], &[])
        .expect("Decryption with imported key should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// Verify that Profile A export uses Iterated+Salted S2K (not Argon2id).
#[test]
fn test_export_profile_a_uses_iterated_salted() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let exported = keys::export_secret_key(&key.cert_data, "test", KeyProfile::Universal)
        .expect("Export should succeed");

    let s2k_info = keys::parse_s2k_params(&exported).expect("S2K params should parse");

    assert_eq!(
        s2k_info.s2k_type, "iterated-salted",
        "Profile A export must use Iterated+Salted S2K, not {}",
        s2k_info.s2k_type
    );
    assert_eq!(
        s2k_info.memory_kib, 0,
        "Iterated+Salted has no memory parameter"
    );
}

/// Fix #3 verification: expired key detected by parse_key_info.
#[test]
fn test_expired_key_detected_profile_a() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        Some(1),
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let info = keys::parse_key_info(&key.cert_data).expect("Parse should succeed");
    assert!(
        info.is_expired,
        "Key with 1-second expiry should be expired after 2 seconds"
    );
    assert!(
        !info.is_revoked,
        "Expired key should not be marked as revoked"
    );
}

/// match_recipients: encrypt to a Profile A key, match against its public cert.
/// Verifies the returned fingerprint is the primary key fingerprint (not the subkey ID).
#[test]
fn test_match_recipients_profile_a_returns_primary_fingerprint() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let ciphertext =
        encrypt::encrypt_binary(b"test message", &[key.public_key_data.clone()], None, None)
            .expect("Encryption should succeed");

    let matched = decrypt::match_recipients(&ciphertext, &[key.public_key_data.clone()])
        .expect("match_recipients should succeed");

    assert_eq!(matched.len(), 1, "Should match exactly one certificate");
    assert_eq!(
        matched[0], key.fingerprint,
        "Matched fingerprint should be the primary key fingerprint"
    );
}

/// match_recipients: encrypt to key A, match against key B → NoMatchingKey.
#[test]
fn test_match_recipients_profile_a_wrong_key_returns_error() {
    let alice =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
        .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"for alice only",
        &[alice.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    let result = decrypt::match_recipients(&ciphertext, &[bob.public_key_data.clone()]);
    assert!(
        matches!(result, Err(pgp_mobile::error::PgpError::NoMatchingKey)),
        "Should return NoMatchingKey for wrong cert, got: {result:?}"
    );
}

/// match_recipients: multi-recipient message matches both certs.
#[test]
fn test_match_recipients_profile_a_multi_recipient() {
    let alice =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
        .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"for both",
        &[alice.public_key_data.clone(), bob.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    let matched = decrypt::match_recipients(
        &ciphertext,
        &[alice.public_key_data.clone(), bob.public_key_data.clone()],
    )
    .expect("match_recipients should succeed");

    assert_eq!(matched.len(), 2, "Should match both certificates");
    assert!(matched.contains(&alice.fingerprint));
    assert!(matched.contains(&bob.fingerprint));
}

/// match_recipients: encrypt-to-self includes sender in match.
#[test]
fn test_match_recipients_profile_a_encrypt_to_self() {
    let sender =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let recipient =
        keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"with encrypt-to-self",
        &[recipient.public_key_data.clone()],
        None,
        Some(&sender.public_key_data),
    )
    .expect("Encryption should succeed");

    let matched = decrypt::match_recipients(&ciphertext, &[sender.public_key_data.clone()])
        .expect("match_recipients should find sender via encrypt-to-self");

    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0], sender.fingerprint);
}

/// Modify expiry on a Profile A key: extend to 3 years.
/// Pass: key is not expired, expiry_timestamp is set, key info updated.
#[test]
fn test_modify_expiry_profile_a_extend() {
    let generated = keys::generate_key_with_profile(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        Some(365 * 24 * 3600),
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    let result = keys::modify_expiry(
        &generated.cert_data,
        Some(3 * 365 * 24 * 3600),
    )
    .expect("modify_expiry should succeed for Profile A");

    assert!(
        !result.cert_data.is_empty(),
        "Updated cert should not be empty"
    );
    assert!(
        !result.public_key_data.is_empty(),
        "Updated public key should not be empty"
    );
    assert!(
        !result.key_info.is_expired,
        "Key should not be expired after extending"
    );
    assert!(
        result.key_info.expiry_timestamp.is_some(),
        "Should have an expiry timestamp"
    );
    assert_eq!(result.key_info.key_version, 4);
    assert_eq!(result.key_info.profile, KeyProfile::Universal);

    let re_parsed = keys::parse_key_info(&result.public_key_data)
        .expect("Updated public key should be parseable");
    assert!(!re_parsed.is_expired);
    assert!(re_parsed.expiry_timestamp.is_some());
}

/// Modify expiry on a Profile A key: remove expiry (set to never expire).
/// Pass: key has no expiry timestamp, key is not expired.
#[test]
fn test_modify_expiry_profile_a_remove() {
    let generated = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        Some(365 * 24 * 3600),
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    let info_before =
        keys::parse_key_info(&generated.public_key_data).expect("Parse should succeed");
    assert!(
        info_before.expiry_timestamp.is_some(),
        "Should have expiry before removal"
    );

    let result = keys::modify_expiry(&generated.cert_data, None)
        .expect("modify_expiry with None should succeed");

    assert!(
        !result.key_info.is_expired,
        "Key should not be expired after removing expiry"
    );
    assert!(
        result.key_info.expiry_timestamp.is_none(),
        "Expiry timestamp should be None after removal"
    );
}

/// Modify expiry on a Profile A key: set to 1 second (effectively expired).
/// Pass: key is expired.
#[test]
fn test_modify_expiry_profile_a_to_past() {
    let generated =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key generation should succeed");

    let result =
        keys::modify_expiry(&generated.cert_data, Some(1)).expect("modify_expiry should succeed");

    std::thread::sleep(std::time::Duration::from_secs(2));

    let info = keys::parse_key_info(&result.public_key_data).expect("Parse should succeed");
    assert!(
        info.is_expired,
        "Key should be expired after setting 1-second expiry and waiting"
    );
}

/// Verify that encrypt/decrypt still works after modifying expiry on a Profile A key.
#[test]
fn test_modify_expiry_profile_a_roundtrip_encrypt_decrypt() {
    let generated = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        Some(365 * 24 * 3600),
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    let result = keys::modify_expiry(&generated.cert_data, Some(3 * 365 * 24 * 3600))
        .expect("modify_expiry should succeed");

    let plaintext = b"Hello after expiry modification!";
    let ciphertext = encrypt::encrypt(plaintext, &[result.public_key_data.clone()], None, None)
        .expect("Encryption should succeed with updated key");

    let decrypted = decrypt::decrypt_detailed(&ciphertext, &[result.cert_data.clone()], &[])
        .expect("Decryption should succeed with updated key");
    assert_eq!(decrypted.plaintext, plaintext);
}
