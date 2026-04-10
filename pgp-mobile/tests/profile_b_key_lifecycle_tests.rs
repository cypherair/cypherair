//! Profile B key lifecycle tests.
//! Covers export policy checks, revocation, recipient matching, Unicode key metadata,
//! and expiry modification paths while leaving the heaviest Argon2id loops in slow tests.

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};

/// Export with wrong profile should fail.
#[test]
fn test_export_wrong_profile_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let result = keys::export_secret_key(&key.cert_data, "passphrase", KeyProfile::Universal);
    assert!(
        result.is_err(),
        "Exporting v6 key with Universal profile should fail"
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

/// C2B.9: Generate + parse revocation cert.
#[test]
fn test_revocation_cert_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let result = keys::parse_revocation_cert(&key.revocation_cert, &key.cert_data)
        .expect("Revocation cert should parse and verify");
    assert!(result.contains("revocation"));
}

/// Revocation cert for key A should not verify against key B.
#[test]
fn test_revocation_cert_wrong_key_profile_b() {
    let key_a =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key A gen should succeed");

    let key_b =
        keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key B gen should succeed");

    let result = keys::parse_revocation_cert(&key_a.revocation_cert, &key_b.cert_data);
    assert!(
        result.is_err(),
        "Revocation cert should not verify against wrong key"
    );
}

/// C2B.6 (extended): Verify that Profile B export uses Argon2id S2K with expected parameters.
/// PRD requires: 512 MB memory (encoded_m=19), p=4 parallelism.
#[test]
fn test_export_profile_b_uses_argon2id() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let passphrase = "s2k-verification-test";

    let exported = keys::export_secret_key(&key.cert_data, passphrase, KeyProfile::Advanced)
        .expect("Export should succeed");

    let s2k_info = keys::parse_s2k_params(&exported).expect("S2K params should parse");

    assert_eq!(
        s2k_info.s2k_type, "argon2id",
        "Profile B export must use Argon2id S2K"
    );
    assert_eq!(
        s2k_info.memory_kib, 524288,
        "Argon2id memory must be 512 MB (524288 KiB = 2^19 KiB per PRD), got {} KiB",
        s2k_info.memory_kib
    );
    assert_eq!(
        s2k_info.parallelism, 4,
        "Argon2id parallelism must be 4 per PRD, got {}",
        s2k_info.parallelism
    );
    assert_eq!(
        s2k_info.time_passes, 3,
        "Argon2id time passes must be 3 per PRD, got {}",
        s2k_info.time_passes
    );
}

/// Fix #3 verification: expired Profile B key detected.
#[test]
fn test_expired_key_detected_profile_b() {
    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        Some(1),
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let info = keys::parse_key_info(&key.cert_data).expect("Parse should succeed");
    assert!(
        info.is_expired,
        "Key with 1-second expiry should be expired after 3 seconds"
    );
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

/// match_recipients: Profile B (v6 key, SEIPDv2) returns primary fingerprint.
#[test]
fn test_match_recipients_profile_b_returns_primary_fingerprint() {
    let key = keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Advanced)
        .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"profile b test",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encryption should succeed");

    let matched = decrypt::match_recipients(&ciphertext, &[key.public_key_data.clone()])
        .expect("match_recipients should succeed for Profile B");

    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0], key.fingerprint);
}

/// match_recipients: Profile B wrong key → NoMatchingKey.
#[test]
fn test_match_recipients_profile_b_wrong_key_returns_error() {
    let alice =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Advanced)
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

/// match_recipients: encrypt-to-self includes sender in match (Profile B).
/// Complements test_match_recipients_profile_a_encrypt_to_self (Profile A).
#[test]
fn test_match_recipients_profile_b_encrypt_to_self() {
    let sender =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let recipient =
        keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"encrypt-to-self test",
        &[recipient.public_key_data.clone()],
        None,
        Some(&sender.public_key_data),
    )
    .expect("Encryption should succeed");

    let matched = decrypt::match_recipients(
        &ciphertext,
        &[
            sender.public_key_data.clone(),
            recipient.public_key_data.clone(),
        ],
    )
    .expect("match_recipients should find sender via encrypt-to-self");

    assert!(
        matched.len() >= 2,
        "match_recipients should find both sender (encrypt-to-self) and recipient, got {}",
        matched.len()
    );
    assert!(matched.contains(&sender.fingerprint));
    assert!(matched.contains(&recipient.fingerprint));
}

/// Modify expiry on a Profile B key: extend to 3 years.
/// Pass: key is not expired, expiry_timestamp is set, key info updated.
#[test]
fn test_modify_expiry_profile_b_extend() {
    let generated = keys::generate_key_with_profile(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        Some(365 * 24 * 3600),
        KeyProfile::Advanced,
    )
    .expect("Key generation should succeed");

    let result = keys::modify_expiry(
        &generated.cert_data,
        Some(3 * 365 * 24 * 3600),
    )
    .expect("modify_expiry should succeed for Profile B");

    assert!(!result.cert_data.is_empty());
    assert!(!result.public_key_data.is_empty());
    assert!(!result.key_info.is_expired);
    assert!(result.key_info.expiry_timestamp.is_some());
    assert_eq!(result.key_info.key_version, 6);
    assert_eq!(result.key_info.profile, KeyProfile::Advanced);

    let re_parsed = keys::parse_key_info(&result.public_key_data)
        .expect("Updated public key should be parseable");
    assert!(!re_parsed.is_expired);
    assert!(re_parsed.expiry_timestamp.is_some());
}

/// Modify expiry on a Profile B key: remove expiry (set to never expire).
/// Pass: key has no expiry timestamp, key is not expired.
#[test]
fn test_modify_expiry_profile_b_remove() {
    let generated = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        Some(365 * 24 * 3600),
        KeyProfile::Advanced,
    )
    .expect("Key generation should succeed");

    let info_before =
        keys::parse_key_info(&generated.public_key_data).expect("Parse should succeed");
    assert!(info_before.expiry_timestamp.is_some());

    let result = keys::modify_expiry(&generated.cert_data, None)
        .expect("modify_expiry with None should succeed");

    assert!(!result.key_info.is_expired);
    assert!(result.key_info.expiry_timestamp.is_none());
}

/// Modify expiry on a Profile B key: set to 1 second (effectively expired).
/// Pass: key is expired.
#[test]
fn test_modify_expiry_profile_b_to_past() {
    let generated =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
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

/// Verify that encrypt/decrypt still works after modifying expiry on a Profile B key.
#[test]
fn test_modify_expiry_profile_b_roundtrip_encrypt_decrypt() {
    let generated = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        Some(365 * 24 * 3600),
        KeyProfile::Advanced,
    )
    .expect("Key generation should succeed");

    let result = keys::modify_expiry(&generated.cert_data, Some(3 * 365 * 24 * 3600))
        .expect("modify_expiry should succeed");

    let plaintext = b"Hello after expiry modification (Profile B)!";
    let ciphertext = encrypt::encrypt(plaintext, &[result.public_key_data.clone()], None, None)
        .expect("Encryption should succeed with updated key");

    let decrypted = decrypt::decrypt(&ciphertext, &[result.cert_data.clone()], &[])
        .expect("Decryption should succeed with updated key");
    assert_eq!(decrypted.plaintext, plaintext);
}
