//! Large payload integration tests.
//! Kept ignored by default to preserve coverage without slowing the default test path.
//! GitHub PR and nightly workflows run this target explicitly with:
//! `cargo test --manifest-path pgp-mobile/Cargo.toml --test large_payload_tests -- --ignored`.

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};

/// C2A.5 (extended): 50 MB file encrypt/decrypt (Profile A).
#[test]
#[ignore = "slow"]
fn test_file_encrypt_decrypt_50mb_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let plaintext = vec![0xABu8; 50 * 1024 * 1024];
    let ciphertext =
        encrypt::encrypt_binary(&plaintext, &[key.public_key_data.clone()], None, None)
            .expect("50 MB encryption should succeed");

    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("50 MB decryption should succeed");

    assert_eq!(
        result.plaintext.len(),
        plaintext.len(),
        "50 MB round-trip size mismatch"
    );
    assert_eq!(
        result.plaintext, plaintext,
        "50 MB round-trip content mismatch"
    );
}

/// C2A.5 (extended): 100 MB file encrypt/decrypt (Profile A).
#[test]
#[ignore = "slow"]
fn test_file_encrypt_decrypt_100mb_profile_a() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let plaintext = vec![0xCDu8; 100 * 1024 * 1024];
    let ciphertext =
        encrypt::encrypt_binary(&plaintext, &[key.public_key_data.clone()], None, None)
            .expect("100 MB encryption should succeed");

    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("100 MB decryption should succeed");

    assert_eq!(
        result.plaintext.len(),
        plaintext.len(),
        "100 MB round-trip size mismatch"
    );
}

/// C2B.5 (extended): 50 MB file encrypt/decrypt (Profile B).
#[test]
#[ignore = "slow"]
fn test_file_encrypt_decrypt_50mb_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let plaintext = vec![0xABu8; 50 * 1024 * 1024];
    let ciphertext =
        encrypt::encrypt_binary(&plaintext, &[key.public_key_data.clone()], None, None)
            .expect("50 MB encryption should succeed");

    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("50 MB decryption should succeed");

    assert_eq!(
        result.plaintext.len(),
        plaintext.len(),
        "50 MB round-trip size mismatch"
    );
    assert_eq!(
        result.plaintext, plaintext,
        "50 MB round-trip content mismatch"
    );
}

/// C2B.5 (extended): 100 MB file encrypt/decrypt (Profile B).
#[test]
#[ignore = "slow"]
fn test_file_encrypt_decrypt_100mb_profile_b() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let plaintext = vec![0xCDu8; 100 * 1024 * 1024];
    let ciphertext =
        encrypt::encrypt_binary(&plaintext, &[key.public_key_data.clone()], None, None)
            .expect("100 MB encryption should succeed");

    let result = decrypt::decrypt(&ciphertext, &[key.cert_data.clone()], &[])
        .expect("100 MB decryption should succeed");

    assert_eq!(
        result.plaintext.len(),
        plaintext.len(),
        "100 MB round-trip size mismatch"
    );
}
