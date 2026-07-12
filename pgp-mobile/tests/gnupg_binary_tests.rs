//! GnuPG Binary Verification Tests.
//!
//! These tests invoke the actual `gpg` binary to verify that GnuPG can correctly
//! process CypherAir's (Sequoia-generated) output. This complements the existing
//! `gnupg_message_interop_tests.rs` which validates the reverse direction (GnuPG output
//! processed by Sequoia).
//!
//! **Skip behavior:** All tests skip gracefully if `gpg` is not found on the system.
//! They will pass silently (with a printed message) rather than fail, so CI
//! environments without GnuPG installed are not affected.
//!
//! **Isolation:** Each test creates a temporary GNUPGHOME directory. The user's
//! real GnuPG keyring is never touched.

mod common;

use common::gnupg::{gpg_cmd, gpg_import_key, setup_gpg_home};
use common::load_fixture;
use pgp_mobile::armor;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::sign;
use pgp_mobile::streaming;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve the `gpg` binary or skip the test, delegating to the shared
/// `common::gnupg` harness. Under `CYPHERAIR_REQUIRE_GPG=1` (the mandatory CI
/// interop lane) a missing gpg fails the test rather than skipping silently.
macro_rules! require_gpg {
    () => {
        match common::gnupg::require_gpg_or_skip() {
            Some(path) => path,
            None => return,
        }
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Verify that `gpg --import` accepts a Sequoia-generated Legacy public key.
#[test]
fn test_gpg_imports_sequoia_legacy_pubkey() {
    let gpg = require_gpg!();
    let gnupghome = setup_gpg_home();

    // Generate a Legacy key with Sequoia
    let key = keys::generate_key_with_profile(
        "Sequoia User".to_string(),
        Some("sequoia@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    // Armor the public key
    let armored_pubkey =
        armor::armor_public_key(&key.public_key_data).expect("Armor should succeed");

    // Write to temp file
    let pubkey_file = gnupghome.path().join("sequoia_pubkey.asc");
    std::fs::write(&pubkey_file, &armored_pubkey).expect("Failed to write pubkey file");

    // gpg --import
    let output = gpg_cmd(&gpg, &gnupghome)
        .arg("--import")
        .arg(&pubkey_file)
        .output()
        .expect("Failed to run gpg --import");

    assert!(
        output.status.success(),
        "gpg --import should accept Sequoia Legacy public key.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    // Verify the key is listed
    let list_output = gpg_cmd(&gpg, &gnupghome)
        .arg("--list-keys")
        .arg("sequoia@example.com")
        .output()
        .expect("Failed to run gpg --list-keys");

    assert!(
        list_output.status.success(),
        "gpg --list-keys should find the imported key.\nstderr: {}",
        String::from_utf8_lossy(&list_output.stderr),
    );
}

/// Verify that `gpg --decrypt` successfully decrypts a Sequoia-encrypted message.
#[test]
fn test_gpg_decrypts_sequoia_encrypted_message() {
    let gpg = require_gpg!();
    let gnupghome = setup_gpg_home();

    // Import the GnuPG fixture secret key into the temp keyring
    let gpg_secretkey = load_fixture("gpg_secretkey.asc");
    gpg_import_key(&gpg, &gnupghome, &gpg_secretkey);

    // Load GnuPG fixture public key for encryption
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");

    // Encrypt a message with Sequoia to the GnuPG public key
    let plaintext = b"Hello GnuPG! This message was encrypted by Sequoia.";
    let ciphertext = encrypt::encrypt(plaintext, &[gpg_pubkey], None, None)
        .expect("Sequoia encryption should succeed");

    // Write ciphertext to temp file
    let ct_file = gnupghome.path().join("sequoia_encrypted.asc");
    std::fs::write(&ct_file, &ciphertext).expect("Failed to write ciphertext file");

    // gpg --decrypt
    let output = gpg_cmd(&gpg, &gnupghome)
        .arg("--decrypt")
        .arg(&ct_file)
        .output()
        .expect("Failed to run gpg --decrypt");

    assert!(
        output.status.success(),
        "gpg --decrypt should succeed on Sequoia-encrypted message.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    // Verify plaintext matches
    let decrypted = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        decrypted.as_ref(),
        std::str::from_utf8(plaintext).unwrap(),
        "Decrypted plaintext should match original",
    );
}

/// Verify that `gpg --verify` accepts a Sequoia cleartext signature.
#[test]
fn test_gpg_verifies_sequoia_cleartext_signature() {
    let gpg = require_gpg!();
    let gnupghome = setup_gpg_home();

    // Generate a Legacy signing key with Sequoia
    let signer = keys::generate_key_with_profile(
        "Sequoia Signer".to_string(),
        Some("signer@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    // Import the public key into gpg
    let armored_pubkey =
        armor::armor_public_key(&signer.public_key_data).expect("Armor should succeed");
    gpg_import_key(&gpg, &gnupghome, &armored_pubkey);

    // Sign a message with Sequoia (cleartext)
    let message = b"This message is signed by Sequoia for GnuPG verification.";
    let signed =
        sign::sign_cleartext(message, &signer.cert_data).expect("Cleartext signing should succeed");

    // Write signed message to temp file
    let signed_file = gnupghome.path().join("sequoia_signed.asc");
    std::fs::write(&signed_file, &signed).expect("Failed to write signed file");

    // gpg --verify
    let output = gpg_cmd(&gpg, &gnupghome)
        .arg("--verify")
        .arg(&signed_file)
        .output()
        .expect("Failed to run gpg --verify");

    assert!(
        output.status.success(),
        "gpg --verify should accept Sequoia cleartext signature.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    // GnuPG prints signature info to stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Good signature"),
        "gpg should report 'Good signature', got stderr:\n{}",
        stderr,
    );
}

/// Verify that `gpg --verify` accepts a Sequoia detached signature.
#[test]
fn test_gpg_verifies_sequoia_detached_signature() {
    let gpg = require_gpg!();
    let gnupghome = setup_gpg_home();

    // Generate a Legacy signing key
    let signer = keys::generate_key_with_profile(
        "Sequoia Signer".to_string(),
        Some("signer@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    // Import the public key into gpg
    let armored_pubkey =
        armor::armor_public_key(&signer.public_key_data).expect("Armor should succeed");
    gpg_import_key(&gpg, &gnupghome, &armored_pubkey);

    // Sign data with Sequoia (detached)
    let data = b"File content signed by Sequoia with detached signature.";
    let data_file = gnupghome.path().join("data.txt");
    let sig_file = gnupghome.path().join("data.txt.sig");
    std::fs::write(&data_file, data).expect("Failed to write data file");
    let signature =
        streaming::sign_detached_file(data_file.to_str().unwrap(), &signer.cert_data, None)
            .expect("Detached signing should succeed");
    std::fs::write(&sig_file, &signature).expect("Failed to write signature file");

    // gpg --verify <sig> <data>
    let output = gpg_cmd(&gpg, &gnupghome)
        .arg("--verify")
        .arg(&sig_file)
        .arg(&data_file)
        .output()
        .expect("Failed to run gpg --verify");

    assert!(
        output.status.success(),
        "gpg --verify should accept Sequoia detached signature.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Good signature"),
        "gpg should report 'Good signature', got stderr:\n{}",
        stderr,
    );
}

/// Verify that `gpg --import` rejects a Sequoia-generated Modern High (v6) public key.
/// GnuPG does not support v6 keys — this is the expected behavior.
#[test]
fn test_gpg_rejects_sequoia_modern_high_pubkey() {
    let gpg = require_gpg!();
    let gnupghome = setup_gpg_home();

    // Generate a Modern High key with Sequoia
    let key = keys::generate_key_with_profile(
        "Modern High User".to_string(),
        Some("profileb@example.com".to_string()),
        None,
        KeyProfile::Advanced,
    )
    .expect("Key generation should succeed");

    assert_eq!(key.key_version, 6, "Modern High must produce v6 key");

    // Armor the public key
    let armored_pubkey =
        armor::armor_public_key(&key.public_key_data).expect("Armor should succeed");

    // Write to temp file
    let pubkey_file = gnupghome.path().join("v6_pubkey.asc");
    std::fs::write(&pubkey_file, &armored_pubkey).expect("Failed to write pubkey file");

    // gpg --import should fail (non-zero exit code)
    let output = gpg_cmd(&gpg, &gnupghome)
        .arg("--import")
        .arg(&pubkey_file)
        .output()
        .expect("Failed to run gpg --import");

    assert!(
        !output.status.success(),
        "gpg --import should reject v6 key (Modern High is not GnuPG compatible).\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Verify that `gpg --decrypt` handles a signed+encrypted message from Sequoia.
/// Decryption should succeed and GnuPG should report signature verification.
#[test]
fn test_gpg_decrypts_sequoia_signed_encrypted_message() {
    let gpg = require_gpg!();
    let gnupghome = setup_gpg_home();

    // Import the GnuPG fixture secret key (recipient)
    let gpg_secretkey = load_fixture("gpg_secretkey.asc");
    gpg_import_key(&gpg, &gnupghome, &gpg_secretkey);

    // Generate a Legacy signing key with Sequoia
    let signer = keys::generate_key_with_profile(
        "Sequoia Signer".to_string(),
        Some("signer@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key generation should succeed");

    // Import signer's public key into gpg (so it can verify the signature)
    let armored_signer_pubkey =
        armor::armor_public_key(&signer.public_key_data).expect("Armor should succeed");
    gpg_import_key(&gpg, &gnupghome, &armored_signer_pubkey);

    // Load GnuPG fixture public key (recipient)
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");

    // Encrypt + sign with Sequoia
    let plaintext = b"Signed and encrypted by Sequoia for GnuPG.";
    let ciphertext = encrypt::encrypt(plaintext, &[gpg_pubkey], Some(&signer.cert_data), None)
        .expect("Encrypt+sign should succeed");

    // Write ciphertext to temp file
    let ct_file = gnupghome.path().join("signed_encrypted.asc");
    std::fs::write(&ct_file, &ciphertext).expect("Failed to write ciphertext file");

    // gpg --decrypt
    let output = gpg_cmd(&gpg, &gnupghome)
        .arg("--decrypt")
        .arg(&ct_file)
        .output()
        .expect("Failed to run gpg --decrypt");

    assert!(
        output.status.success(),
        "gpg --decrypt should succeed on Sequoia signed+encrypted message.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    // Verify plaintext matches
    let decrypted = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        decrypted.as_ref(),
        std::str::from_utf8(plaintext).unwrap(),
        "Decrypted plaintext should match original",
    );

    // GnuPG should report signature verification in stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Good signature"),
        "gpg should verify the inline signature, got stderr:\n{}",
        stderr,
    );
}
