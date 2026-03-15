//! GnuPG Binary Verification Tests.
//!
//! These tests invoke the actual `gpg` binary to verify that GnuPG can correctly
//! process Cypher Air's (Sequoia-generated) output. This complements the existing
//! `gnupg_interop_tests.rs` which validates the reverse direction (GnuPG output
//! processed by Sequoia).
//!
//! **Skip behavior:** All tests skip gracefully if `gpg` is not found on the system.
//! They will pass silently (with a printed message) rather than fail, so CI
//! environments without GnuPG installed are not affected.
//!
//! **Isolation:** Each test creates a temporary GNUPGHOME directory. The user's
//! real GnuPG keyring is never touched.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

use pgp_mobile::armor;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::sign;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Search for the `gpg` binary on this system.
/// Checks PATH first, then common Homebrew and system paths.
fn find_gpg() -> Option<PathBuf> {
    // Check PATH via `which`
    if let Ok(output) = Command::new("which").arg("gpg").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    // Check common locations
    let candidates = [
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        "/usr/bin/gpg",
    ];
    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Create a temporary GNUPGHOME with non-interactive configuration.
fn setup_gpg_home() -> TempDir {
    let dir = TempDir::new().expect("Failed to create temp GNUPGHOME");

    // Set directory permissions to 700 (required by gpg)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("Failed to set GNUPGHOME permissions");
    }

    // Write gpg.conf for non-interactive use
    let gpg_conf = dir.path().join("gpg.conf");
    std::fs::write(
        &gpg_conf,
        "no-tty\nbatch\nyes\ntrust-model always\nforce-mdc\n",
    )
    .expect("Failed to write gpg.conf");

    // Write gpg-agent.conf
    let agent_conf = dir.path().join("gpg-agent.conf");
    std::fs::write(&agent_conf, "allow-preset-passphrase\n")
        .expect("Failed to write gpg-agent.conf");

    dir
}

/// Create a `Command` for gpg with the given GNUPGHOME.
fn gpg_cmd(gpg_path: &PathBuf, gnupghome: &TempDir) -> Command {
    let mut cmd = Command::new(gpg_path);
    cmd.env("GNUPGHOME", gnupghome.path());
    cmd.arg("--batch");
    cmd.arg("--yes");
    cmd.arg("--trust-model").arg("always");
    cmd
}

/// Import a key (public or secret) into the temporary gpg keyring.
/// Writes the key data to a temp file, then runs `gpg --import`.
fn gpg_import_key(gpg_path: &PathBuf, gnupghome: &TempDir, key_data: &[u8]) {
    let key_file = gnupghome.path().join("import_key.tmp");
    std::fs::write(&key_file, key_data).expect("Failed to write key file");

    let output = gpg_cmd(gpg_path, gnupghome)
        .arg("--import")
        .arg(&key_file)
        .output()
        .expect("Failed to run gpg --import");

    assert!(
        output.status.success(),
        "gpg --import failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Load a fixture file from the fixtures directory.
fn load_fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to load fixture {}: {}", name, e))
}

/// Macro to skip a test if gpg is not found, printing a message.
macro_rules! require_gpg {
    () => {
        match find_gpg() {
            Some(path) => path,
            None => {
                eprintln!("gpg not found on this system, skipping test");
                return;
            }
        }
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Verify that `gpg --import` accepts a Sequoia-generated Profile A public key.
#[test]
fn test_gpg_imports_sequoia_profile_a_pubkey() {
    let gpg = require_gpg!();
    let gnupghome = setup_gpg_home();

    // Generate a Profile A key with Sequoia
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
        "gpg --import should accept Sequoia Profile A public key.\nstderr: {}",
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

    // Generate a Profile A signing key with Sequoia
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
    let signed = sign::sign_cleartext(message, &signer.cert_data)
        .expect("Cleartext signing should succeed");

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

    // Generate a Profile A signing key
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
    let signature =
        sign::sign_detached(data, &signer.cert_data).expect("Detached signing should succeed");

    // Write data and signature to temp files
    let data_file = gnupghome.path().join("data.txt");
    let sig_file = gnupghome.path().join("data.txt.sig");
    std::fs::write(&data_file, data).expect("Failed to write data file");
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

/// Verify that `gpg --import` rejects a Sequoia-generated Profile B (v6) public key.
/// GnuPG does not support v6 keys — this is the expected behavior.
#[test]
fn test_gpg_rejects_sequoia_profile_b_pubkey() {
    let gpg = require_gpg!();
    let gnupghome = setup_gpg_home();

    // Generate a Profile B key with Sequoia
    let key = keys::generate_key_with_profile(
        "Profile B User".to_string(),
        Some("profileb@example.com".to_string()),
        None,
        KeyProfile::Advanced,
    )
    .expect("Key generation should succeed");

    assert_eq!(key.key_version, 6, "Profile B must produce v6 key");

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
        "gpg --import should reject v6 key (Profile B is not GnuPG compatible).\nstderr: {}",
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

    // Generate a Profile A signing key with Sequoia
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
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[gpg_pubkey],
        Some(&signer.cert_data),
        None,
    )
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
