//! `sq` (sequoia-sq) live cross-tool interoperability tests.
//!
//! These drive the real `sq` binary for the two directions the committed
//! fixtures cannot prove — sq consuming CypherAir-produced artifacts:
//! - (f) sq imports our secret key and decrypts a message our engine
//!   encrypted to our own certificate;
//! - (g) sq verifies a cleartext signature our engine produced.
//!
//! Every test probes for sq first (`common/sq.rs`) and skips with a note when
//! it is unavailable; the `rust-gnupg-interop` CI job brews sequoia-sq and
//! runs this lane under `CYPHERAIR_REQUIRE_SQ=1`, which forbids skips. The
//! post-quantum tests additionally gate on a functional capability probe —
//! an sq built on pre-2.4 sequoia-openpgp cannot read final RFC 9980
//! artifacts and skips those tests loudly (see `require_pq_capable_sq_or_skip`).
//! Each test uses an isolated `sq --home` inside a temp dir; the user's real
//! cert/key store is never touched, and nothing goes near the network.

use std::path::Path;

use tempfile::TempDir;

use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, GeneratedKey, KeyProfile};
use pgp_mobile::sign;

mod common;
use common::sq::{
    require_pq_capable_sq_or_skip, require_sq_or_skip, run_sq, setup_sq_home, sq_cmd,
};

/// Post-quantum profiles need an sq that reads final RFC 9980 artifacts;
/// classical profiles only need sq present.
fn sq_for(profile: &KeyProfile) -> Option<std::path::PathBuf> {
    match profile {
        KeyProfile::PostQuantum | KeyProfile::PostQuantumHigh => require_pq_capable_sq_or_skip(),
        _ => require_sq_or_skip(),
    }
}

fn generate_engine_key(profile: KeyProfile, label: &str) -> GeneratedKey {
    keys::generate_key_with_profile(
        format!("CypherAir {label} Live"),
        Some(format!(
            "cypherair-{}-live@example.com",
            label.to_lowercase()
        )),
        None,
        profile,
    )
    .expect("engine key generation should succeed")
}

fn write_file(dir: &TempDir, name: &str, data: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, data).expect("temp file should be written");
    path
}

fn read_file(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("output file should be readable")
}

// ── (f) Our engine encrypts → sq decrypts with our imported secret key ─────

fn assert_sq_decrypts_our_message(profile: KeyProfile, label: &str) {
    let Some(sq) = sq_for(&profile) else {
        return;
    };
    let home = setup_sq_home();
    let work = TempDir::new().expect("temp workdir");

    let key = generate_engine_key(profile, label);

    // sq imports our secret key (binary TSK) into its isolated key store.
    let tsk_path = write_file(&work, "engine_key.pgp", &key.cert_data);
    let mut import = sq_cmd(&sq, &home);
    import.arg("key").arg("import").arg(&tsk_path);
    run_sq(import, "key import");

    // Our engine encrypts to our own certificate.
    let plaintext: &[u8] = b"CypherAir encrypts, sq decrypts (live interop).";
    let ciphertext = encrypt::encrypt(plaintext, &[key.public_key_data.clone()], None, None)
        .expect("engine encryption should succeed");
    let ct_path = write_file(&work, "message.asc", &ciphertext);

    // sq decrypts via its key store and must recover the plaintext.
    let out_path = work.path().join("decrypted.txt");
    let mut decrypt = sq_cmd(&sq, &home);
    decrypt
        .arg("decrypt")
        .arg("--output")
        .arg(&out_path)
        .arg(&ct_path);
    run_sq(decrypt, "decrypt");

    assert_eq!(
        read_file(&out_path),
        plaintext,
        "sq must recover the exact plaintext"
    );
}

#[test]
fn test_sq_decrypts_engine_message_legacy() {
    assert_sq_decrypts_our_message(KeyProfile::Universal, "Legacy");
}

#[test]
fn test_sq_decrypts_engine_message_modern() {
    assert_sq_decrypts_our_message(KeyProfile::Modern, "Modern");
}

#[test]
fn test_sq_decrypts_engine_message_modernhigh() {
    assert_sq_decrypts_our_message(KeyProfile::Advanced, "ModernHigh");
}

#[test]
fn test_sq_decrypts_engine_message_pq() {
    assert_sq_decrypts_our_message(KeyProfile::PostQuantum, "PQ");
}

#[test]
fn test_sq_decrypts_engine_message_pqhigh() {
    assert_sq_decrypts_our_message(KeyProfile::PostQuantumHigh, "PQHigh");
}

// ── (g) Our engine signs → sq verifies against our public certificate ──────

fn assert_sq_verifies_our_cleartext_signature(profile: KeyProfile, label: &str) {
    let Some(sq) = sq_for(&profile) else {
        return;
    };
    let home = setup_sq_home();
    let work = TempDir::new().expect("temp workdir");

    let key = generate_engine_key(profile, label);

    let plaintext: &[u8] = b"CypherAir signs, sq verifies (live interop).";
    let signed = sign::sign_cleartext(plaintext, &key.cert_data)
        .expect("engine cleartext signing should succeed");
    let signed_path = write_file(&work, "signed.asc", &signed);
    let cert_path = write_file(&work, "engine_cert.pgp", &key.public_key_data);

    // --signer-file makes the provided certificate the trust anchor, so this
    // is a pure signature-validity check against our exported public cert.
    let out_path = work.path().join("verified.txt");
    let mut verify = sq_cmd(&sq, &home);
    verify
        .arg("verify")
        .arg("--cleartext")
        .arg("--signer-file")
        .arg(&cert_path)
        .arg("--output")
        .arg(&out_path)
        .arg(&signed_path);
    run_sq(verify, "verify --cleartext");

    // The cleartext framework may normalize trailing whitespace; compare
    // trimmed content like the GnuPG cleartext tests do.
    let verified = read_file(&out_path);
    assert_eq!(
        String::from_utf8_lossy(&verified).trim(),
        String::from_utf8_lossy(plaintext).trim(),
        "sq must release the signed content"
    );
}

#[test]
fn test_sq_verifies_engine_signature_legacy() {
    assert_sq_verifies_our_cleartext_signature(KeyProfile::Universal, "Legacy");
}

#[test]
fn test_sq_verifies_engine_signature_modern() {
    assert_sq_verifies_our_cleartext_signature(KeyProfile::Modern, "Modern");
}

#[test]
fn test_sq_verifies_engine_signature_modernhigh() {
    assert_sq_verifies_our_cleartext_signature(KeyProfile::Advanced, "ModernHigh");
}

#[test]
fn test_sq_verifies_engine_signature_pq() {
    assert_sq_verifies_our_cleartext_signature(KeyProfile::PostQuantum, "PQ");
}

#[test]
fn test_sq_verifies_engine_signature_pqhigh() {
    assert_sq_verifies_our_cleartext_signature(KeyProfile::PostQuantumHigh, "PQHigh");
}
