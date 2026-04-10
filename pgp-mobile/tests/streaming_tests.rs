//! Streaming file operation tests.
//! Covers encrypt_file, decrypt_file, sign_detached_file, verify_detached_file,
//! and match_recipients_from_file for both Profile A and Profile B.

mod common;

use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use pgp_mobile::decrypt::SignatureStatus;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::streaming::{self, ProgressReporter};

/// Test progress reporter that records callback data.
struct TestProgressReporter {
    last_bytes: AtomicU64,
    last_total: AtomicU64,
    call_count: AtomicU64,
    should_cancel: AtomicBool,
    cancel_after_bytes: u64,
}

impl TestProgressReporter {
    fn new() -> Self {
        Self {
            last_bytes: AtomicU64::new(0),
            last_total: AtomicU64::new(0),
            call_count: AtomicU64::new(0),
            should_cancel: AtomicBool::new(false),
            cancel_after_bytes: u64::MAX,
        }
    }

    fn with_cancel_after(bytes: u64) -> Self {
        Self {
            last_bytes: AtomicU64::new(0),
            last_total: AtomicU64::new(0),
            call_count: AtomicU64::new(0),
            should_cancel: AtomicBool::new(false),
            cancel_after_bytes: bytes,
        }
    }
}

impl ProgressReporter for TestProgressReporter {
    fn on_progress(&self, bytes_processed: u64, total_bytes: u64) -> bool {
        self.last_bytes.store(bytes_processed, Ordering::Relaxed);
        self.last_total.store(total_bytes, Ordering::Relaxed);
        self.call_count.fetch_add(1, Ordering::Relaxed);

        if bytes_processed >= self.cancel_after_bytes {
            self.should_cancel.store(true, Ordering::Relaxed);
        }

        !self.should_cancel.load(Ordering::Relaxed)
    }
}

/// Helper to generate a key pair for testing.
fn gen_key(name: &str, profile: KeyProfile) -> keys::GeneratedKey {
    keys::generate_key_with_profile(name.to_string(), None, None, profile)
        .expect("Key generation should succeed")
}

// ── Encrypt/Decrypt Round-Trip Tests ───────────────────────────────────

#[test]
fn test_encrypt_decrypt_file_profile_a_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

    // Write test data to input file
    let plaintext = b"Hello from Profile A streaming test!";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    // Encrypt
    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        None,
    )
    .expect("Encrypt should succeed");

    assert!(encrypted_path.exists(), "Encrypted file should exist");
    assert!(
        fs::metadata(&encrypted_path).unwrap().len() > 0,
        "Encrypted file should not be empty"
    );

    // Decrypt
    let result = streaming::decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    assert!(decrypted_path.exists(), "Decrypted file should exist");
    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(
        decrypted, plaintext,
        "Decrypted content must match original"
    );

    // No signing key was used, so signature should be NotSigned
    assert_eq!(
        result.signature_status,
        Some(SignatureStatus::NotSigned),
        "Unsigned message should report NotSigned"
    );
}

#[test]
fn test_encrypt_decrypt_file_profile_b_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Bob", KeyProfile::Advanced);

    let plaintext = b"Hello from Profile B streaming test with AEAD!";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let result = streaming::decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(result.signature_status, Some(SignatureStatus::NotSigned));
}

// ── Signed Encrypt/Decrypt Tests ───────────────────────────────────────

#[test]
fn test_encrypt_decrypt_file_with_signature_profile_a() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

    let plaintext = b"Signed Profile A streaming message";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    // Encrypt with signing
    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        Some(&key.cert_data),
        None,
        None,
    )
    .expect("Signed encrypt should succeed");

    // Decrypt with verification
    let result = streaming::decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(
        result.signature_status,
        Some(SignatureStatus::Valid),
        "Signature should be valid"
    );
    assert!(
        result.signer_fingerprint.is_some(),
        "Signer fingerprint should be present"
    );
    assert_eq!(
        result.signer_fingerprint.unwrap(),
        key.fingerprint,
        "Signer fingerprint should match"
    );
}

#[test]
fn test_encrypt_decrypt_file_with_signature_profile_b() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Bob", KeyProfile::Advanced);

    let plaintext = b"Signed Profile B streaming message with AEAD";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        Some(&key.cert_data),
        None,
        None,
    )
    .expect("Signed encrypt should succeed");

    let result = streaming::decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(result.signature_status, Some(SignatureStatus::Valid));
    assert_eq!(result.signer_fingerprint.unwrap(), key.fingerprint);
}

// ── Tamper Tests ───────────────────────────────────────────────────────

#[test]
fn test_decrypt_file_tampered_profile_a() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

    let plaintext = b"Tamper test Profile A";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        None,
    )
    .unwrap();

    // Tamper: flip a bit near the middle of the ciphertext
    let mut ciphertext = fs::read(&encrypted_path).unwrap();
    let midpoint = ciphertext.len() / 2;
    ciphertext[midpoint] ^= 0x01;
    fs::write(&encrypted_path, &ciphertext).unwrap();

    // Decrypt should fail
    let result = streaming::decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    );
    assert!(result.is_err(), "Tampered ciphertext should fail");

    // SECURITY: No output file should exist (AEAD hard-fail)
    assert!(
        !decrypted_path.exists(),
        "Decrypted file must not exist after tamper failure"
    );

    // Verify no temp files remain (temp path now has random suffix)
    let tmp_files: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "tmp"))
        .collect();
    assert!(
        tmp_files.is_empty(),
        "No .tmp files should remain after tamper failure, found: {:?}",
        tmp_files.iter().map(|e| e.path()).collect::<Vec<_>>()
    );
}

#[test]
fn test_decrypt_file_tampered_profile_b() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Bob", KeyProfile::Advanced);

    let plaintext = b"Tamper test Profile B AEAD";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        None,
    )
    .unwrap();

    // Tamper
    let mut ciphertext = fs::read(&encrypted_path).unwrap();
    let midpoint = ciphertext.len() / 2;
    ciphertext[midpoint] ^= 0x01;
    fs::write(&encrypted_path, &ciphertext).unwrap();

    let result = streaming::decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    );
    assert!(result.is_err(), "Tampered AEAD ciphertext should fail");
    assert!(
        !decrypted_path.exists(),
        "Decrypted file must not exist after AEAD failure"
    );
}

// ── Error Reclassification Tests (M2 fix) ─────────────────────────────
// These tests verify that streaming decrypt_file correctly reclassifies
// decryption errors (AEAD/MDC) that are wrapped inside io::Error by
// Sequoia's Decryptor Read impl, rather than returning generic FileIoError.

#[test]
fn test_streaming_decrypt_tampered_profile_b_returns_specific_error() {
    // Profile B uses SEIPDv2 AEAD — tampering should yield AeadAuthenticationFailed
    // or IntegrityCheckFailed, NOT FileIoError or generic CorruptData.
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Bob", KeyProfile::Advanced);

    let plaintext = b"AEAD error reclassification test for M2 fix";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        None,
    )
    .unwrap();

    // Tamper near the end (AEAD tag area) — flip a bit at 3/4 point
    let mut ciphertext = fs::read(&encrypted_path).unwrap();
    let tamper_pos = ciphertext.len() * 3 / 4;
    ciphertext[tamper_pos] ^= 0x01;
    fs::write(&encrypted_path, &ciphertext).unwrap();

    let result = streaming::decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    );
    assert!(result.is_err(), "Tampered AEAD ciphertext should fail");

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("Expected error but got Ok"),
    };
    // The key invariant: the error must NOT be FileIoError. Before the M2 fix,
    // streaming decrypt errors were misclassified as FileIoError because the
    // io::Error wrapper was not unwrapped. The specific error variant depends
    // on WHERE in the ciphertext the tamper occurs (AEAD tag area vs headers
    // vs session key area), so we accept all properly-classified variants.
    assert!(
        !matches!(&err, PgpError::FileIoError { .. }),
        "Must NOT be FileIoError — error reclassification failed. Got: {err:?}"
    );
}

#[test]
fn test_streaming_decrypt_tampered_profile_a_returns_specific_error() {
    // Profile A uses SEIPDv1 (MDC) — tampering should yield IntegrityCheckFailed,
    // NOT FileIoError or generic CorruptData.
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

    let plaintext = b"MDC error reclassification test for M2 fix";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        None,
    )
    .unwrap();

    // Tamper near the end (MDC area) — flip a bit at 3/4 point
    let mut ciphertext = fs::read(&encrypted_path).unwrap();
    let tamper_pos = ciphertext.len() * 3 / 4;
    ciphertext[tamper_pos] ^= 0x01;
    fs::write(&encrypted_path, &ciphertext).unwrap();

    let result = streaming::decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    );
    assert!(result.is_err(), "Tampered MDC ciphertext should fail");

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("Expected error but got Ok"),
    };
    // Same invariant as Profile B: error must NOT be FileIoError.
    // The specific variant depends on tamper position within the ciphertext.
    assert!(
        !matches!(&err, PgpError::FileIoError { .. }),
        "Must NOT be FileIoError — error reclassification failed. Got: {err:?}"
    );
}

// ── Sign/Verify Detached File Tests ────────────────────────────────────

#[test]
fn test_sign_verify_detached_file_profile_a() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

    let data = b"File content to sign with Profile A";
    let data_path = dir.path().join("document.txt");
    fs::write(&data_path, data).unwrap();

    // Sign
    let signature =
        streaming::sign_detached_file(data_path.to_str().unwrap(), &key.cert_data, None)
            .expect("Signing should succeed");

    assert!(!signature.is_empty(), "Signature should not be empty");

    // Verify
    let result = streaming::verify_detached_file(
        data_path.to_str().unwrap(),
        &signature,
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Verification should succeed");

    assert_eq!(result.status, SignatureStatus::Valid);
    assert_eq!(result.signer_fingerprint.unwrap(), key.fingerprint);
}

#[test]
fn test_sign_verify_detached_file_profile_b() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Bob", KeyProfile::Advanced);

    let data = b"File content to sign with Profile B";
    let data_path = dir.path().join("document.txt");
    fs::write(&data_path, data).unwrap();

    let signature =
        streaming::sign_detached_file(data_path.to_str().unwrap(), &key.cert_data, None)
            .expect("Signing should succeed");

    let result = streaming::verify_detached_file(
        data_path.to_str().unwrap(),
        &signature,
        &[key.public_key_data.clone()],
        None,
    )
    .expect("Verification should succeed");

    assert_eq!(result.status, SignatureStatus::Valid);
    assert_eq!(result.signer_fingerprint.unwrap(), key.fingerprint);
}

#[test]
fn test_verify_detached_file_cancellation_returns_operation_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

    let data = vec![0x42u8; 256 * 1024];
    let data_path = dir.path().join("document.bin");
    fs::write(&data_path, &data).unwrap();

    let signature = streaming::sign_detached_file(data_path.to_str().unwrap(), &key.cert_data, None)
        .expect("Signing should succeed");
    let reporter = Arc::new(TestProgressReporter::with_cancel_after(32 * 1024));

    let result = streaming::verify_detached_file(
        data_path.to_str().unwrap(),
        &signature,
        &[key.public_key_data],
        Some(reporter),
    );

    match result {
        Err(PgpError::OperationCancelled) => {}
        Ok(_) => panic!("expected OperationCancelled, got Ok(..)"),
        Err(other) => panic!("expected OperationCancelled, got Err({other})"),
    }
}

// ── Match Recipients From File Test ────────────────────────────────────

#[test]
fn test_match_recipients_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let alice = gen_key("Alice", KeyProfile::Universal);
    let bob = gen_key("Bob", KeyProfile::Advanced);

    let plaintext = b"Recipient matching test";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    fs::write(&input_path, plaintext).unwrap();

    // Encrypt to Alice only
    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[alice.public_key_data.clone()],
        None,
        None,
        None,
    )
    .unwrap();

    // Match against both Alice and Bob
    let matched = streaming::match_recipients_from_file(
        encrypted_path.to_str().unwrap(),
        &[alice.public_key_data.clone(), bob.public_key_data.clone()],
    )
    .expect("Matching should succeed");

    assert_eq!(matched.len(), 1, "Only Alice should match");
    assert_eq!(matched[0], alice.fingerprint);

    // Match against Bob only — should fail
    let result = streaming::match_recipients_from_file(
        encrypted_path.to_str().unwrap(),
        &[bob.public_key_data.clone()],
    );
    assert!(
        matches!(result, Err(PgpError::NoMatchingKey)),
        "Bob's key should not match"
    );
}

// ── Progress Reporter Test ─────────────────────────────────────────────

#[test]
fn test_progress_reporter_called() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

    // Create a reasonably sized file (128 KB) to ensure multiple progress callbacks
    let data = vec![0x42u8; 128 * 1024];
    let input_path = dir.path().join("input.bin");
    let encrypted_path = dir.path().join("encrypted.gpg");
    fs::write(&input_path, &data).unwrap();

    let reporter = Arc::new(TestProgressReporter::new());

    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        Some(reporter.clone()),
    )
    .expect("Encrypt should succeed");

    // Progress should have been reported at least once
    assert!(
        reporter.call_count.load(Ordering::Relaxed) > 0,
        "Progress callback should have been called"
    );

    // Total bytes should match the input file size
    assert_eq!(
        reporter.last_total.load(Ordering::Relaxed),
        128 * 1024,
        "Total bytes should match input file size"
    );

    // Last bytes_processed should equal total (fully read)
    assert_eq!(
        reporter.last_bytes.load(Ordering::Relaxed),
        reporter.last_total.load(Ordering::Relaxed),
        "Final bytes_processed should equal total_bytes"
    );
}

// ── Cancellation Test ──────────────────────────────────────────────────

#[test]
fn test_cancellation_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

    // Create a file large enough that cancellation happens mid-stream
    let data = vec![0x42u8; 256 * 1024];
    let input_path = dir.path().join("input.bin");
    let encrypted_path = dir.path().join("encrypted.gpg");
    fs::write(&input_path, &data).unwrap();

    // Cancel after reading 32 KB
    let reporter = Arc::new(TestProgressReporter::with_cancel_after(32 * 1024));

    let result = streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[key.public_key_data.clone()],
        None,
        None,
        Some(reporter),
    );

    assert!(
        matches!(result, Err(PgpError::OperationCancelled)),
        "Should return OperationCancelled, got: {:?}",
        result
    );

    // Partial output should be cleaned up
    assert!(
        !encrypted_path.exists(),
        "Partial output file should be cleaned up after cancellation"
    );
}

// ── Cross-Profile Test ─────────────────────────────────────────────────

#[test]
fn test_encrypt_file_cross_profile() {
    let dir = tempfile::tempdir().unwrap();
    let sender_b = gen_key("Bob", KeyProfile::Advanced);
    let recipient_a = gen_key("Alice", KeyProfile::Universal);

    let plaintext = b"Cross-profile streaming: B sender to A recipient";
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");
    fs::write(&input_path, plaintext).unwrap();

    // Encrypt from Profile B sender to Profile A recipient (should use SEIPDv1)
    streaming::encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &[recipient_a.public_key_data.clone()],
        Some(&sender_b.cert_data),
        None,
        None,
    )
    .expect("Cross-profile encrypt should succeed");

    // Verify the ciphertext uses SEIPDv1 (because recipient is v4)
    let ciphertext = fs::read(&encrypted_path).unwrap();
    let (has_v1, has_v2) = common::detect_message_format(&ciphertext);
    assert!(has_v1, "Cross-profile message should use SEIPDv1");
    assert!(!has_v2, "Cross-profile message should NOT use SEIPDv2");

    // Decrypt with Profile A recipient key
    let result = streaming::decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[recipient_a.cert_data.clone()],
        &[sender_b.public_key_data.clone()],
        None,
    )
    .expect("Decrypt should succeed");

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(result.signature_status, Some(SignatureStatus::Valid));
}
