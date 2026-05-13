//! Streaming resilience tests.
//! Covers tamper handling, error reclassification, progress, cancellation,
//! and cleanup behavior for file-based operations.

mod common;

use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

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

fn gen_key(name: &str, profile: KeyProfile) -> keys::GeneratedKey {
    keys::generate_key_with_profile(name.to_string(), None, None, profile)
        .expect("Key generation should succeed")
}

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

    let ciphertext = fs::read(&encrypted_path).unwrap();
    let ciphertext = common::tamper_at_ratio(&ciphertext, 1, 2);
    fs::write(&encrypted_path, &ciphertext).unwrap();

    let result = streaming::decrypt_file_detailed(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &[key.cert_data.clone()],
        &[key.public_key_data.clone()],
        None,
    );
    assert!(result.is_err(), "Tampered ciphertext should fail");
    assert!(
        !decrypted_path.exists(),
        "Decrypted file must not exist after tamper failure"
    );

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

    let ciphertext = fs::read(&encrypted_path).unwrap();
    let ciphertext = common::tamper_at_ratio(&ciphertext, 1, 2);
    fs::write(&encrypted_path, &ciphertext).unwrap();

    let result = streaming::decrypt_file_detailed(
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

#[test]
fn test_streaming_decrypt_tampered_profile_b_returns_specific_error() {
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

    let ciphertext = fs::read(&encrypted_path).unwrap();
    let ciphertext = common::tamper_at_ratio(&ciphertext, 3, 4);
    fs::write(&encrypted_path, &ciphertext).unwrap();

    let result = streaming::decrypt_file_detailed(
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
    assert!(
        !matches!(&err, PgpError::FileIoError { .. }),
        "Must NOT be FileIoError — error reclassification failed. Got: {err:?}"
    );
}

#[test]
fn test_streaming_decrypt_tampered_profile_a_returns_specific_error() {
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

    let ciphertext = fs::read(&encrypted_path).unwrap();
    let ciphertext = common::tamper_at_ratio(&ciphertext, 3, 4);
    fs::write(&encrypted_path, &ciphertext).unwrap();

    let result = streaming::decrypt_file_detailed(
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
    assert!(
        !matches!(&err, PgpError::FileIoError { .. }),
        "Must NOT be FileIoError — error reclassification failed. Got: {err:?}"
    );
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

    let result = streaming::verify_detached_file_detailed(
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

#[test]
fn test_progress_reporter_called() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

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

    assert!(
        reporter.call_count.load(Ordering::Relaxed) > 0,
        "Progress callback should have been called"
    );
    assert_eq!(
        reporter.last_total.load(Ordering::Relaxed),
        128 * 1024,
        "Total bytes should match input file size"
    );
    assert_eq!(
        reporter.last_bytes.load(Ordering::Relaxed),
        reporter.last_total.load(Ordering::Relaxed),
        "Final bytes_processed should equal total_bytes"
    );
}

#[test]
fn test_cancellation_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let key = gen_key("Alice", KeyProfile::Universal);

    let data = vec![0x42u8; 256 * 1024];
    let input_path = dir.path().join("input.bin");
    let encrypted_path = dir.path().join("encrypted.gpg");
    fs::write(&input_path, &data).unwrap();

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
    assert!(
        !encrypted_path.exists(),
        "Partial output file should be cleaned up after cancellation"
    );
}
