//! Streaming file operations for CypherAir.
//!
//! All functions use constant-memory I/O via manual copy loops with `Zeroizing<Vec<u8>>`
//! buffers. `std::io::copy` is intentionally avoided because its internal 8 KiB stack
//! buffer is not zeroized. `BufReader`/`BufWriter` are also avoided for the same reason.
//!
//! SECURITY INVARIANTS:
//! - All intermediate plaintext buffers are `Zeroizing<Vec<u8>>` (auto-zeroized on drop).
//! - `decrypt_file` writes to a `.tmp` file first; on any error, `secure_delete_file`
//!   removes the temp file. Only on full success is the temp renamed to the final path.
//!   This enforces the AEAD hard-fail requirement.
//! - Cancellation via `ProgressReporter::on_progress() → false` returns
//!   `PgpError::OperationCancelled` and cleans up partial output.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::sync::Arc;

use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use crate::decrypt::{
    classify_decrypt_error, is_expired_error, parse_verification_certs, DecryptHelper,
    SignatureStatus,
};
use crate::encrypt;
use crate::error::PgpError;
use crate::sign;
use crate::signature_details::{
    state_from_legacy_status, FileDecryptDetailedResult, FileVerifyDetailedResult,
};
use crate::verify::{VerifyHelper, VerifyResult};

/// Buffer size for streaming copy operations.
const STREAM_BUFFER_SIZE: usize = 64 * 1024; // 64 KB

// ── Progress Reporting ─────────────────────────────────────────────────

/// Foreign trait for progress reporting across the FFI boundary.
/// Swift implements this to receive progress updates and support cancellation.
///
/// Return `false` from `on_progress` to cancel the operation.
#[uniffi::export(with_foreign)]
pub trait ProgressReporter: Send + Sync {
    /// Report progress during a streaming operation.
    ///
    /// - `bytes_processed`: Total bytes processed so far.
    /// - `total_bytes`: Total expected bytes (from file metadata). May be 0 if unknown.
    /// - Returns: `true` to continue, `false` to cancel.
    fn on_progress(&self, bytes_processed: u64, total_bytes: u64) -> bool;
}

/// Wrapper around a `Read` that reports progress and supports cancellation.
struct ProgressReader<R: Read> {
    inner: R,
    bytes_read: u64,
    total_bytes: u64,
    reporter: Option<Arc<dyn ProgressReporter>>,
}

impl<R: Read> ProgressReader<R> {
    fn new(inner: R, total_bytes: u64, reporter: Option<Arc<dyn ProgressReporter>>) -> Self {
        Self {
            inner,
            bytes_read: 0,
            total_bytes,
            reporter,
        }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;

        if let Some(ref reporter) = self.reporter {
            let should_continue = reporter.on_progress(self.bytes_read, self.total_bytes);
            if !should_continue {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    StreamingCancelled,
                ));
            }
        }

        Ok(n)
    }
}

/// Marker error for streaming-operation cancellation.
///
/// Some downstream readers transparently retry `io::ErrorKind::Interrupted`, so
/// cancellation must use a distinct non-retryable error type.
#[derive(Debug)]
struct StreamingCancelled;

impl fmt::Display for StreamingCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Operation cancelled by user")
    }
}

impl std::error::Error for StreamingCancelled {}

/// Reader used only for detached file verification.
///
/// Unlike `ProgressReader`, cancellation is surfaced as a non-retryable error so that
/// `buffered-reader` does not transparently retry reads and hang the operation.
struct DetachedVerifyProgressReader<R: Read> {
    inner: R,
    bytes_read: u64,
    total_bytes: u64,
    reporter: Option<Arc<dyn ProgressReporter>>,
}

impl<R: Read> DetachedVerifyProgressReader<R> {
    fn new(inner: R, total_bytes: u64, reporter: Option<Arc<dyn ProgressReporter>>) -> Self {
        Self {
            inner,
            bytes_read: 0,
            total_bytes,
            reporter,
        }
    }
}

impl<R: Read> Read for DetachedVerifyProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;

        if let Some(ref reporter) = self.reporter {
            let should_continue = reporter.on_progress(self.bytes_read, self.total_bytes);
            if !should_continue {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    StreamingCancelled,
                ));
            }
        }

        Ok(n)
    }
}

// ── Zeroing Copy Utilities ─────────────────────────────────────────────

/// Internal error type for zeroing_copy that preserves the original io::Error
/// from the reader, allowing callers to extract and reclassify decryption errors.
#[derive(Debug)]
enum CopyError {
    /// Read error — preserves the original io::Error (may wrap Sequoia anyhow::Error)
    Read(std::io::Error),
    /// Write error — preserves the original io::Error
    Write(std::io::Error),
    /// Operation cancelled by user (progress callback returned false)
    Cancelled,
}

/// Copy data from `reader` to `writer` using a zeroizing buffer.
///
/// Unlike `std::io::copy`, the internal buffer is guaranteed to be zeroized on drop
/// (including panic/early-return paths) via `Zeroizing<Vec<u8>>`.
///
/// Returns `CopyError` instead of `PgpError` to preserve the original `io::Error`
/// from the reader. This is critical for `decrypt_file`, where Sequoia's Decryptor
/// wraps decryption errors (AEAD/MDC) as `io::Error`. Callers can extract the inner
/// error via `io::Error::into_inner()` and reclassify it using `classify_decrypt_error()`.
fn zeroing_copy<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
) -> Result<u64, CopyError> {
    let mut buf = Zeroizing::new(vec![0u8; buf_size]);
    let mut total: u64 = 0;

    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted
                || e.get_ref()
                    .and_then(|inner| inner.downcast_ref::<StreamingCancelled>())
                    .is_some()
            {
                CopyError::Cancelled
            } else {
                CopyError::Read(e)
            }
        })?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).map_err(CopyError::Write)?;
        total += n as u64;
    }

    Ok(total)
}

/// Map detached file verify runtime errors that originate from the streaming reader.
///
/// Detached verification failures are graded results, but file-read failures and user
/// cancellation must still surface as hard errors instead of collapsing to `Bad`.
fn classify_detached_verify_reader_error(error: &openpgp::anyhow::Error) -> Option<PgpError> {
    for cause in error.chain() {
        if cause.downcast_ref::<StreamingCancelled>().is_some() {
            return Some(PgpError::OperationCancelled);
        }
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            if io_error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<StreamingCancelled>())
                .is_some()
            {
                return Some(PgpError::OperationCancelled);
            }
            return Some(PgpError::FileIoError {
                reason: format!("Read failed: {io_error}"),
            });
        }
    }

    None
}
// ── Secure File Deletion ───────────────────────────────────────────────

/// Overwrite file contents with zeros before deleting.
///
/// NOTE: APFS is copy-on-write, so zero-overwrite does not guarantee physical sector
/// erasure. This provides defense-in-depth matching the in-memory zeroize guarantee
/// level — data is overwritten at the logical level even if physical blocks persist
/// briefly until TRIM/garbage collection.
fn secure_delete_file(path: &std::path::Path) {
    // Best-effort: if any step fails, still try to remove the file.
    if let Ok(metadata) = fs::metadata(path) {
        let size = metadata.len();
        if size > 0 {
            if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
                // Stack-allocated zero buffer — writing zeros, no sensitive data.
                let buf = [0u8; 8192];
                let mut remaining = size;
                while remaining > 0 {
                    let to_write = std::cmp::min(remaining, buf.len() as u64) as usize;
                    if file.write_all(&buf[..to_write]).is_err() {
                        break;
                    }
                    remaining -= to_write as u64;
                }
                let _ = file.sync_all();
            }
        }
    }
    let _ = fs::remove_file(path);
}

// ── File Decrypt Result ────────────────────────────────────────────────

/// Result of streaming file decryption.
/// Contains signature verification info (plaintext is written to output file, not returned).
#[derive(uniffi::Record)]
pub struct FileDecryptResult {
    /// Signature verification status, if the message was signed.
    pub signature_status: Option<SignatureStatus>,
    /// Fingerprint of the signing key, if signed and key is known.
    pub signer_fingerprint: Option<String>,
}

// ── Streaming File Operations ──────────────────────────────────────────

/// Encrypt a file using streaming I/O. Constant memory usage.
///
/// Output format is binary (.gpg, no ASCII armor) for file encryption.
/// Message format is auto-selected by recipient key versions (same rules as `encrypt()`).
pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    recipient_certs: &[Vec<u8>],
    signing_key: Option<&[u8]>,
    encrypt_to_self: Option<&[u8]>,
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<(), PgpError> {
    let policy = StandardPolicy::new();

    // Validate and collect recipients
    let certs = encrypt::collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = encrypt::build_recipients(&certs, &policy);

    // Open input file and get size for progress
    let input_file = File::open(input_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot open input file '{}': {e}", input_path),
    })?;
    let total_bytes = input_file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut progress_reader = ProgressReader::new(input_file, total_bytes, progress);

    // Open output file
    let output_file = File::create(output_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot create output file '{}': {e}", output_path),
    })?;

    // Build the Sequoia message pipeline: output → encryptor → [signer] → literal writer
    let message = Message::new(output_file);

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;

    let message = encrypt::setup_signer(message, signing_key, &policy)?;

    let mut literal =
        LiteralWriter::new(message)
            .build()
            .map_err(|e| PgpError::EncryptionFailed {
                reason: format!("Literal writer setup failed: {e}"),
            })?;

    // Stream data through the pipeline with progress reporting
    if let Err(e) = zeroing_copy(&mut progress_reader, &mut literal, STREAM_BUFFER_SIZE) {
        // Clean up partial output on error
        drop(literal);
        secure_delete_file(std::path::Path::new(output_path));
        return Err(match e {
            CopyError::Read(io_err) => PgpError::EncryptionFailed {
                reason: format!("Read failed: {io_err}"),
            },
            CopyError::Write(io_err) => PgpError::EncryptionFailed {
                reason: format!("Write failed: {io_err}"),
            },
            CopyError::Cancelled => PgpError::OperationCancelled,
        });
    }

    // Finalize the pipeline (flushes encryption/signature)
    literal.finalize().map_err(|e| {
        secure_delete_file(std::path::Path::new(output_path));
        PgpError::EncryptionFailed {
            reason: format!("Finalize failed: {e}"),
        }
    })?;

    Ok(())
}

/// Decrypt a file using streaming I/O. Phase 2 — requires authenticated key access.
///
/// SECURITY: Writes to a `.tmp` file first. If ANY error occurs (AEAD failure, MDC failure,
/// cancellation, I/O error), the temp file is securely deleted. The output file is only
/// created by renaming the temp file after full successful decryption + verification.
/// This enforces the AEAD hard-fail requirement: no partial plaintext on auth failure.
pub fn decrypt_file<K: AsRef<[u8]>>(
    input_path: &str,
    output_path: &str,
    secret_keys: &[K],
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<FileDecryptResult, PgpError> {
    let detailed = decrypt_file_detailed(
        input_path,
        output_path,
        secret_keys,
        verification_keys,
        progress,
    )?;
    Ok(FileDecryptResult {
        signature_status: Some(detailed.legacy_status),
        signer_fingerprint: detailed.legacy_signer_fingerprint,
    })
}

/// Decrypt a file using streaming I/O and preserve detailed per-signature results.
pub fn decrypt_file_detailed<K: AsRef<[u8]>>(
    input_path: &str,
    output_path: &str,
    secret_keys: &[K],
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<FileDecryptDetailedResult, PgpError> {
    let policy = StandardPolicy::new();

    // Parse secret key certificates
    let mut certs = Vec::new();
    for key_data in secret_keys {
        let cert =
            openpgp::Cert::from_bytes(key_data.as_ref()).map_err(|e| PgpError::InvalidKeyData {
                reason: format!("Invalid secret key: {e}"),
            })?;
        certs.push(cert);
    }

    // Parse verification key certificates
    let mut verifier_certs = Vec::new();
    for key_data in verification_keys {
        let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Invalid verification key: {e}"),
        })?;
        verifier_certs.push(cert);
    }

    // Open input file with progress reporting
    let input_file = File::open(input_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot open input file '{}': {e}", input_path),
    })?;
    let total_bytes = input_file.metadata().map(|m| m.len()).unwrap_or(0);
    let progress_reader = ProgressReader::new(input_file, total_bytes, progress);

    // Construct the decryption helper
    let helper = DecryptHelper {
        policy: &policy,
        secret_certs: &certs,
        verifier_certs: &verifier_certs,
        collector: crate::signature_details::SignatureCollector::new(
            crate::signature_details::LegacyFoldMode::DecryptLike,
        ),
    };

    // Build decryptor from file reader
    let mut decryptor = DecryptorBuilder::from_reader(progress_reader)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?
        .with_policy(&policy, None, helper)
        .map_err(|e| classify_decrypt_error(e))?;

    // Write to temp file first (AEAD hard-fail: no partial plaintext).
    // Use a random suffix to prevent predictable temp file paths (M3 fix).
    let mut random_bytes = [0u8; 8];
    openpgp::crypto::random(&mut random_bytes).map_err(|e| PgpError::InternalError {
        reason: format!("Random generation failed: {e}"),
    })?;
    let hex_suffix: String = random_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let temp_path = format!("{output_path}.{hex_suffix}.tmp");
    let temp_path_ref = std::path::Path::new(&temp_path);

    let mut temp_file = File::create(&temp_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot create temp file '{}': {e}", temp_path),
    })?;

    // Stream decrypted data to temp file using zeroing copy.
    // CopyError preserves the original io::Error so we can extract and reclassify
    // Sequoia decryption errors (AEAD/MDC/wrong-key) that are wrapped inside io::Error
    // by the Decryptor's Read impl. This is the core fix for security finding M2.
    if let Err(e) = zeroing_copy(&mut decryptor, &mut temp_file, STREAM_BUFFER_SIZE) {
        drop(temp_file);
        secure_delete_file(temp_path_ref);
        return Err(match e {
            CopyError::Read(io_err) => {
                // Sequoia's Decryptor wraps decryption errors (anyhow::Error) inside
                // io::Error via io::Error::new(). Convert to anyhow::Error and pass to
                // classify_decrypt_error, which already handles unwrapping io::Error
                // layers (Strategy 1b) to find the inner openpgp::Error.
                classify_decrypt_error(openpgp::anyhow::Error::from(io_err))
            }
            CopyError::Write(io_err) => PgpError::FileIoError {
                reason: format!("Write failed: {io_err}"),
            },
            CopyError::Cancelled => PgpError::OperationCancelled,
        });
    }

    // Flush temp file
    temp_file.sync_all().map_err(|e| {
        secure_delete_file(temp_path_ref);
        PgpError::FileIoError {
            reason: format!("Sync failed: {e}"),
        }
    })?;
    drop(temp_file);

    // Extract signature verification results
    let helper = decryptor.into_helper();

    // Rename temp → final output (atomic on same filesystem)
    fs::rename(&temp_path, output_path).map_err(|e| {
        secure_delete_file(temp_path_ref);
        PgpError::FileIoError {
            reason: format!("Cannot rename temp to output: {e}"),
        }
    })?;

    let (legacy_status, legacy_signer_fingerprint, summary_state, summary_entry_index, signatures) =
        helper.collector.into_parts();

    Ok(FileDecryptDetailedResult {
        legacy_status,
        legacy_signer_fingerprint,
        summary_state,
        summary_entry_index,
        signatures,
    })
}

/// Create a detached signature for a file using streaming I/O.
/// Returns the ASCII-armored signature (small, in memory).
pub fn sign_detached_file(
    input_path: &str,
    signer_cert: &[u8],
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let signing_keypair = sign::extract_signing_keypair(signer_cert, &policy)?;

    // Open input file with progress reporting
    let input_file = File::open(input_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot open input file '{}': {e}", input_path),
    })?;
    let total_bytes = input_file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut progress_reader = ProgressReader::new(input_file, total_bytes, progress);

    // Build the signer pipeline
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);

    let message = openpgp::serialize::stream::Armorer::new(message)
        .kind(openpgp::armor::Kind::Signature)
        .build()
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Armor setup failed: {e}"),
        })?;

    let mut signer = openpgp::serialize::stream::Signer::new(message, signing_keypair)
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Signer setup failed: {e}"),
        })?
        .detached()
        .build()
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Signer setup failed: {e}"),
        })?;

    // Stream file data through the signer
    if let Err(e) = zeroing_copy(&mut progress_reader, &mut signer, STREAM_BUFFER_SIZE) {
        return Err(match e {
            CopyError::Read(io_err) => PgpError::SigningFailed {
                reason: format!("Read failed: {io_err}"),
            },
            CopyError::Write(io_err) => PgpError::SigningFailed {
                reason: format!("Write failed: {io_err}"),
            },
            CopyError::Cancelled => PgpError::OperationCancelled,
        });
    }

    signer.finalize().map_err(|e| PgpError::SigningFailed {
        reason: format!("Finalize failed: {e}"),
    })?;

    Ok(sink)
}

/// Verify a detached signature against a file using streaming I/O.
/// The signature is small and passed in-memory; the data file is streamed.
pub fn verify_detached_file(
    data_path: &str,
    signature: &[u8],
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<VerifyResult, PgpError> {
    let policy = StandardPolicy::new();
    let certs = parse_verification_certs(verification_keys)?;

    let helper = VerifyHelper::new(&certs);

    // Build the detached verifier from the signature bytes
    let verifier_result = DetachedVerifierBuilder::from_bytes(signature)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse signature: {e}"),
        })?
        .with_policy(&policy, None, helper);

    // Graded result: if with_policy() fails, inspect the error before defaulting to Bad.
    let mut verifier = match verifier_result {
        Ok(v) => v,
        Err(e) => {
            let status = if is_expired_error(&e) {
                SignatureStatus::Expired
            } else {
                SignatureStatus::Bad
            };
            return Ok(VerifyResult {
                status,
                signer_fingerprint: None,
                content: None,
            });
        }
    };

    // Open data file with progress reporting
    let data_file = File::open(data_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot open data file '{}': {e}", data_path),
    })?;
    let total_bytes = data_file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut progress_reader = DetachedVerifyProgressReader::new(data_file, total_bytes, progress);

    // Verify by streaming the data through the verifier
    if let Err(error) = verifier.verify_reader(&mut progress_reader) {
        if let Some(classified) = classify_detached_verify_reader_error(&error) {
            return Err(classified);
        }

        let helper = verifier.into_helper();
        return Ok(VerifyResult {
            status: SignatureStatus::Bad,
            signer_fingerprint: helper.collector.legacy_signer_fingerprint(),
            content: None,
        });
    }

    let helper = verifier.into_helper();

    Ok(VerifyResult {
        status: helper.collector.legacy_status(),
        signer_fingerprint: helper.collector.legacy_signer_fingerprint(),
        content: None,
    })
}

/// Verify a detached signature against a file using streaming I/O and preserve details.
pub fn verify_detached_file_detailed(
    data_path: &str,
    signature: &[u8],
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<FileVerifyDetailedResult, PgpError> {
    let policy = StandardPolicy::new();
    let certs = parse_verification_certs(verification_keys)?;
    let helper = VerifyHelper::new(&certs);

    let verifier_result = DetachedVerifierBuilder::from_bytes(signature)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse signature: {e}"),
        })?
        .with_policy(&policy, None, helper);

    // Match the current early-setup grading: no observed per-signature results means
    // an empty detailed array and a legacy Bad/Expired status.
    let mut verifier = match verifier_result {
        Ok(v) => v,
        Err(e) => {
            let status = if is_expired_error(&e) {
                SignatureStatus::Expired
            } else {
                SignatureStatus::Bad
            };
            return Ok(FileVerifyDetailedResult {
                legacy_status: status.clone(),
                legacy_signer_fingerprint: None,
                summary_state: state_from_legacy_status(&status),
                summary_entry_index: None,
                signatures: Vec::new(),
            });
        }
    };

    let data_file = File::open(data_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot open data file '{}': {e}", data_path),
    })?;
    let total_bytes = data_file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut progress_reader = DetachedVerifyProgressReader::new(data_file, total_bytes, progress);

    if let Err(error) = verifier.verify_reader(&mut progress_reader) {
        if let Some(classified) = classify_detached_verify_reader_error(&error) {
            return Err(classified);
        }

        let helper = verifier.into_helper();
        return Ok(FileVerifyDetailedResult {
            legacy_status: SignatureStatus::Bad,
            legacy_signer_fingerprint: helper.collector.legacy_signer_fingerprint(),
            summary_state: helper.collector.summary_state(),
            summary_entry_index: helper.collector.summary_entry_index(),
            signatures: helper.collector.signatures(),
        });
    }

    let helper = verifier.into_helper();
    let (legacy_status, legacy_signer_fingerprint, summary_state, summary_entry_index, signatures) =
        helper.collector.into_parts();

    Ok(FileVerifyDetailedResult {
        legacy_status,
        legacy_signer_fingerprint,
        summary_state,
        summary_entry_index,
        signatures,
    })
}

/// Match PKESK recipients from an encrypted file against local certificates.
/// Returns primary fingerprints of matching certificates (lowercase hex).
///
/// This is Phase 1 — reads only PKESK headers, does not decrypt.
/// No secret keys or authentication needed.
/// Handles both binary and ASCII-armored input transparently via `PacketParserBuilder::dearmor`.
pub fn match_recipients_from_file(
    input_path: &str,
    local_certs: &[Vec<u8>],
) -> Result<Vec<String>, PgpError> {
    let policy = StandardPolicy::new();

    // Open file — PacketParserBuilder with dearmor handles both binary and armored input
    let file = File::open(input_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot open file '{}': {e}", input_path),
    })?;

    // Parse PKESK recipients as KeyHandle values
    let mut pkesk_recipients: Vec<openpgp::KeyHandle> = Vec::new();
    let mut ppr = openpgp::parse::PacketParserBuilder::from_reader(file)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?
        .dearmor(openpgp::parse::Dearmor::Auto(Default::default()))
        .build()
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?;

    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        match pp.packet {
            openpgp::Packet::PKESK(ref pkesk) => {
                if let Some(rid) = pkesk.recipient() {
                    pkesk_recipients.push(rid.clone());
                }
            }
            // Stop after we've seen all PKESKs (they come before the encrypted data).
            openpgp::Packet::SEIP(_) => {
                break;
            }
            _ => {}
        }
        let (_, next) = pp.recurse().map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?;
        ppr = next;
    }

    if pkesk_recipients.is_empty() {
        return Err(PgpError::CorruptData {
            reason: "No recipients found in message".to_string(),
        });
    }

    // Parse local certificates (silently skip unparseable ones)
    let mut local_parsed = Vec::new();
    for cert_data in local_certs {
        if let Ok(cert) = openpgp::Cert::from_bytes(cert_data) {
            local_parsed.push(cert);
        }
    }

    // Match: for each local cert, check if any of its encryption subkeys match a PKESK recipient.
    let mut matched_fingerprints: Vec<String> = Vec::new();
    for cert in &local_parsed {
        let primary_fp = cert.fingerprint().to_hex().to_lowercase();
        if matched_fingerprints.contains(&primary_fp) {
            continue;
        }
        for rid in &pkesk_recipients {
            let has_match = cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .key_handles(std::iter::once(rid))
                .for_transport_encryption()
                .next()
                .is_some();
            if has_match {
                matched_fingerprints.push(primary_fp);
                break;
            }
        }
    }

    if matched_fingerprints.is_empty() {
        return Err(PgpError::NoMatchingKey);
    }

    Ok(matched_fingerprints)
}
