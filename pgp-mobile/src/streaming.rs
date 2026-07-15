//! Streaming file operations for CypherAir.
//!
//! All functions use constant-memory I/O via manual copy loops with `Zeroizing<Vec<u8>>`
//! buffers. `std::io::copy` is intentionally avoided because its internal 8 KiB stack
//! buffer is not zeroized. `BufReader`/`BufWriter` are also avoided for the same reason.
//!
//! SECURITY INVARIANTS:
//! - All intermediate plaintext buffers are `Zeroizing<Vec<u8>>` (auto-zeroized on drop).
//! - `decrypt_file_detailed` writes to a `.tmp` file first; on any error, `secure_delete_file`
//!   removes the temp file. Only on full success is the temp renamed to the final path.
//!   This enforces the AEAD hard-fail requirement.
//! - Cancellation via `StreamingProgressReporter::on_progress() → false` returns
//!   `PgpError::OperationCancelled` and cleans up partial output.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::sync::Arc;

use openpgp::crypto::Signer as CryptoSigner;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use crate::decrypt::{
    classify_decrypt_error, is_expired_error, parse_verification_certs, DecryptHelper,
};
use crate::encrypt;
use crate::error::PgpError;
use crate::external_composite_signer::{
    composite_high_signer_for_provider, composite_signer_for_provider,
};
use crate::external_signer::{map_external_signing_error, signer_for_provider};
use crate::keys::{
    ExternalMlDsa65SigningProvider, ExternalMlDsa87SigningProvider, ExternalP256SigningProvider,
};
use crate::sign;
use crate::signature_details::{
    FileDecryptDetailedResult, FileVerifyDetailedResult, SignatureVerificationState,
};
use crate::verify::VerifyHelper;

/// Buffer size for streaming copy operations.
const STREAM_BUFFER_SIZE: usize = 64 * 1024; // 64 KB

/// Ceiling on decrypted output relative to encrypted input for the streaming
/// file path. Sequoia transparently decompresses an embedded CompressedData
/// packet while writing plaintext to the temp file, so a small crafted input
/// can expand without bound and fill the device volume (storage pressure can
/// jetsam other apps). The effective ceiling is `max(input * ratio, floor)`:
/// the ratio bounds the decompression bomb while the floor lets small
/// legitimate inputs expand fully. DEFLATE's maximum ratio is 1032:1 (only
/// `compression-deflate` is enabled — no bzip2), so 2048 sits safely above any
/// legitimate deflate expansion (a zero-padded file from default GnuPG hits the
/// deflate edge) while still bounding a bomb at ~2 KiB output per input byte.
/// The 256 MiB floor mirrors the in-memory decrypt cap.
const MAX_STREAMING_DECOMPRESSION_RATIO: u64 = 2048;
const MIN_STREAMING_DECRYPT_OUTPUT_CEILING: u64 = 256 * 1024 * 1024;

fn streaming_decrypt_output_ceiling(input_bytes: u64) -> u64 {
    input_bytes
        .saturating_mul(MAX_STREAMING_DECOMPRESSION_RATIO)
        .max(MIN_STREAMING_DECRYPT_OUTPUT_CEILING)
}

// ── Progress Reporting ─────────────────────────────────────────────────

/// Foreign trait for progress reporting across the FFI boundary.
/// Swift implements this to receive progress updates and support cancellation.
///
/// Return `false` from `on_progress` to cancel the operation.
#[uniffi::export(with_foreign)]
pub trait StreamingProgressReporter: Send + Sync {
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
    reporter: Option<Arc<dyn StreamingProgressReporter>>,
}

impl<R: Read> ProgressReader<R> {
    fn new(
        inner: R,
        total_bytes: u64,
        reporter: Option<Arc<dyn StreamingProgressReporter>>,
    ) -> Self {
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
    reporter: Option<Arc<dyn StreamingProgressReporter>>,
}

impl<R: Read> DetachedVerifyProgressReader<R> {
    fn new(
        inner: R,
        total_bytes: u64,
        reporter: Option<Arc<dyn StreamingProgressReporter>>,
    ) -> Self {
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
    /// Decrypted output exceeded the streaming decompression ceiling.
    OutputCeilingExceeded,
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

/// Copy decrypted plaintext to the output file with an output-side ceiling and
/// output-side cancellation.
///
/// The input-side `ProgressReader` only polls cancellation as ciphertext is
/// read. Once a small compressed input is consumed, Sequoia's transparent
/// decompressor emits plaintext with no further input reads, so input-side
/// cancellation goes inert and the progress bar freezes while the temp file
/// grows unbounded. This loop bounds the written output at `max_output_bytes`
/// (fail-closed before the breaching chunk is written, so the temp file never
/// exceeds the ceiling) and re-polls the reporter per chunk so Cancel stays
/// responsive during decompression expansion. Progress is reported as output
/// bytes clamped to `total_bytes`, keeping the bar monotonic and never above
/// 100% for a compressed input.
fn zeroing_copy_decrypt<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
    max_output_bytes: u64,
    total_bytes: u64,
    reporter: Option<&Arc<dyn StreamingProgressReporter>>,
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
        // Fail closed before writing a chunk that would breach the ceiling, so
        // the temp file is never allowed to exceed it.
        if n as u64 > max_output_bytes - total {
            return Err(CopyError::OutputCeilingExceeded);
        }
        writer.write_all(&buf[..n]).map_err(CopyError::Write)?;
        total += n as u64;

        if let Some(reporter) = reporter {
            let processed = total.min(total_bytes);
            if !reporter.on_progress(processed, total_bytes) {
                return Err(CopyError::Cancelled);
            }
        }
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
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<(), PgpError> {
    let policy = StandardPolicy::new();

    // Validate and collect recipients
    let certs = encrypt::collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = encrypt::build_recipients(&certs, &policy);

    let progress_reader = progress_reader_for_file(input_path, progress)?;
    let output_file = output_file_for_path(output_path)?;

    // Build the Sequoia message pipeline: output → encryptor → [signer] → literal writer
    let message = Message::new(output_file);

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| {
            secure_delete_file(std::path::Path::new(output_path));
            PgpError::EncryptionFailed {
                reason: format!("Encryptor setup failed: {e}"),
            }
        })?;

    let message = encrypt::setup_signer(message, signing_key, &policy).map_err(|error| {
        secure_delete_file(std::path::Path::new(output_path));
        error
    })?;

    write_streaming_encrypted_file(
        message,
        progress_reader,
        output_path,
        StreamingFinalizeMode::Software,
    )
}

/// Encrypt a file using a public certificate plus external P-256 signer.
pub fn encrypt_file_with_external_p256_signer(
    input_path: &str,
    output_path: &str,
    recipient_certs: &[Vec<u8>],
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
    encrypt_to_self: Option<&[u8]>,
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<(), PgpError> {
    let policy = StandardPolicy::new();

    let certs = encrypt::collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = encrypt::build_recipients(&certs, &policy);

    let progress_reader = progress_reader_for_file(input_path, progress)?;
    let output_file = output_file_for_path(output_path)?;

    let message = Message::new(output_file);

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| {
            secure_delete_file(std::path::Path::new(output_path));
            PgpError::EncryptionFailed {
                reason: format!("Encryptor setup failed: {e}"),
            }
        })?;

    let message = encrypt::setup_external_p256_signer(
        message,
        signing_public_cert,
        signing_key_fingerprint,
        signer,
        &policy,
    )
    .map_err(|error| {
        secure_delete_file(std::path::Path::new(output_path));
        error
    })?;

    write_streaming_encrypted_file(
        message,
        progress_reader,
        output_path,
        StreamingFinalizeMode::ExternalSigning,
    )
}

/// Encrypt a file using a public certificate plus external split-custody
/// composite signer.
pub fn encrypt_file_with_external_composite_signer(
    input_path: &str,
    output_path: &str,
    recipient_certs: &[Vec<u8>],
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa65SigningProvider>,
    encrypt_to_self: Option<&[u8]>,
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<(), PgpError> {
    let policy = StandardPolicy::new();

    let certs = encrypt::collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = encrypt::build_recipients(&certs, &policy);

    let progress_reader = progress_reader_for_file(input_path, progress)?;
    let output_file = output_file_for_path(output_path)?;

    let message = Message::new(output_file);

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| {
            secure_delete_file(std::path::Path::new(output_path));
            PgpError::EncryptionFailed {
                reason: format!("Encryptor setup failed: {e}"),
            }
        })?;

    let message = encrypt::setup_external_composite_signer(
        message,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        &policy,
    )
    .map_err(|error| {
        secure_delete_file(std::path::Path::new(output_path));
        error
    })?;

    write_streaming_encrypted_file(
        message,
        progress_reader,
        output_path,
        StreamingFinalizeMode::ExternalSigning,
    )
}

/// Device-Bound Post-Quantum · High analog of
/// `encrypt_file_with_external_composite_signer`.
pub fn encrypt_file_with_external_composite_high_signer(
    input_path: &str,
    output_path: &str,
    recipient_certs: &[Vec<u8>],
    signing_public_cert: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa87SigningProvider>,
    encrypt_to_self: Option<&[u8]>,
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<(), PgpError> {
    let policy = StandardPolicy::new();

    let certs = encrypt::collect_recipients(recipient_certs, encrypt_to_self, &policy)?;
    let recipient_keys = encrypt::build_recipients(&certs, &policy);

    let progress_reader = progress_reader_for_file(input_path, progress)?;
    let output_file = output_file_for_path(output_path)?;

    let message = Message::new(output_file);

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| {
            secure_delete_file(std::path::Path::new(output_path));
            PgpError::EncryptionFailed {
                reason: format!("Encryptor setup failed: {e}"),
            }
        })?;

    let message = encrypt::setup_external_composite_high_signer(
        message,
        signing_public_cert,
        signing_key_fingerprint,
        classical_eddsa_secret,
        signer,
        &policy,
    )
    .map_err(|error| {
        secure_delete_file(std::path::Path::new(output_path));
        error
    })?;

    write_streaming_encrypted_file(
        message,
        progress_reader,
        output_path,
        StreamingFinalizeMode::ExternalSigning,
    )
}

fn progress_reader_for_file(
    input_path: &str,
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<ProgressReader<File>, PgpError> {
    let input_file = File::open(input_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot open input file '{}': {e}", input_path),
    })?;
    let total_bytes = input_file.metadata().map(|m| m.len()).unwrap_or(0);
    Ok(ProgressReader::new(input_file, total_bytes, progress))
}

fn output_file_for_path(output_path: &str) -> Result<File, PgpError> {
    File::create(output_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot create output file '{}': {e}", output_path),
    })
}

enum StreamingFinalizeMode {
    Software,
    ExternalSigning,
}

fn write_streaming_encrypted_file(
    message: Message<'_>,
    mut progress_reader: ProgressReader<File>,
    output_path: &str,
    finalize_mode: StreamingFinalizeMode,
) -> Result<(), PgpError> {
    let mut literal = LiteralWriter::new(message).build().map_err(|e| {
        secure_delete_file(std::path::Path::new(output_path));
        PgpError::EncryptionFailed {
            reason: format!("Literal writer setup failed: {e}"),
        }
    })?;

    if let Err(e) = zeroing_copy(&mut progress_reader, &mut literal, STREAM_BUFFER_SIZE) {
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
            // Not producible by zeroing_copy on the encrypt path; mapped
            // defensively rather than panicking.
            CopyError::OutputCeilingExceeded => PgpError::EncryptionFailed {
                reason: "Output exceeded the streaming ceiling".to_string(),
            },
        });
    }

    literal.finalize().map_err(|error| {
        secure_delete_file(std::path::Path::new(output_path));
        match finalize_mode {
            StreamingFinalizeMode::Software => PgpError::EncryptionFailed {
                reason: format!("Finalize failed: {error}"),
            },
            StreamingFinalizeMode::ExternalSigning => {
                map_external_signing_error(error, |reason| PgpError::SigningFailed {
                    reason: format!("Finalize failed: {reason}"),
                })
            }
        }
    })
}

/// Decrypt a file using streaming I/O and preserve detailed per-signature results.
///
/// SECURITY: Writes to a `.tmp` file first. If ANY error occurs (AEAD failure, MDC failure,
/// cancellation, I/O error), the temp file is securely deleted. The output file is only
/// created by renaming the temp file after full successful decryption + verification.
/// This enforces the AEAD hard-fail requirement: no partial plaintext on auth failure.
pub fn decrypt_file_detailed<K: AsRef<[u8]>>(
    input_path: &str,
    output_path: &str,
    secret_keys: &[K],
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn StreamingProgressReporter>>,
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

    // Construct the software recipient-key decryption helper and stream to a
    // success-only output file through the shared streaming machinery.
    let helper = DecryptHelper {
        policy: &policy,
        secret_certs: &certs,
        verifier_certs: &verifier_certs,
        collector: crate::signature_details::SignatureCollector::new(
            crate::signature_details::SummaryFoldMode::DecryptLike,
        ),
    };

    let helper = decrypt_file_with_helper(input_path, output_path, &policy, helper, progress)?;

    let (summary_state, summary_entry_index, signatures) = helper.collector.into_parts();

    Ok(FileDecryptDetailedResult {
        summary_state,
        summary_entry_index,
        signatures,
    })
}

/// Stream-decrypt a file through any `DecryptionHelper`/`VerificationHelper` while
/// preserving the success-only output contract.
///
/// This is the streaming analog of `decrypt::decrypt_with_helper`: the software
/// recipient-key helper (`DecryptHelper`) and the external P-256 key-agreement helper
/// (`external_decryptor::ExternalDecryptHelper`) both share this temp-file machinery.
///
/// SECURITY: Decrypted bytes are written to a randomly-suffixed `.tmp` file and the
/// final output is produced by `fs::rename` ONLY after a full successful decrypt and
/// payload authentication. Any error (AEAD failure, MDC failure, cancellation, I/O
/// error, or an external key-agreement callback failure during session-key
/// acquisition) securely deletes the temp file before returning. No partial plaintext
/// is ever released to the final output path.
pub(crate) fn decrypt_file_with_helper<'a, H>(
    input_path: &str,
    output_path: &str,
    policy: &'a StandardPolicy<'a>,
    helper: H,
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<H, PgpError>
where
    H: VerificationHelper + DecryptionHelper,
{
    // Open input file with progress reporting
    let input_file = File::open(input_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot open input file '{}': {e}", input_path),
    })?;
    let total_bytes = input_file.metadata().map(|m| m.len()).unwrap_or(0);
    let output_ceiling = streaming_decrypt_output_ceiling(total_bytes);
    // Clone the reporter for the output side; the input-side ProgressReader
    // consumes the original. Both share the same foreign reporter, so
    // cancellation is polled on whichever side is active.
    let output_progress = progress.clone();
    let progress_reader = ProgressReader::new(input_file, total_bytes, progress);

    // Build decryptor from file reader. Both stages route through
    // `classify_decrypt_error`: the parse stage can surface a progress-callback
    // cancellation (`StreamingCancelled`) as the first bytes are pulled, and the policy
    // stage runs the helper's `decrypt` callback where session-key acquisition (software
    // `KeyPair` or external P-256 key agreement) happens. Classifying both keeps a
    // user-initiated cancel reported as `OperationCancelled` rather than `CorruptData`,
    // while genuine parse/decrypt failures still map to their fail-closed categories.
    let mut decryptor = DecryptorBuilder::from_reader(progress_reader)
        .map_err(classify_decrypt_error)?
        .with_policy(policy, None, helper)
        .map_err(classify_decrypt_error)?;

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
    if let Err(e) = zeroing_copy_decrypt(
        &mut decryptor,
        &mut temp_file,
        STREAM_BUFFER_SIZE,
        output_ceiling,
        total_bytes,
        output_progress.as_ref(),
    ) {
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
            CopyError::OutputCeilingExceeded => PgpError::CorruptData {
                reason: "Decrypted output exceeds the maximum expansion for this input \
                         (possible decompression bomb)"
                    .to_string(),
            },
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

    // Extract the helper (carrying signature verification results) before rename.
    let helper = decryptor.into_helper();

    // Rename temp → final output (atomic on same filesystem)
    fs::rename(&temp_path, output_path).map_err(|e| {
        secure_delete_file(temp_path_ref);
        PgpError::FileIoError {
            reason: format!("Cannot rename temp to output: {e}"),
        }
    })?;

    Ok(helper)
}

/// Create a detached signature for a file using streaming I/O.
/// Returns the ASCII-armored signature (small, in memory).
pub fn sign_detached_file(
    input_path: &str,
    signer_cert: &[u8],
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let signing_keypair = sign::extract_signing_keypair(signer_cert, &policy)?;

    sign_detached_file_with_signer(input_path, signing_keypair, progress)
}

/// Create a detached file signature using a public certificate plus external P-256 signer.
pub fn sign_detached_file_with_external_p256_signer(
    input_path: &str,
    public_cert_data: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let signing_public_key =
        sign::select_external_signing_key(public_cert_data, signing_key_fingerprint, &policy)?;
    let external_signer = signer_for_provider(signing_public_key, signer).map_err(|error| {
        PgpError::SigningFailed {
            reason: format!("External signer setup failed: {error}"),
        }
    })?;

    sign_detached_file_with_signer(input_path, external_signer, progress)
}

/// Create a detached file signature using a public certificate plus external
/// split-custody composite signer.
pub fn sign_detached_file_with_external_composite_signer(
    input_path: &str,
    public_cert_data: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa65SigningProvider>,
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let signing_public_key =
        sign::select_external_signing_key(public_cert_data, signing_key_fingerprint, &policy)?;
    let external_signer =
        composite_signer_for_provider(signing_public_key, classical_eddsa_secret, signer).map_err(
            |error| PgpError::SigningFailed {
                reason: format!("External signer setup failed: {error}"),
            },
        )?;

    sign_detached_file_with_signer(input_path, external_signer, progress)
}

/// Device-Bound Post-Quantum · High analog of
/// `sign_detached_file_with_external_composite_signer`.
pub fn sign_detached_file_with_external_composite_high_signer(
    input_path: &str,
    public_cert_data: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa87SigningProvider>,
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let signing_public_key =
        sign::select_external_signing_key(public_cert_data, signing_key_fingerprint, &policy)?;
    let external_signer =
        composite_high_signer_for_provider(signing_public_key, classical_eddsa_secret, signer)
            .map_err(|error| PgpError::SigningFailed {
                reason: format!("External signer setup failed: {error}"),
            })?;

    sign_detached_file_with_signer(input_path, external_signer, progress)
}

fn sign_detached_file_with_signer<S>(
    input_path: &str,
    signing_keypair: S,
    progress: Option<Arc<dyn StreamingProgressReporter>>,
) -> Result<Vec<u8>, PgpError>
where
    S: CryptoSigner + Send + Sync,
{
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
        .map_err(|error| map_detached_signing_error("Signer setup failed", error))?;

    // Stream file data through the signer
    if let Err(e) = zeroing_copy(&mut progress_reader, &mut signer, STREAM_BUFFER_SIZE) {
        return Err(match e {
            CopyError::Read(io_err) => classify_detached_signing_io_error("Read failed", io_err),
            CopyError::Write(io_err) => PgpError::SigningFailed {
                reason: format!("Write failed: {io_err}"),
            },
            CopyError::Cancelled => PgpError::OperationCancelled,
            // Not producible by zeroing_copy on the signing path; mapped
            // defensively rather than panicking.
            CopyError::OutputCeilingExceeded => PgpError::SigningFailed {
                reason: "Output exceeded the streaming ceiling".to_string(),
            },
        });
    }

    signer
        .finalize()
        .map_err(|error| map_detached_signing_error("Finalize failed", error))?;

    Ok(sink)
}

fn classify_detached_signing_io_error(context: &str, error: std::io::Error) -> PgpError {
    if error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<StreamingCancelled>())
        .is_some()
    {
        return PgpError::OperationCancelled;
    }

    map_external_signing_error(openpgp::anyhow::Error::from(error), |reason| {
        PgpError::SigningFailed {
            reason: format!("{context}: {reason}"),
        }
    })
}

fn map_detached_signing_error(context: &str, error: openpgp::anyhow::Error) -> PgpError {
    map_external_signing_error(error, |reason| PgpError::SigningFailed {
        reason: format!("{context}: {reason}"),
    })
}

/// Verify a detached signature against a file using streaming I/O and preserve details.
pub fn verify_detached_file_detailed(
    data_path: &str,
    signature: &[u8],
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn StreamingProgressReporter>>,
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
    // an empty detailed array and an Expired/Invalid summary.
    let mut verifier = match verifier_result {
        Ok(v) => v,
        Err(e) => {
            let summary_state = if is_expired_error(&e) {
                SignatureVerificationState::Expired
            } else {
                SignatureVerificationState::Invalid
            };
            return Ok(FileVerifyDetailedResult {
                summary_state,
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
            summary_state: helper.collector.summary_state(),
            summary_entry_index: helper.collector.summary_entry_index(),
            signatures: helper.collector.signatures(),
        });
    }

    let helper = verifier.into_helper();
    let (summary_state, summary_entry_index, signatures) = helper.collector.into_parts();

    Ok(FileVerifyDetailedResult {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Reporter that continues for `cancel_after` calls, then cancels. Records
    /// the last reported (bytes_processed, total_bytes) for assertions.
    struct TestReporter {
        calls: AtomicU64,
        cancel_after: u64,
        last_processed: AtomicU64,
        last_total: AtomicU64,
    }

    impl TestReporter {
        fn new(cancel_after: u64) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU64::new(0),
                cancel_after,
                last_processed: AtomicU64::new(0),
                last_total: AtomicU64::new(0),
            })
        }
    }

    impl StreamingProgressReporter for TestReporter {
        fn on_progress(&self, bytes_processed: u64, total_bytes: u64) -> bool {
            self.last_processed.store(bytes_processed, Ordering::SeqCst);
            self.last_total.store(total_bytes, Ordering::SeqCst);
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            n <= self.cancel_after
        }
    }

    #[test]
    fn output_ceiling_uses_floor_for_small_inputs() {
        assert_eq!(
            streaming_decrypt_output_ceiling(0),
            MIN_STREAMING_DECRYPT_OUTPUT_CEILING
        );
        assert_eq!(
            streaming_decrypt_output_ceiling(1024),
            MIN_STREAMING_DECRYPT_OUTPUT_CEILING
        );
    }

    #[test]
    fn output_ceiling_scales_with_large_inputs() {
        let input = 1024 * 1024 * 1024; // 1 GiB input
        assert_eq!(
            streaming_decrypt_output_ceiling(input),
            input * MAX_STREAMING_DECOMPRESSION_RATIO
        );
    }

    #[test]
    fn output_ceiling_saturates_instead_of_overflowing() {
        // A near-u64::MAX reported input size must not overflow the ratio mul.
        assert_eq!(streaming_decrypt_output_ceiling(u64::MAX), u64::MAX);
    }

    #[test]
    fn decrypt_copy_halts_at_output_ceiling() {
        // Simulates a decompression bomb: an effectively infinite reader with a
        // small ceiling. The copy must fail closed and never write past the cap.
        let mut reader = std::io::repeat(0u8);
        let mut sink: Vec<u8> = Vec::new();
        let ceiling = 4 * STREAM_BUFFER_SIZE as u64;
        let result = zeroing_copy_decrypt(
            &mut reader,
            &mut sink,
            STREAM_BUFFER_SIZE,
            ceiling,
            0,
            None,
        );
        assert!(matches!(result, Err(CopyError::OutputCeilingExceeded)));
        assert!(sink.len() as u64 <= ceiling);
    }

    #[test]
    fn decrypt_copy_cancels_on_output_side_without_input_progress() {
        // The whole input is already available (no input-side stalling), yet the
        // output-side poll must still observe the reporter's cancellation.
        let data = vec![0u8; STREAM_BUFFER_SIZE * 4];
        let mut reader = &data[..];
        let mut sink: Vec<u8> = Vec::new();
        let reporter = TestReporter::new(1); // continue once, then cancel
        let result = zeroing_copy_decrypt(
            &mut reader,
            &mut sink,
            STREAM_BUFFER_SIZE,
            u64::MAX,
            data.len() as u64,
            Some(&(reporter.clone() as Arc<dyn StreamingProgressReporter>)),
        );
        assert!(matches!(result, Err(CopyError::Cancelled)));
    }

    #[test]
    fn decrypt_copy_reports_clamped_progress_and_succeeds_under_ceiling() {
        // Output is larger than the reported input size (a compressed input that
        // expands), so the clamp branch is exercised: reported progress must
        // never exceed total_bytes even though more output bytes are written.
        let data = vec![7u8; STREAM_BUFFER_SIZE * 3];
        let mut reader = &data[..];
        let mut sink: Vec<u8> = Vec::new();
        let reporter = TestReporter::new(u64::MAX); // never cancels
        let output_len = data.len() as u64;
        let reported_total = STREAM_BUFFER_SIZE as u64; // input smaller than output
        let copied = zeroing_copy_decrypt(
            &mut reader,
            &mut sink,
            STREAM_BUFFER_SIZE,
            u64::MAX,
            reported_total,
            Some(&(reporter.clone() as Arc<dyn StreamingProgressReporter>)),
        )
        .expect("copy under ceiling succeeds");
        assert_eq!(copied, output_len);
        assert_eq!(sink, data);
        // Progress is clamped to total_bytes, never above 100%, even though
        // output_len > reported_total.
        assert_eq!(reporter.last_processed.load(Ordering::SeqCst), reported_total);
        assert_eq!(reporter.last_total.load(Ordering::SeqCst), reported_total);
    }
}
