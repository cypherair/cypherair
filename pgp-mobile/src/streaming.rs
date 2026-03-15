//! Streaming file operations for Cypher Air.
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

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::sync::Arc;

use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use crate::decrypt::{classify_decrypt_error, is_expired_error, DecryptHelper, SignatureStatus};
use crate::encrypt;
use crate::error::PgpError;
use crate::sign;
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
                    std::io::ErrorKind::Interrupted,
                    "Operation cancelled by user",
                ));
            }
        }

        Ok(n)
    }
}

// ── Zeroing Copy Utilities ─────────────────────────────────────────────

/// Copy data from `reader` to `writer` using a zeroizing buffer.
///
/// Unlike `std::io::copy`, the internal buffer is guaranteed to be zeroized on drop
/// (including panic/early-return paths) via `Zeroizing<Vec<u8>>`.
fn zeroing_copy<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
) -> Result<u64, PgpError> {
    let mut buf = Zeroizing::new(vec![0u8; buf_size]);
    let mut total: u64 = 0;

    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                PgpError::OperationCancelled
            } else {
                PgpError::FileIoError {
                    reason: format!("Read failed: {e}"),
                }
            }
        })?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).map_err(|e| PgpError::FileIoError {
            reason: format!("Write failed: {e}"),
        })?;
        total += n as u64;
    }

    Ok(total)
}

/// Copy data from `reader` to `writer` with progress reporting and cancellation.
///
/// The `ProgressReader` wrapper handles progress callbacks on the read side.
/// This function uses a `Zeroizing<Vec<u8>>` buffer for the copy loop.
fn zeroing_copy_with_progress<W: Write>(
    reader: &mut ProgressReader<impl Read>,
    writer: &mut W,
    buf_size: usize,
) -> Result<u64, PgpError> {
    let mut buf = Zeroizing::new(vec![0u8; buf_size]);
    let mut total: u64 = 0;

    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                PgpError::OperationCancelled
            } else {
                PgpError::FileIoError {
                    reason: format!("Read failed: {e}"),
                }
            }
        })?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).map_err(|e| PgpError::FileIoError {
            reason: format!("Write failed: {e}"),
        })?;
        total += n as u64;
    }

    Ok(total)
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

    let mut literal = LiteralWriter::new(message)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Literal writer setup failed: {e}"),
        })?;

    // Stream data through the pipeline with progress reporting
    let result = zeroing_copy_with_progress(&mut progress_reader, &mut literal, STREAM_BUFFER_SIZE);

    if let Err(e) = result {
        // Clean up partial output on error
        drop(literal);
        secure_delete_file(std::path::Path::new(output_path));
        return Err(e);
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
pub fn decrypt_file(
    input_path: &str,
    output_path: &str,
    secret_keys: &[Vec<u8>],
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<FileDecryptResult, PgpError> {
    let policy = StandardPolicy::new();

    // Parse secret key certificates
    let mut certs = Vec::new();
    for key_data in secret_keys {
        let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| PgpError::InvalidKeyData {
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
        signature_status: None,
        signer_fingerprint: None,
    };

    // Build decryptor from file reader
    let mut decryptor = DecryptorBuilder::from_reader(progress_reader)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse message: {e}"),
        })?
        .with_policy(&policy, None, helper)
        .map_err(|e| classify_decrypt_error(e))?;

    // Write to temp file first (AEAD hard-fail: no partial plaintext)
    let temp_path = format!("{output_path}.tmp");
    let temp_path_ref = std::path::Path::new(&temp_path);

    let mut temp_file = File::create(&temp_path).map_err(|e| PgpError::FileIoError {
        reason: format!("Cannot create temp file '{}': {e}", temp_path),
    })?;

    // Stream decrypted data to temp file using zeroing copy
    if let Err(e) = zeroing_copy(&mut decryptor, &mut temp_file, STREAM_BUFFER_SIZE) {
        drop(temp_file);
        secure_delete_file(temp_path_ref);
        return Err(match e {
            PgpError::FileIoError { ref reason } => {
                // Check if this is actually a decryption error wrapped in an I/O error.
                // Sequoia's Decryptor implements Read; read() wraps decryption errors in io::Error.
                if reason.contains("Read failed:") {
                    // Re-classify: the "read" failure was likely a decryption error
                    PgpError::CorruptData {
                        reason: reason.clone(),
                    }
                } else {
                    e
                }
            }
            _ => e,
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

    Ok(FileDecryptResult {
        signature_status: helper.signature_status,
        signer_fingerprint: helper.signer_fingerprint,
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
    zeroing_copy_with_progress(&mut progress_reader, &mut signer, STREAM_BUFFER_SIZE)?;

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

    // Parse verification key certificates
    let mut certs = Vec::new();
    for key_data in verification_keys {
        let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Invalid verification key: {e}"),
        })?;
        certs.push(cert);
    }

    let helper = VerifyHelper {
        certs: &certs,
        status: SignatureStatus::NotSigned,
        signer_fingerprint: None,
    };

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
    let mut progress_reader = ProgressReader::new(data_file, total_bytes, progress);

    // Verify by streaming the data through the verifier
    if verifier.verify_reader(&mut progress_reader).is_err() {
        let helper = verifier.into_helper();
        return Ok(VerifyResult {
            status: SignatureStatus::Bad,
            signer_fingerprint: helper.signer_fingerprint,
            content: None,
        });
    }

    let helper = verifier.into_helper();

    Ok(VerifyResult {
        status: helper.status,
        signer_fingerprint: helper.signer_fingerprint,
        content: None,
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
