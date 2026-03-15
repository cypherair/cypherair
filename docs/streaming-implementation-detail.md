# Streaming File Processing — Detailed Implementation Plan

> Based on the v2 high-level plan, refined against actual codebase analysis.
> Line references are current as of this analysis.

---

## PR 1: Rust Layer — Streaming File APIs

### 1.1 `pgp-mobile/src/error.rs` — Add 2 variants

**Current state:** 17 variants (lines 6–88), no blanket `From<anyhow::Error>` (lines 90–94).

**Changes:**

Insert after `InternalError` (line 87), before the closing `}`:

```rust
/// Operation was cancelled by the user (via progress callback returning false).
#[error("Operation cancelled")]
OperationCancelled,

/// File I/O error (path not found, permission denied, disk full, etc.).
#[error("File I/O error: {reason}")]
FileIoError { reason: String },
```

**Verification:** `init(pgpError:)` in `CypherAirError.swift` will need the corresponding cases in PR 2. The Rust side is self-contained.

### 1.2 `pgp-mobile/src/encrypt.rs` — Change 3 functions to `pub(crate)`

**Current state:** All 4 helper functions are private (`fn`, no `pub`):
- `collect_recipients` (line 11)
- `build_recipients` (line 88)
- `setup_signer` (line 108)
- `write_and_finalize` (line 151)

**Changes:**

| Function | Line | Current | New | Reason |
|----------|------|---------|-----|--------|
| `collect_recipients` | 11 | `fn` | `pub(crate) fn` | `streaming.rs` needs to gather recipients from cert data |
| `build_recipients` | 88 | `fn` | `pub(crate) fn` | `streaming.rs` needs to build `Recipient` objects |
| `setup_signer` | 108 | `fn` | `pub(crate) fn` | `streaming.rs` needs to set up optional signer in the encryption pipeline |
| `write_and_finalize` | 151 | `fn` (unchanged) | `fn` (unchanged) | Streaming uses `zeroing_copy_with_progress` instead |

The two public functions `encrypt` (line 191) and `encrypt_binary` (line 230) remain unchanged.

### 1.3 `pgp-mobile/src/decrypt.rs` — Change 2 items to `pub(crate)`

**Current state:**
- `DecryptHelper` struct (line 259) — private
- `classify_decrypt_error` fn (line 356) — private
- `is_expired_error` fn (line 446) — already `pub(crate)`
- `map_openpgp_error` fn (line 411) — private (only called by `classify_decrypt_error`)

**Changes:**

| Item | Line | Current | New | Reason |
|------|------|---------|-----|--------|
| `DecryptHelper` struct | 259 | `struct` | `pub(crate) struct` | `streaming.rs` needs to construct `DecryptHelper` for streaming `DecryptorBuilder::from_reader()` |
| `classify_decrypt_error` fn | 356 | `fn` | `pub(crate) fn` | `streaming.rs` needs to classify errors from streaming decryption |
| `VerificationHelper` impl for `DecryptHelper` | 267 | implicit pub | unchanged | Trait impls are automatically visible within the crate |
| `DecryptionHelper` impl for `DecryptHelper` | 462 | implicit pub | unchanged | Same |

**Note on `DecryptHelper` fields:** The struct has fields `policy`, `secret_certs`, `verifier_certs`, `signature_status`, `signer_fingerprint` (lines 260–264). All need to be `pub(crate)` for `streaming.rs` to construct the struct. Currently they're all implicitly private (no `pub` prefix on fields). Change:

```rust
pub(crate) struct DecryptHelper<'a> {
    pub(crate) policy: &'a StandardPolicy<'a>,
    pub(crate) secret_certs: &'a [openpgp::Cert],
    pub(crate) verifier_certs: &'a [openpgp::Cert],
    pub(crate) signature_status: Option<SignatureStatus>,
    pub(crate) signer_fingerprint: Option<String>,
}
```

### 1.4 `pgp-mobile/src/sign.rs` — Extract signing keypair helper

**Current state:** The cert-parse → key-selection → `into_keypair()` pattern is duplicated:
- `sign_cleartext` lines 17–38
- `sign_detached` lines 76–97

**Changes:**

Add new `pub(crate)` function:

```rust
/// Extract a signing keypair from a certificate.
/// Used by sign_cleartext, sign_detached, and streaming::sign_detached_file.
pub(crate) fn extract_signing_keypair(
    cert_data: &[u8],
    policy: &StandardPolicy,
) -> Result<openpgp::crypto::KeyPair, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid signing key: {e}"),
        }
    })?;

    cert.keys()
        .with_policy(policy, None)
        .supported()
        .secret()
        .for_signing()
        .next()
        .ok_or(PgpError::SigningFailed {
            reason: "No signing-capable secret key found".to_string(),
        })?
        .key()
        .clone()
        .into_keypair()
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Failed to create signing keypair: {e}"),
        })
}
```

Then refactor `sign_cleartext` (lines 17–38) and `sign_detached` (lines 76–97) to call `extract_signing_keypair` instead of repeating the pattern. The function bodies change from:

```rust
// Before (sign_cleartext lines 17-38):
let cert = openpgp::Cert::from_bytes(signer_cert_data).map_err(|e| { ... })?;
let signing_keypair = cert.keys() ... .into_keypair() ... ?;

// After:
let signing_keypair = extract_signing_keypair(signer_cert_data, &policy)?;
```

Same for `sign_detached` (lines 76–97).

### 1.5 `pgp-mobile/src/verify.rs` — Change `VerifyHelper` to `pub(crate)`

**Current state:** `VerifyHelper` struct (line 152) is private.

**Changes:**

| Item | Line | Current | New | Reason |
|------|------|---------|-----|--------|
| `VerifyHelper` struct | 152 | `struct` | `pub(crate) struct` | `streaming.rs` needs for `verify_detached_file` |

Fields also need `pub(crate)`:

```rust
pub(crate) struct VerifyHelper<'a> {
    pub(crate) certs: &'a [openpgp::Cert],
    pub(crate) status: SignatureStatus,
    pub(crate) signer_fingerprint: Option<String>,
}
```

### 1.6 New file: `pgp-mobile/src/streaming.rs`

**Constants:**

```rust
const STREAM_BUFFER_SIZE: usize = 64 * 1024; // 64 KB
```

**Foreign trait (UniFFI callback from Swift):**

```rust
#[uniffi::export(with_foreign)]
pub trait ProgressReporter: Send + Sync {
    /// Report progress. Returns false to cancel.
    fn on_progress(&self, bytes_processed: u64, total_bytes: u64) -> bool;
}
```

**Zeroing copy utilities:**

Two functions as specified in the plan: `zeroing_copy` and `zeroing_copy_with_progress`. Implementation uses `Zeroizing<Vec<u8>>` from the `zeroize` crate (already in Cargo.toml).

**`secure_delete_file` helper:**

```rust
/// Overwrite file contents with zeros before deleting.
/// NOTE: APFS is copy-on-write, so zero-overwrite does not guarantee
/// physical sector erasure. This matches the in-memory zeroize guarantee
/// level. See SECURITY.md for accepted tradeoff discussion.
fn secure_delete_file(path: &std::path::Path) -> std::io::Result<()> {
    if let Ok(metadata) = std::fs::metadata(path) {
        let size = metadata.len();
        if size > 0 {
            let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
            let buf = [0u8; 8192]; // Stack-allocated — writing zeros, no sensitive data
            let mut remaining = size;
            while remaining > 0 {
                let to_write = std::cmp::min(remaining, buf.len() as u64) as usize;
                std::io::Write::write_all(&mut file, &buf[..to_write])?;
                remaining -= to_write as u64;
            }
            file.sync_all()?;
        }
    }
    std::fs::remove_file(path)
}
```

**5 streaming functions:**

#### `encrypt_file`

```rust
pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    recipient_certs: &[Vec<u8>],
    signing_key: Option<&[u8]>,
    encrypt_to_self: Option<&[u8]>,
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<(), PgpError>
```

Implementation steps:
1. Open input file, get metadata for total_bytes
2. Call `encrypt::collect_recipients` to validate and deduplicate recipients
3. Call `encrypt::build_recipients` to get `Recipient` objects
4. Open output file
5. Create Sequoia `Message::new(&mut output_file)` pipeline:
   - `Encryptor::for_recipients(message, recipient_keys).build()`
   - `encrypt::setup_signer(message, signing_key, &policy)`
   - `LiteralWriter::new(message).build()`
6. Use `zeroing_copy_with_progress` to copy from `ProgressReader<File>` to `literal_writer`
7. Finalize the pipeline

**Key insight from code analysis:** The existing `encrypt.rs` `write_and_finalize` (line 151) does `io::copy(&mut &plaintext[..], &mut literal)`. For streaming, we instead do `zeroing_copy_with_progress(&mut progress_reader, &mut literal_writer, ...)`. The `LiteralWriter` is the `Write` sink.

#### `decrypt_file`

```rust
pub fn decrypt_file(
    input_path: &str,
    output_path: &str,
    secret_keys: &[Vec<u8>],
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<FileDecryptResult, PgpError>
```

Implementation steps:
1. Open input file, get metadata for total_bytes
2. Parse secret key certs and verification key certs (same pattern as `decrypt.rs` lines 204–224)
3. Construct `DecryptHelper` (now `pub(crate)`)
4. Create temp output path: `output_path.tmp`
5. Create `DecryptorBuilder::from_reader(ProgressReader<File>)`
   - `.with_policy(&policy, None, helper)`
   - `.map_err(|e| classify_decrypt_error(e))`
6. Open temp output file
7. `zeroing_copy(&mut decryptor, &mut temp_file, STREAM_BUFFER_SIZE)` — note: using `zeroing_copy` without progress here because `ProgressReader` is already on the input side
8. On ANY error: call `secure_delete_file` on temp, return error
9. After successful complete read: `decryptor.into_helper()` to get signature status
10. Rename temp → final output path
11. Return `FileDecryptResult` with signature info

**AEAD safety:** The `DecryptorBuilder::from_reader` path uses Sequoia's streaming decryption, which processes AEAD chunks incrementally. If an AEAD chunk fails verification, `read()` returns an error. Our `zeroing_copy` catches this error, triggers `secure_delete_file` on the temp file, and returns the error. The temp file never gets renamed to the final path.

**ProgressReader placement:** The `ProgressReader` wraps the input `File`, so progress is reported as bytes are read from the ciphertext file. For decryption, ciphertext bytes ≈ plaintext bytes (with slight overhead), so progress is accurate enough.

#### `sign_detached_file`

```rust
pub fn sign_detached_file(
    input_path: &str,
    signer_cert: &[u8],
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<Vec<u8>, PgpError>
```

Implementation steps:
1. Open input file, get metadata for total_bytes
2. Call `sign::extract_signing_keypair(signer_cert, &policy)` (new helper)
3. Create `Signer::new(message, signing_keypair).detached().build()`
4. `zeroing_copy_with_progress` from `File` to signer (with progress reporting)
5. Finalize signer
6. Return signature bytes (small, in memory)

**Note from code analysis:** The existing `sign_detached` (sign.rs line 73) writes to a `Vec<u8>` sink with `Armorer`. For streaming, we do the same thing but read input from a file via `zeroing_copy_with_progress` instead of `io::copy(&mut &data[..], &mut signer)`.

#### `verify_detached_file`

```rust
pub fn verify_detached_file(
    data_path: &str,
    signature: &[u8],
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn ProgressReporter>>,
) -> Result<VerifyResult, PgpError>
```

Implementation steps:
1. Open data file, get metadata for total_bytes
2. Parse verification key certs (same pattern as `verify.rs` lines 93–101)
3. Construct `VerifyHelper` (now `pub(crate)`)
4. Build `DetachedVerifierBuilder::from_bytes(signature)` with policy and helper
5. Use `verify_reader(ProgressReader<File>)` (Sequoia's `DetachedVerifier::verify_reader`)
6. Return `VerifyResult`

**Note from code analysis:** The existing `verify_detached` (verify.rs line 86) uses `verifier.verify_bytes(data)`. The streaming version uses `verifier.verify_reader(reader)` instead. Sequoia's `DetachedVerifier` supports both APIs.

#### `match_recipients_from_file`

```rust
pub fn match_recipients_from_file(
    input_path: &str,
    local_certs: &[Vec<u8>],
) -> Result<Vec<String>, PgpError>
```

Implementation steps:
1. Open input file
2. Wrap with `armor::Reader::from_reader(file, ReaderMode::Tolerant(None))` — this handles both binary and armored input transparently
3. Use `PacketParser::from_reader(armor_reader)` to parse PKESK packets (same logic as `match_recipients` lines 114–137 but reading from file)
4. Match against local certs (same logic as lines 146–177)
5. Return matched fingerprints

**Key difference from plan:** The plan mentions "Internally handles ASCII armor via `armor::Reader` wrapping." This is correct — we wrap the file reader in `armor::Reader` which transparently handles both binary and armored input. This matches the Swift-side pattern where `DecryptionService.parseRecipients` (line 51) checks for `0x2D` to dearmor, but here we let Sequoia's armor reader handle it automatically.

### 1.7 `pgp-mobile/src/lib.rs` — Add module + 5 exports

**Changes:**

1. Add `pub mod streaming;` after line 13 (after `pub mod verify;`)

2. Add import: `use crate::streaming::FileDecryptResult;`

3. Add to the existing `use` block (around line 18): `use crate::decrypt::SignatureStatus;` (already imported indirectly but need it for `FileDecryptResult`)

4. Add 5 new methods to `#[uniffi::export] impl PgpEngine` block:

```rust
// ── Streaming File Operations ──────────────────────────────────────

/// Encrypt a file using streaming I/O. Constant memory usage.
pub fn encrypt_file(
    &self,
    input_path: String,
    output_path: String,
    recipients: Vec<Vec<u8>>,
    signing_key: Option<Vec<u8>>,
    encrypt_to_self: Option<Vec<u8>>,
    progress: Option<Arc<dyn streaming::ProgressReporter>>,
) -> Result<(), PgpError> {
    streaming::encrypt_file(
        &input_path, &output_path,
        &recipients, signing_key.as_deref(), encrypt_to_self.as_deref(),
        progress,
    )
}

/// Decrypt a file using streaming I/O. Phase 2 — requires authenticated key access.
pub fn decrypt_file(
    &self,
    input_path: String,
    output_path: String,
    secret_keys: Vec<Vec<u8>>,
    verification_keys: Vec<Vec<u8>>,
    progress: Option<Arc<dyn streaming::ProgressReporter>>,
) -> Result<FileDecryptResult, PgpError> {
    streaming::decrypt_file(
        &input_path, &output_path,
        &secret_keys, &verification_keys,
        progress,
    )
}

/// Create a detached signature for a file using streaming I/O.
pub fn sign_detached_file(
    &self,
    input_path: String,
    signer_cert: Vec<u8>,
    progress: Option<Arc<dyn streaming::ProgressReporter>>,
) -> Result<Vec<u8>, PgpError> {
    streaming::sign_detached_file(
        &input_path, &signer_cert, progress,
    )
}

/// Verify a detached signature against a file using streaming I/O.
pub fn verify_detached_file(
    &self,
    data_path: String,
    signature: Vec<u8>,
    verification_keys: Vec<Vec<u8>>,
    progress: Option<Arc<dyn streaming::ProgressReporter>>,
) -> Result<VerifyResult, PgpError> {
    streaming::verify_detached_file(
        &data_path, &signature, &verification_keys, progress,
    )
}

/// Match PKESK recipients from a file against local certificates (Phase 1).
/// Reads only PKESK headers — does not load the full file.
pub fn match_recipients_from_file(
    &self,
    input_path: String,
    local_certs: Vec<Vec<u8>>,
) -> Result<Vec<String>, PgpError> {
    streaming::match_recipients_from_file(&input_path, &local_certs)
}
```

5. Export `ProgressReporter` trait — this happens automatically via `#[uniffi::export(with_foreign)]` on the trait definition in `streaming.rs`.

### 1.8 `FileDecryptResult` record

Defined in `streaming.rs`:

```rust
#[derive(uniffi::Record)]
pub struct FileDecryptResult {
    pub signature_status: Option<SignatureStatus>,
    pub signer_fingerprint: Option<String>,
}
```

Uses `SignatureStatus` from `decrypt.rs` (already `pub` and `uniffi::Enum`).

### 1.9 Rust tests: `pgp-mobile/tests/streaming_tests.rs`

12 test functions as specified in the plan. Key implementation notes:

- Use `tempfile` crate (already in dev-deps) for temp directories
- Generate fresh keys per test using `keys::generate_key_with_profile`
- Write test data to temp files, call streaming functions, verify results
- For tamper tests: flip a bit in the ciphertext file, verify error + no output file
- For progress tests: implement a simple `ProgressReporter` that records callbacks
- For cancellation tests: implement a `ProgressReporter` that returns `false` after N bytes

---

## PR 2: UniFFI Bindings + Swift Error/Model Updates

### 2.1 Regenerate bindings

Run the full build pipeline per CLAUDE.md. The regenerated `pgp_mobile.swift` will contain:
- `ProgressReporterProtocol` (Swift protocol from `#[uniffi::export(with_foreign)]`)
- New methods on `PgpEngine`: `encryptFile`, `decryptFile`, `signDetachedFile`, `verifyDetachedFile`, `matchRecipientsFromFile`
- `FileDecryptResult` struct
- New `PgpError` cases: `.OperationCancelled`, `.FileIoError(reason:)`

### 2.2 `Sources/Models/CypherAirError.swift`

**Current state:** 24 cases (lines 7–39), `init(pgpError:)` at lines 120–158.

**Changes:**

Add 3 new cases. Insert after `duplicateKey` (line 39):

```swift
case operationCancelled
case fileIoError(reason: String)
case insufficientDiskSpace(fileSizeMB: Int, requiredMB: Int, availableMB: Int)
```

Add to `errorDescription` computed property (after `duplicateKey` case, line 101):

```swift
case .operationCancelled:
    String(localized: "error.operationCancelled", defaultValue: "Operation cancelled.")
case .fileIoError(let reason):
    String(localized: "error.fileIo", defaultValue: "File operation failed: \(reason)")
case .insufficientDiskSpace(let fileSizeMB, let requiredMB, let availableMB):
    String(localized: "error.insufficientDiskSpace",
           defaultValue: "Insufficient storage to process this file. Processing a \(fileSizeMB) MB file requires approximately \(requiredMB) MB of temporary space, but only \(availableMB) MB is available. Please free up storage and try again.")
```

Add to `init(pgpError:)` (after `.InternalError` case, line 157):

```swift
case .OperationCancelled:
    self = .operationCancelled
case .FileIoError(let reason):
    self = .fileIoError(reason: reason)
```

**IMPORTANT:** Do NOT remove `fileTooLarge(sizeMB:)`. It is still referenced by `EncryptionService.encryptFile` line 81.

### 2.3 String Catalog updates

Add to `Localizable.xcstrings`:
- `error.operationCancelled` (en + zh-Hans)
- `error.fileIo` (en + zh-Hans)
- `error.insufficientDiskSpace` (en + zh-Hans)

---

## PR 3: Swift Service Layer Integration

### 3.1 New file: `Sources/Services/FileProgressReporter.swift`

```swift
import Foundation
import os

@Observable
final class FileProgressReporter: ProgressReporterProtocol, @unchecked Sendable {
    // @unchecked Sendable safety justification:
    // - cancelFlag is protected by OSAllocatedUnfairLock (thread-safe)
    // - @Observable properties (progress, bytesProcessed, totalBytes) are only
    //   mutated via Task { @MainActor in }, ensuring main-actor isolation
    // - onProgress() is nonisolated and only reads cancelFlag + enqueues main-actor updates

    private(set) var progress: Double = 0
    private(set) var bytesProcessed: UInt64 = 0
    private(set) var totalBytes: UInt64 = 0
    private let cancelLock = OSAllocatedUnfairLock(initialState: false)

    nonisolated func onProgress(bytesProcessed: UInt64, totalBytes: UInt64) -> Bool {
        Task { @MainActor in
            self.bytesProcessed = bytesProcessed
            self.totalBytes = totalBytes
            if totalBytes > 0 { self.progress = Double(bytesProcessed) / Double(totalBytes) }
        }
        return !cancelLock.withLock { $0 }
    }

    func cancel() { cancelLock.withLock { $0 = true } }
}
```

### 3.2 New file: `Sources/Services/DiskSpaceChecker.swift`

Follows the `Argon2idMemoryGuard` + `MemoryInfoProvidable` pattern exactly:

```swift
import Foundation

/// Protocol abstracting disk space queries for testability.
/// Follows the same pattern as MemoryInfoProvidable / Argon2idMemoryGuard.
protocol DiskSpaceProvidable: Sendable {
    func availableBytes() throws -> Int64
}

/// Production implementation: queries volumeAvailableCapacityForImportantUsageKey.
struct SystemDiskSpace: DiskSpaceProvidable {
    func availableBytes() throws -> Int64 {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
        let values = try url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return values.volumeAvailableCapacityForImportantUsage ?? 0
    }
}

/// Checks if sufficient disk space is available for a file streaming operation.
struct DiskSpaceChecker {
    private let diskSpace: any DiskSpaceProvidable

    init(diskSpace: any DiskSpaceProvidable = SystemDiskSpace()) {
        self.diskSpace = diskSpace
    }

    /// Requires fileSize * 2.2 available (input + output + temporary overhead).
    func check(fileSize: Int) throws {
        let available = try diskSpace.availableBytes()
        let required = Int64(Double(fileSize) * 2.2)
        guard available >= required else {
            throw CypherAirError.insufficientDiskSpace(
                fileSizeMB: fileSize / (1024 * 1024),
                requiredMB: Int(required / (1024 * 1024)),
                availableMB: Int(available / (1024 * 1024))
            )
        }
    }
}
```

### 3.3 New file: `Sources/Security/Mocks/MockDiskSpace.swift`

```swift
import Foundation

final class MockDiskSpace: DiskSpaceProvidable, @unchecked Sendable {
    var availableBytes_: Int64 = 10 * 1024 * 1024 * 1024  // 10 GB default
    private(set) var callCount = 0

    func availableBytes() throws -> Int64 {
        callCount += 1
        return availableBytes_
    }
}
```

### 3.4 `Sources/Services/EncryptionService.swift` changes

**Current state:** 183 lines. Dependencies: `engine`, `keyManagement`, `contactService`.

**Changes:**

1. Add `diskSpaceChecker` dependency (after line 15):

```swift
private let diskSpaceChecker: DiskSpaceChecker
```

2. Update `init` (lines 17–25) to accept `diskSpaceChecker`:

```swift
init(
    engine: PgpEngine = PgpEngine(),
    keyManagement: KeyManagementService,
    contactService: ContactService,
    diskSpaceChecker: DiskSpaceChecker = DiskSpaceChecker()
) {
    self.engine = engine
    self.keyManagement = keyManagement
    self.contactService = contactService
    self.diskSpaceChecker = diskSpaceChecker
}
```

3. Add new streaming method after `encryptFile` (after line 92):

```swift
// MARK: - File Streaming Encryption

/// Encrypt a file using streaming I/O. Constant memory usage.
/// Disk space is validated before starting. No fixed file size limit.
///
/// - Parameters:
///   - inputURL: The file to encrypt (security-scoped URL).
///   - outputURL: Where to write the encrypted output (.gpg).
///   - recipientFingerprints: Fingerprints of recipients.
///   - signWithFingerprint: Fingerprint of the signing key (nil = don't sign).
///   - encryptToSelf: Whether to also encrypt to the sender's own key.
///   - progress: Progress reporter for UI updates and cancellation.
@concurrent
func encryptFileStreaming(
    inputURL: URL, outputURL: URL,
    recipientFingerprints: [String], signWithFingerprint: String?,
    encryptToSelf: Bool, encryptToSelfFingerprint: String? = nil,
    progress: FileProgressReporter
) async throws {
    guard !recipientFingerprints.isEmpty else {
        throw CypherAirError.noRecipientsSelected
    }

    // Check disk space
    let fileSize = try FileManager.default.attributesOfItem(
        atPath: inputURL.path
    )[.size] as? Int ?? 0
    try diskSpaceChecker.check(fileSize: fileSize)

    // Gather recipient public keys (same as existing encrypt method, lines 110-119)
    let recipientKeys = recipientFingerprints.compactMap { fp in
        contactService.contact(forFingerprint: fp)?.publicKeyData
    }
    guard recipientKeys.count == recipientFingerprints.count else {
        throw CypherAirError.invalidKeyData(
            reason: String(localized: "error.recipientNotFound",
                           defaultValue: "One or more recipients could not be found in contacts.")
        )
    }

    // Get signing key if requested (requires SE unwrap → Face ID)
    var signingKey: Data?
    if let signerFp = signWithFingerprint {
        do {
            signingKey = try keyManagement.unwrapPrivateKey(fingerprint: signerFp)
        } catch {
            throw CypherAirError.from(error) { _ in .authenticationFailed }
        }
    }

    // Get encrypt-to-self key
    var selfKey: Data?
    if encryptToSelf {
        if let fp = encryptToSelfFingerprint,
           let key = keyManagement.keys.first(where: { $0.fingerprint == fp }) {
            selfKey = key.publicKeyData
        } else if let defaultKey = keyManagement.defaultKey {
            selfKey = defaultKey.publicKeyData
        } else {
            throw CypherAirError.noKeySelected
        }
    }

    defer {
        if signingKey != nil {
            signingKey!.resetBytes(in: 0..<signingKey!.count)
            signingKey = nil
        }
    }

    do {
        try engine.encryptFile(
            inputPath: inputURL.path,
            outputPath: outputURL.path,
            recipients: recipientKeys,
            signingKey: signingKey,
            encryptToSelf: selfKey,
            progress: progress
        )
    } catch {
        throw CypherAirError.from(error) { .encryptionFailed(reason: $0) }
    }

    // Primary zeroing
    if signingKey != nil {
        signingKey!.resetBytes(in: 0..<signingKey!.count)
        signingKey = nil
    }
}
```

**The old `encryptFile(_ fileData: Data)` method (lines 70–92) remains unchanged.**

### 3.5 `Sources/Services/DecryptionService.swift` changes

**Current state:** 160 lines. Two-phase: `parseRecipients` (Phase 1) + `decrypt` (Phase 2).

**Changes:**

1. Add new struct for file Phase 1 result (after line 22):

```swift
/// Result of file-based Phase 1 analysis.
struct FilePhase1Result {
    /// Matched primary fingerprints from PKESK header.
    let matchedFingerprints: [String]
    /// Matched local key identity.
    let matchedKey: PGPKeyIdentity?
    /// Input file path — stored for Phase 2 re-read.
    let inputPath: String
}
```

2. Add file-based Phase 1 method (after line 88):

```swift
// MARK: - File Phase 1: Parse Recipients from File (No Authentication)

/// Parse PKESK recipients from an encrypted file without loading it into memory.
/// This is Phase 1 — no authentication needed. Reads only the header.
/// Rust handles armor detection internally via armor::Reader.
@concurrent
func parseRecipientsFromFile(fileURL: URL) async throws -> FilePhase1Result {
    let localCerts = keyManagement.keys.map { $0.publicKeyData }
    let matchedFingerprints: [String]
    do {
        matchedFingerprints = try engine.matchRecipientsFromFile(
            inputPath: fileURL.path,
            localCerts: localCerts
        )
    } catch {
        throw CypherAirError.noMatchingKey
    }

    let matchedKey = keyManagement.keys.first { identity in
        matchedFingerprints.contains(identity.fingerprint)
    }

    guard matchedKey != nil else {
        throw CypherAirError.noMatchingKey
    }

    return FilePhase1Result(
        matchedFingerprints: matchedFingerprints,
        matchedKey: matchedKey,
        inputPath: fileURL.path
    )
}
```

3. Add file-based Phase 2 method (after the Phase 1 method):

```swift
// MARK: - File Phase 2: Decrypt File Streaming (Authentication Required)

/// Decrypt a file using streaming I/O. Phase 2 — requires SE unwrap + biometric.
///
/// SECURITY: This method must only be called after Phase 1 has identified the key.
@concurrent
func decryptFileStreaming(
    phase1: FilePhase1Result, outputURL: URL, progress: FileProgressReporter
) async throws -> SignatureVerification {
    guard let matchedKey = phase1.matchedKey else {
        throw CypherAirError.noMatchingKey
    }

    // SE unwrap triggers Face ID / Touch ID
    var secretKey: Data
    do {
        secretKey = try keyManagement.unwrapPrivateKey(fingerprint: matchedKey.fingerprint)
    } catch {
        throw CypherAirError.from(error) { _ in .authenticationFailed }
    }
    defer {
        secretKey.resetBytes(in: 0..<secretKey.count)
    }

    // Gather verification keys
    let verificationKeys = contactService.contacts.map { $0.publicKeyData }
        + keyManagement.keys.map { $0.publicKeyData }

    // Decrypt via Rust streaming engine
    let result: FileDecryptResult
    do {
        result = try engine.decryptFile(
            inputPath: phase1.inputPath,
            outputPath: outputURL.path,
            secretKeys: [secretKey],
            verificationKeys: verificationKeys,
            progress: progress
        )
    } catch {
        throw CypherAirError.from(error) { .corruptData(reason: $0) }
    }

    return SignatureVerification(
        status: result.signatureStatus ?? .notSigned,
        signerFingerprint: result.signerFingerprint,
        signerContact: result.signerFingerprint.flatMap {
            contactService.contact(forFingerprint: $0)
        }
    )
}
```

### 3.6 `Sources/Services/SigningService.swift` changes

**Current state:** 151 lines.

**Changes:** Add two streaming methods after `signDetached` (after line 79):

```swift
// MARK: - Streaming File Signing

/// Create a detached signature for a file using streaming I/O.
/// Triggers device authentication via SE unwrap.
@concurrent
func signDetachedStreaming(fileURL: URL, signerFingerprint: String, progress: FileProgressReporter) async throws -> Data {
    var secretKey: Data
    do {
        secretKey = try keyManagement.unwrapPrivateKey(fingerprint: signerFingerprint)
    } catch {
        throw CypherAirError.from(error) { _ in .authenticationFailed }
    }
    defer {
        secretKey.resetBytes(in: 0..<secretKey.count)
    }

    do {
        return try engine.signDetachedFile(
            inputPath: fileURL.path,
            signerCert: secretKey,
            progress: progress
        )
    } catch {
        throw CypherAirError.from(error) { .signingFailed(reason: $0) }
    }
}

/// Verify a detached signature against a file using streaming I/O.
@concurrent
func verifyDetachedStreaming(fileURL: URL, signature: Data, progress: FileProgressReporter) async throws -> SignatureVerification {
    let verificationKeys = allVerificationKeys()

    let result: VerifyResult
    do {
        result = try engine.verifyDetachedFile(
            dataPath: fileURL.path,
            signature: signature,
            verificationKeys: verificationKeys,
            progress: progress
        )
    } catch {
        throw CypherAirError.from(error) { .corruptData(reason: $0) }
    }

    return SignatureVerification(
        status: result.status,
        signerFingerprint: result.signerFingerprint,
        signerContact: result.signerFingerprint.flatMap {
            contactService.contact(forFingerprint: $0)
        }
    )
}
```

### 3.7 `CypherAirApp.swift` — Add `tmp/streaming/` to cleanup

**Current state:** `cleanupTempDecryptedFiles` (lines 233–243) cleans `tmp/decrypted/` and `tmp/share/`.

**Changes:** Add after the `shareDir` cleanup (line 242):

```swift
let streamingDir = fm.temporaryDirectory.appendingPathComponent("streaming", isDirectory: true)
if fm.fileExists(atPath: streamingDir.path) {
    try? fm.removeItem(at: streamingDir)
}
```

### 3.8 `CypherAirApp.swift` — Update `EncryptionService` init

**Current state:** Line 55 creates `EncryptionService` without `diskSpaceChecker`:

```swift
let encryption = EncryptionService(
    engine: engine,
    keyManagement: keyMgmt,
    contactService: contacts
)
```

**Changes:** No change needed — `diskSpaceChecker` has a default parameter value of `DiskSpaceChecker()`, so the existing call site compiles without modification.

### 3.9 `TestHelpers.swift` — Update `ServiceStack` for new dependency

**Current state:** `makeServiceStack` creates `EncryptionService` at line 95 without `diskSpaceChecker`.

**Changes:** No change needed — default parameter. Tests that need mock disk space will create their own `EncryptionService` with `DiskSpaceChecker(diskSpace: MockDiskSpace())`.

### 3.10 Swift tests: `Tests/ServiceTests/StreamingServiceTests.swift`

8 test functions:

1. `test_encryptDecryptFile_profileA_streaming_roundTrip` — Generate Profile A key + contact, encrypt file via streaming, decrypt via streaming, verify content matches
2. `test_encryptDecryptFile_profileB_streaming_roundTrip` — Same for Profile B
3. `test_diskSpaceCheck_insufficient_throwsInsufficientDiskSpace` — Inject `MockDiskSpace` with low value, verify error
4. `test_progressReporter_updatesCorrectly` — Encrypt a file, verify progress callback received
5. `test_cancellation_returnsOperationCancelled` — Cancel mid-stream, verify error
6. `test_aeadTamper_noOutputFile` — Encrypt Profile B, tamper, decrypt → verify no output file exists
7. `test_twoPhaseAuthBoundary_preserved` — Verify Phase 1 (`parseRecipientsFromFile`) does NOT call `unwrapPrivateKey` on mock SE; Phase 2 (`decryptFileStreaming`) DOES
8. `test_signVerifyDetachedFile_streaming_roundTrip` — Sign a file via streaming, verify via streaming

---

## PR 4: UI Layer — Progress Bar + Cancel

### 4.1 `EncryptView.swift` changes

**Current state:**
- `@State private var encryptedFileData: Data?` (line 44)
- `Data(contentsOf: fileURL)` (line 387)
- `data.writeToShareTempFile` (line 210)
- "Maximum file size: 100 MB" footer (line 292)
- `ProgressView(...)` indeterminate (line 140)

**Changes:**

1. Replace state variable (line 44):
   - Remove: `@State private var encryptedFileData: Data?`
   - Add: `@State private var encryptedFileURL: URL?`
   - Add: `@State private var fileProgress: FileProgressReporter?`

2. Update file result section (lines 208–219):
   ```swift
   // Before:
   if encryptMode == .file, let data = encryptedFileData,
      let fileURL = data.writeToShareTempFile(named: "...") {
       ShareLink(item: fileURL) { ... }
   }

   // After:
   if encryptMode == .file, let fileURL = encryptedFileURL {
       Section {
           ShareLink(item: fileURL) {
               Label(
                   String(localized: "fileEncrypt.share", defaultValue: "Share Encrypted File"),
                   systemImage: "square.and.arrow.up"
               )
           }
       }
   }
   ```

3. Update progress display in encrypt button (lines 138–151):
   ```swift
   // Replace indeterminate ProgressView with determinate when streaming:
   if isEncrypting {
       HStack {
           if encryptMode == .file, let p = fileProgress {
               ProgressView(value: p.progress)
               Text(String(localized: "fileEncrypt.encrypting", defaultValue: "Encrypting..."))
           } else {
               ProgressView(encryptMode == .file
                   ? String(localized: "fileEncrypt.encrypting", defaultValue: "Encrypting...")
                   : "")
           }
           if encryptMode == .file {
               Spacer()
               Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                   fileProgress?.cancel()
                   currentTask?.cancel()
                   currentTask = nil
                   isEncrypting = false
               }
           }
       }
   }
   ```

4. Update `encryptFile()` method (lines 353–405):
   ```swift
   private func encryptFile() {
       guard let fileURL = selectedFileURL else { return }
       let service = encryptionService
       let recipients = Array(selectedRecipients)
       let signerFp = signMessage ? signerFingerprint : nil
       let selfEncrypt = encryptToSelf ?? config.encryptToSelf
       let selfEncryptFp = selfEncrypt ? encryptToSelfFingerprint : nil
       let progress = FileProgressReporter()

       isEncrypting = true
       fileProgress = progress
       currentTask = Task {
           #if canImport(UIKit)
           var bgTaskID = UIBackgroundTaskIdentifier.invalid
           bgTaskID = UIApplication.shared.beginBackgroundTask { ... }
           #endif
           defer {
               #if canImport(UIKit)
               if bgTaskID != .invalid { UIApplication.shared.endBackgroundTask(bgTaskID) }
               #endif
               isEncrypting = false
               currentTask = nil
               fileProgress = nil
           }
           do {
               guard fileURL.startAccessingSecurityScopedResource() else {
                   error = .corruptData(reason: ...)
                   showError = true
                   return
               }
               defer { fileURL.stopAccessingSecurityScopedResource() }

               let filename = selectedFileName ?? "encrypted"
               let streamingDir = FileManager.default.temporaryDirectory
                   .appendingPathComponent("streaming", isDirectory: true)
               try? FileManager.default.createDirectory(at: streamingDir, withIntermediateDirectories: true)
               let outputURL = streamingDir
                   .appendingPathComponent("\(UUID().uuidString)_\(filename).gpg")

               try await service.encryptFileStreaming(
                   inputURL: fileURL, outputURL: outputURL,
                   recipientFingerprints: recipients,
                   signWithFingerprint: signerFp,
                   encryptToSelf: selfEncrypt,
                   encryptToSelfFingerprint: selfEncryptFp,
                   progress: progress
               )
               encryptedFileURL = outputURL
           } catch is CancellationError {
               // cancelled
           } catch let err as CypherAirError where err == .operationCancelled {
               // cancelled via progress reporter
           } catch {
               self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
               showError = true
           }
       }
   }
   ```

   **Note:** `CypherAirError` doesn't conform to `Equatable`, so the `where err == .operationCancelled` pattern won't work directly. Instead use a `case let` pattern or add an `isCancelled` property check. More precisely:
   ```swift
   } catch {
       if case .operationCancelled = error as? CypherAirError {
           // cancelled via progress reporter — no error to show
       } else {
           self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
           showError = true
       }
   }
   ```

5. Remove footer (line 292):
   ```swift
   // Before:
   } footer: {
       Text(String(localized: "fileEncrypt.sizeLimit", defaultValue: "Maximum file size: 100 MB"))
   }

   // After:
   }
   ```
   Remove the `footer:` block entirely.

### 4.2 `DecryptView.swift` changes

**Current state:**
- `@State private var decryptedFileData: Data?` (line 37)
- `Data(contentsOf: fileURL)` in `parseRecipientsFile` (line 319)
- `decryptedFileData?.resetBytes(in:)` in `onDisappear` (line 202)
- `data.writeToShareTempFile` (line 143)

**Changes:**

1. Replace state variables:
   - Remove: `@State private var decryptedFileData: Data?`
   - Add: `@State private var decryptedFileURL: URL?`
   - Add: `@State private var fileProgress: FileProgressReporter?`
   - Add: `@State private var filePhase1Result: DecryptionService.FilePhase1Result?`

2. Update `parseRecipientsFile()` (lines 306–328):
   ```swift
   private func parseRecipientsFile() {
       guard let fileURL = selectedFileURL else { return }
       let service = decryptionService
       isDecrypting = true
       Task {
           do {
               guard fileURL.startAccessingSecurityScopedResource() else {
                   error = .corruptData(reason: ...)
                   showError = true
                   isDecrypting = false
                   return
               }
               defer { fileURL.stopAccessingSecurityScopedResource() }
               // Phase 1: streaming header parse — no full file load
               let result = try await service.parseRecipientsFromFile(fileURL: fileURL)
               filePhase1Result = result
               // Also populate the existing phase1Result for UI display
               phase1Result = DecryptionService.Phase1Result(
                   recipientKeyIds: result.matchedFingerprints,
                   matchedKey: result.matchedKey,
                   ciphertext: Data() // placeholder — file path stored in filePhase1Result
               )
           } catch { ... }
           isDecrypting = false
       }
   }
   ```

   **Alternative approach:** Instead of creating a dummy `Phase1Result`, add a conditional in the UI that checks both `phase1Result` and `filePhase1Result`. This is cleaner:

   The Phase 1 result UI section (lines 80–129) currently checks `phase1Result.matchedKey`. For file mode, we use `filePhase1Result.matchedKey` instead. Adjust the condition:

   ```swift
   // Unified matched key — works for both text and file mode
   var matchedKeyForDisplay: PGPKeyIdentity? {
       if decryptMode == .file {
           return filePhase1Result?.matchedKey
       } else {
           return phase1Result?.matchedKey
       }
   }
   ```

   Then use `matchedKeyForDisplay` in the UI section.

3. Update `decryptFile()` (lines 355–390):
   ```swift
   private func decryptFile() {
       guard let fileURL = selectedFileURL,
             let phase1 = filePhase1Result else { return }
       let service = decryptionService
       let progress = FileProgressReporter()

       isDecrypting = true
       fileProgress = progress
       currentTask = Task {
           // background task setup...
           defer { ... isDecrypting = false; currentTask = nil; fileProgress = nil }
           do {
               guard fileURL.startAccessingSecurityScopedResource() else { ... }
               defer { fileURL.stopAccessingSecurityScopedResource() }

               let filename = decryptedFilename()
               let decryptedDir = FileManager.default.temporaryDirectory
                   .appendingPathComponent("decrypted", isDirectory: true)
               try? FileManager.default.createDirectory(at: decryptedDir, withIntermediateDirectories: true)
               let outputURL = decryptedDir
                   .appendingPathComponent("\(UUID().uuidString)_\(filename)")

               let sigVerification = try await service.decryptFileStreaming(
                   phase1: phase1, outputURL: outputURL, progress: progress
               )
               decryptedFileURL = outputURL
               signatureVerification = sigVerification
           } catch { ... }
       }
   }
   ```

4. Update `onDisappear` (lines 196–211):
   ```swift
   .onDisappear {
       decryptedText = ""
       decryptedText = nil
       // File mode: delete temp file instead of resetBytes
       if let url = decryptedFileURL {
           try? FileManager.default.removeItem(at: url)
           decryptedFileURL = nil
       }
       signatureVerification = nil
       phase1Result = nil
       filePhase1Result = nil
       if let url = tempShareFileURL {
           try? FileManager.default.removeItem(at: url)
           tempShareFileURL = nil
       }
   }
   ```

5. Update `onChange(of: config.contentClearGeneration)` (lines 212–224) similarly.

6. Update file result section (lines 142–153):
   ```swift
   // Before: uses decryptedFileData.writeToShareTempFile
   // After: uses decryptedFileURL directly
   if decryptMode == .file, let fileURL = decryptedFileURL {
       Section {
           ShareLink(item: fileURL) {
               Label(
                   String(localized: "fileDecrypt.save", defaultValue: "Save Decrypted File"),
                   systemImage: "square.and.arrow.down"
               )
           }
       }
   }
   ```

7. Update Phase 2 progress display (lines 106–119):
   ```swift
   if isDecrypting {
       HStack {
           if decryptMode == .file, let p = fileProgress {
               ProgressView(value: p.progress)
               Text(String(localized: "fileDecrypt.decrypting", defaultValue: "Decrypting..."))
           } else {
               ProgressView(decryptMode == .file
                   ? String(localized: "fileDecrypt.decrypting", defaultValue: "Decrypting...")
                   : "")
           }
           if decryptMode == .file {
               Spacer()
               Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                   fileProgress?.cancel()
                   currentTask?.cancel()
                   ...
               }
           }
       }
   }
   ```

### 4.3 `SignView.swift` changes

**Current state:**
- `Data(contentsOf: fileURL)` in `signFile` (line 262)
- `ProgressView()` indeterminate (line 79)

**Changes:**

1. Add state: `@State private var fileProgress: FileProgressReporter?`

2. Update `signFile()` (lines 251–271):
   ```swift
   private func signFile() {
       guard let fileURL = selectedFileURL,
             let signerFp = signerFingerprint ?? keyManagement.defaultKey?.fingerprint else { return }
       let progress = FileProgressReporter()
       isSigning = true
       fileProgress = progress
       let service = signingService
       Task {
           do {
               guard fileURL.startAccessingSecurityScopedResource() else {
                   throw CypherAirError.internalError(reason: ...)
               }
               defer { fileURL.stopAccessingSecurityScopedResource() }
               let sig = try await service.signDetachedStreaming(
                   fileURL: fileURL, signerFingerprint: signerFp, progress: progress
               )
               detachedSignature = sig
           } catch { ... }
           isSigning = false
           fileProgress = nil
       }
   }
   ```

3. Update progress display (line 79):
   ```swift
   if isSigning {
       if signMode == .file, let p = fileProgress {
           HStack {
               ProgressView(value: p.progress)
               Text(String(localized: "sign.signing", defaultValue: "Signing..."))
               Spacer()
               Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                   fileProgress?.cancel()
               }
           }
           .frame(maxWidth: .infinity)
       } else {
           ProgressView()
               .frame(maxWidth: .infinity)
       }
   }
   ```

### 4.4 `VerifyView.swift` changes

**Current state:**
- `Data(contentsOf: origURL)` and `Data(contentsOf: sigURL)` in `verifyDetached` (lines 228–229)
- `ProgressView()` indeterminate (line 60)

**Changes:**

1. Add state: `@State private var fileProgress: FileProgressReporter?`

2. Update `verifyDetached()` (lines 212–238):
   ```swift
   private func verifyDetached() {
       guard let origURL = originalFileURL, let sigURL = signatureFileURL else { return }
       let progress = FileProgressReporter()
       isVerifying = true
       fileProgress = progress
       let service = signingService
       Task {
           do {
               guard origURL.startAccessingSecurityScopedResource() else { throw ... }
               defer { origURL.stopAccessingSecurityScopedResource() }

               guard sigURL.startAccessingSecurityScopedResource() else { throw ... }
               defer { sigURL.stopAccessingSecurityScopedResource() }

               // Signature file is small — load into memory
               let sigData = try Data(contentsOf: sigURL)

               // Original file is streamed
               let result = try await service.verifyDetachedStreaming(
                   fileURL: origURL, signature: sigData, progress: progress
               )
               verification = result
           } catch { ... }
           isVerifying = false
           fileProgress = nil
       }
   }
   ```

3. Update progress display (line 60):
   ```swift
   if isVerifying {
       if verifyMode == .detached, let p = fileProgress {
           HStack {
               ProgressView(value: p.progress)
               Text(String(localized: "verify.verifying", defaultValue: "Verifying..."))
           }
           .frame(maxWidth: .infinity)
       } else {
           ProgressView()
               .frame(maxWidth: .infinity)
       }
   }
   ```

### 4.5 String Catalog updates

Add/update:
- `sign.signing` = "Signing..." / "正在签名..."
- `verify.verifying` = "Verifying..." / "正在验证..."
- Remove: `fileEncrypt.sizeLimit` (no longer used)

---

## Summary of Discrepancies Between Plan and Actual Code

| # | Plan Assumption | Actual Code | Impact |
|---|----------------|-------------|--------|
| 1 | `encrypt.rs` functions marked `fn` → change to `pub(crate) fn` | Confirmed: all 4 helpers are plain `fn` | No change to plan |
| 2 | `DecryptHelper` fields need `pub(crate)` | Confirmed: fields have no pub qualifier | Plan updated to include field visibility changes |
| 3 | `VerifyHelper` fields need `pub(crate)` | Confirmed: fields have no pub qualifier | Plan updated |
| 4 | Plan says `sign.rs` lines 17-38 and 76-97 have duplicated pattern | Confirmed: exact same cert parse + key selection + into_keypair in both functions | No change |
| 5 | Plan says `EncryptionService` init at lines 17-25 | Confirmed: lines 17-25 | No change |
| 6 | Plan says `fileTooLarge` at line 81 | Confirmed: line 81 | No change |
| 7 | Plan references `Data+TempFile.swift` `writeToShareTempFile` | Confirmed: exists at `Sources/Extensions/Data+TempFile.swift` | No change |
| 8 | `DecryptView` uses `tempShareFileURL` for cleanup | Confirmed: line 39 + cleanup in onDisappear lines 207-210 | No change |
| 9 | `CypherAirApp` cleanup at lines 233-243 | Confirmed: exactly 2 dirs cleaned | Plan adds third dir |
| 10 | `TestHelpers.makeServiceStack` creates `EncryptionService` without diskSpaceChecker | Confirmed: line 95 | Default param means no change needed |
| 11 | Plan specifies `ProgressReader` wrapper struct | Not in actual code yet (new) | Will be implemented in streaming.rs |
| 12 | `DecryptView.decryptFile` at line 355 takes `phase1: DecryptionService.Phase1Result` | Confirmed: line 355 | File mode will use `FilePhase1Result` instead |
| 13 | `DecryptView` Phase 2 button uses condition `if let phase1 = phase1Result` at line 80 | Confirmed: line 80 | Need unified `matchedKeyForDisplay` computed property for both text and file modes |

---

## Sequoia API Usage Notes

From analyzing the actual Rust code:

1. **Encryption streaming:** `Message::new(&mut output_file)` → `Encryptor::for_recipients()` → `setup_signer()` → `LiteralWriter::new()` → `zeroing_copy_with_progress()` from input to literal writer → finalize. The key insight is that `LiteralWriter` implements `Write`, so we write streaming data into it.

2. **Decryption streaming:** `DecryptorBuilder::from_reader(ProgressReader<File>)` → `.with_policy()` → Sequoia returns a `Read`-able `Decryptor` → `zeroing_copy()` from decryptor to temp file → `into_helper()` for signature verification → rename temp.

3. **Detached sign streaming:** `Signer::new(message, keypair).detached().build()` → `zeroing_copy_with_progress()` from file to signer → finalize. The signer computes a hash over the data without buffering it.

4. **Detached verify streaming:** `DetachedVerifierBuilder::from_bytes(signature)` → `.with_policy()` → `verify_reader(ProgressReader<File>)`. Sequoia's `DetachedVerifier` has a `verify_reader()` method that accepts a `Read` impl.

5. **Match recipients from file:** `armor::Reader::from_reader(file, Tolerant)` → `PacketParser::from_reader()` → walk PKESK packets. Same logic as `match_recipients()` but reading from file.
